"""Restart-time validation of the persisted key-ring snapshot.

Business coverage:
  * restart-multi-active-rejected .......... 快照里有多个 ACTIVE 版本 -> 拒绝启动
  * restart-current-not-active-rejected .... current 指向 DEACTIVATED/REVOKED -> 拒绝启动
  * restart-no-active-rejected ............. 快照里 0 个 ACTIVE -> 拒绝启动
  * restart-inmemory-multi-active-rejected . InMemoryStateStore 同样拒绝（规则与存储无关）
  * restart-valid-history-no-rollback ...... 合法历史快照正常重启，current 不回退
  * restart-valid-history-ciphertext-rules . 历史密文重启后按各自规则可解密/被拒绝

A failed startup must surface PERSISTED_STATE_INVALID (distinct from
CONFIG_INVALID), never silently load / auto-repair / fall back to the source.
"""

from __future__ import annotations

import json

import pytest

from app.audit import NullAuditLogger
from app.errors import (
    ConfigurationError,
    KeyRevokedError,
    PersistedStateInvalidError,
)
from app.key_source import InlineKeySource
from app.manager import KeyManager
from app.models import KeyState, b64e
from app.state_store import FileStateStore, InMemoryStateStore, RingSnapshot, VersionSnapshot
from app.key_source import generate_local_key

from .conftest import log_case

CTX = {"tenant": "acme"}


def _boot(key_id, versions, store):
    return KeyManager(key_id, InlineKeySource(versions),
                      NullAuditLogger(), store)


def _snapshot_entry(version: str, state: str) -> dict:
    return {
        "version": version,
        "key_material": b64e(generate_local_key()),
        "state": state,
        "created_at": "2026-10-05T00:00:00.000+00:00",
    }


def _write_state_file(path, *, key_id: str, current: str, entries: list[dict]):
    """Hand-author a (possibly inconsistent) persisted snapshot on disk.

    This simulates an operator restore/tidy that leaves contradictory state,
    which the service itself would never write.
    """
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "key_id": key_id,
                "current_version": current,
                "versions": entries,
            },
            handle,
        )


@pytest.fixture
def state_path(tmp_path):
    return str(tmp_path / "ekm-state.json")


# --------------------------------------------------------------------------- #
# Inconsistent persisted state: startup must be refused, clearly classified
# --------------------------------------------------------------------------- #
def test_restart_refused_when_multiple_active_versions(state_path):
    """The reported bug: two ACTIVE versions must not boot after restart."""
    entries = [
        _snapshot_entry("v1", "ACTIVE"),       # stale version left ACTIVE
        _snapshot_entry("v2", "DEACTIVATED"),
        _snapshot_entry("v3", "ACTIVE"),       # current
    ]
    _write_state_file(state_path, key_id="primary", current="v3", entries=entries)

    with pytest.raises(PersistedStateInvalidError) as exc:
        _boot("primary", [entries[0]], FileStateStore(state_path))

    # Distinguishable, specific reason: persisted-state inconsistency, naming
    # both offending versions — not a generic config error.
    assert exc.value.code.value == "PERSISTED_STATE_INVALID"
    message = str(exc.value)
    assert "2 versions are ACTIVE" in message
    assert "'v1'" in message and "'v3'" in message
    assert not isinstance(exc.value, ConfigurationError)
    log_case(
        "restart-multi-active-rejected",
        current="v3",
        states={e["version"]: e["state"] for e in entries},
        reason=exc.value.code.value,
    )


@pytest.mark.parametrize(
    "current,extra_states,reason_fragment",
    [
        # current pointer targets a non-ACTIVE version while another is ACTIVE
        ("v2", [("v1", "ACTIVE"), ("v2", "DEACTIVATED")],
         "is not the unique ACTIVE version"),
        # current pointer claims a REVOKED version
        ("v1", [("v1", "REVOKED"), ("v2", "ACTIVE")],
         "is not the unique ACTIVE version"),
        # no ACTIVE version anywhere in the ring
        ("v1", [("v1", "DEACTIVATED"), ("v2", "REVOKED")],
         "no ACTIVE key version exists"),
    ],
)
def test_restart_refused_for_other_ring_invariant_violations(
    state_path, current, extra_states, reason_fragment
):
    entries = [_snapshot_entry(version, state) for version, state in extra_states]
    _write_state_file(state_path, key_id="primary", current=current, entries=entries)

    with pytest.raises(PersistedStateInvalidError) as exc:
        _boot("primary", [entries[0]], FileStateStore(state_path))
    assert exc.value.code.value == "PERSISTED_STATE_INVALID"
    assert reason_fragment in str(exc.value)
    log_case(
        "restart-invariant-violation",
        current=current,
        states={version: state for version, state in extra_states},
        reason_fragment=reason_fragment,
        reason=exc.value.code.value,
    )


def test_restart_refused_for_multi_active_via_inmemory_store():
    """Validation lives in the manager, so every store backend is covered."""
    entries = [
        VersionSnapshot("v1", generate_local_key(), KeyState.ACTIVE, "t"),
        VersionSnapshot("v2", generate_local_key(), KeyState.ACTIVE, "t"),
    ]
    store = InMemoryStateStore()
    store.save(RingSnapshot(key_id="primary", current_version="v2",
                            versions=tuple(entries)))
    with pytest.raises(PersistedStateInvalidError) as exc:
        KeyManager("primary", InlineKeySource([]), NullAuditLogger(), store)
    assert exc.value.code.value == "PERSISTED_STATE_INVALID"
    assert "2 versions are ACTIVE" in str(exc.value)
    log_case("restart-inmemory-multi-active-rejected",
             states={"v1": "ACTIVE", "v2": "ACTIVE"})


def test_inconsistent_snapshot_is_not_repaired_or_fallen_back(state_path):
    """We never silently fix the snapshot nor fall back to the key source."""
    good_v1 = _snapshot_entry("v1", "ACTIVE")
    bad_entries = [good_v1, _snapshot_entry("v2", "ACTIVE")]
    _write_state_file(state_path, key_id="primary", current="v2",
                      entries=bad_entries)

    source = [good_v1]  # a perfectly valid source exists, but must not be used
    with pytest.raises(PersistedStateInvalidError):
        _boot("primary", source, FileStateStore(state_path))

    # The contradictory snapshot must remain untouched on disk (no "repair").
    with open(state_path, encoding="utf-8") as handle:
        on_disk = json.load(handle)
    assert on_disk["current_version"] == "v2"
    assert [v["state"] for v in on_disk["versions"]] == ["ACTIVE", "ACTIVE"]
    log_case("restart-no-repair-no-fallback",
             current="v2", states={"v1": "ACTIVE", "v2": "ACTIVE"})


# --------------------------------------------------------------------------- #
# Legitimate historical state: restarts normally, current never rolls back
# --------------------------------------------------------------------------- #
def test_valid_history_restarts_without_rollback(state_path):
    """current ACTIVE + history DEACTIVATED/REVOKED boots and keeps current."""
    from .conftest import make_inline_versions

    source = make_inline_versions("ACTIVE")  # frozen source still says v1
    m1 = _boot("primary", source, FileStateStore(state_path))
    v1_cipher_revoked_later = m1.encrypt(b"will-be-revoked", CTX)
    m1.rotate()  # v2 current, v1 DEACTIVATED
    v2_cipher = m1.encrypt(b"on-v2", CTX)
    m1.rotate()  # v3 current, v2 DEACTIVATED
    v3_cipher = m1.encrypt(b"on-v3", CTX)
    m1.revoke("v1")

    # Restart over the same snapshot: legal shape (v3 ACTIVE current,
    # v2 DEACTIVATED, v1 REVOKED) must boot and preserve the latest pointer.
    m2 = _boot("primary", source, FileStateStore(state_path))
    assert m2.current_version() == "v3"
    states = {v.version: v.state for v in m2.list_versions()}
    assert states == {"v1": KeyState.REVOKED, "v2": KeyState.DEACTIVATED,
                      "v3": KeyState.ACTIVE}

    # New writes still use the restored (latest) current, never v1.
    fresh = m2.encrypt(b"post-restart", CTX)
    assert m2.decrypt(fresh, CTX) == b"post-restart"

    # Historical ciphertexts keep their per-version rules after restart.
    assert m2.decrypt(v2_cipher, CTX) == b"on-v2"   # DEACTIVATED decrypts
    assert m2.decrypt(v3_cipher, CTX) == b"on-v3"   # ACTIVE decrypts
    with pytest.raises(KeyRevokedError):
        m2.decrypt(v1_cipher_revoked_later, CTX)    # REVOKED rejected
    log_case("restart-valid-history-no-rollback",
             current="v3", states={k: s.value for k, s in states.items()})
