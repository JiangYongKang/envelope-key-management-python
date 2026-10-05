"""Restart-time integrity: inconsistent persisted state refuses to boot.

Covers the invariant shared with first boot from the key source: exactly
one ACTIVE version exists and it is the current one. A persisted snapshot
violating it (e.g. manually restored/edited state with two ACTIVE versions)
must abort startup with the distinguishable STATE_INCONSISTENT reason —
never silently load, self-heal or roll back. Legal historical states
(current ACTIVE, history DEACTIVATED/REVOKED) must keep booting normally
with the current version untouched.
"""

from __future__ import annotations

import json

import pytest

from app.audit import NullAuditLogger
from app.errors import (
    ConfigurationError,
    KeyRevokedError,
    PersistedStateInconsistentError,
)
from app.key_source import InlineKeySource, generate_local_key
from app.manager import KeyManager
from app.models import KeyState
from app.state_store import (
    FileStateStore,
    InMemoryStateStore,
    RingSnapshot,
    VersionSnapshot,
)

from .conftest import log_case, make_inline_versions

CTX = {"tenant": "acme"}


def _boot(key_id, versions, store, audit=None):
    return KeyManager(key_id, InlineKeySource(versions),
                      audit or NullAuditLogger(), store)


@pytest.fixture
def state_path(tmp_path):
    return str(tmp_path / "ekm-state.json")


@pytest.fixture
def source_versions():
    # The on-disk key source stays frozen at v1-ACTIVE forever; all lifecycle
    # progress must come from the state store after restart.
    return make_inline_versions("ACTIVE")


def _read_doc(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write_doc(path, doc):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _snapshot(current, *states):
    """Hand-build a ring snapshot (for the store-agnostic manager check)."""
    return RingSnapshot(
        key_id="primary",
        current_version=current,
        versions=tuple(
            VersionSnapshot(
                version=f"v{i}",
                key_material=generate_local_key(),
                state=KeyState(state),
                created_at="2026-10-05T00:00:00.000+00:00",
            )
            for i, state in enumerate(states, start=1)
        ),
    )


# --------------------------------------------------------------------------- #
# Inconsistent persisted state => startup refused with STATE_INCONSISTENT
# --------------------------------------------------------------------------- #
def test_restart_refuses_snapshot_with_two_active_versions(state_path, source_versions):
    """The reported scenario: restored/tidied state with v1 AND v2 ACTIVE."""
    m1 = _boot("primary", source_versions, FileStateStore(state_path))
    m1.rotate()  # v1 DEACTIVATED, v2 ACTIVE+current — a legal on-disk state

    # Doctor the persisted file: bring the old v1 back to ACTIVE as well.
    doc = _read_doc(state_path)
    doc["versions"][0]["state"] = "ACTIVE"
    _write_doc(state_path, doc)

    with pytest.raises(PersistedStateInconsistentError) as exc:
        _boot("primary", source_versions, FileStateStore(state_path))
    assert exc.value.code.value == "STATE_INCONSISTENT"
    # The reason names the offending versions so the bad file is identifiable.
    assert "v1" in str(exc.value) and "v2" in str(exc.value)
    # It is still a ConfigurationError subclass for existing callers...
    assert isinstance(exc.value, ConfigurationError)
    # ...but distinguishable from a plain config problem.
    assert exc.value.code.value != "CONFIG_INVALID"
    # No silent repair / rollback: the snapshot on disk is left untouched.
    assert _read_doc(state_path) == doc
    log_case("restart-two-active-refused",
             active=["v1", "v2"], current="v2",
             verdict=exc.value.code.value)


def test_restart_refuses_current_pointer_not_active(state_path, source_versions):
    """current points at a DEACTIVATED version while another is ACTIVE."""
    m1 = _boot("primary", source_versions, FileStateStore(state_path))
    m1.rotate()  # v1 DEACTIVATED, v2 ACTIVE+current

    doc = _read_doc(state_path)
    # Contradiction: current stays v2 but v2 is DEACTIVATED, v1 ACTIVE.
    doc["versions"][0]["state"] = "ACTIVE"
    doc["versions"][1]["state"] = "DEACTIVATED"
    _write_doc(state_path, doc)

    with pytest.raises(PersistedStateInconsistentError) as exc:
        _boot("primary", source_versions, FileStateStore(state_path))
    assert exc.value.code.value == "STATE_INCONSISTENT"
    assert _read_doc(state_path) == doc  # untouched
    log_case("restart-current-not-active-refused",
             current="v2", states={"v1": "ACTIVE", "v2": "DEACTIVATED"},
             verdict=exc.value.code.value)


def test_restart_refuses_snapshot_without_any_active(state_path, source_versions):
    m1 = _boot("primary", source_versions, FileStateStore(state_path))
    m1.rotate()

    doc = _read_doc(state_path)
    for entry in doc["versions"]:
        entry["state"] = "DEACTIVATED"
    _write_doc(state_path, doc)

    with pytest.raises(PersistedStateInconsistentError) as exc:
        _boot("primary", source_versions, FileStateStore(state_path))
    assert exc.value.code.value == "STATE_INCONSISTENT"
    assert _read_doc(state_path) == doc
    log_case("restart-no-active-refused",
             states={"v1": "DEACTIVATED", "v2": "DEACTIVATED"},
             verdict=exc.value.code.value)


# --------------------------------------------------------------------------- #
# The same invariant is enforced for ANY state store (not just the file one)
# --------------------------------------------------------------------------- #
def test_inmemory_store_inconsistent_snapshot_refused(source_versions):
    store = InMemoryStateStore()
    store.save(_snapshot("v2", "ACTIVE", "ACTIVE"))  # two ACTIVE versions
    with pytest.raises(PersistedStateInconsistentError) as exc:
        _boot("primary", source_versions, store)
    assert exc.value.code.value == "STATE_INCONSISTENT"
    log_case("restart-two-active-refused-inmemory", verdict=exc.value.code.value)


def test_inmemory_store_current_mismatch_refused(source_versions):
    store = InMemoryStateStore()
    # current=v1 but v1 is DEACTIVATED and v2 is the ACTIVE one.
    store.save(_snapshot("v1", "DEACTIVATED", "ACTIVE"))
    with pytest.raises(PersistedStateInconsistentError) as exc:
        _boot("primary", source_versions, store)
    assert exc.value.code.value == "STATE_INCONSISTENT"
    log_case("restart-current-mismatch-refused-inmemory",
             verdict=exc.value.code.value)


def test_inmemory_store_zero_active_refused(source_versions):
    store = InMemoryStateStore()
    store.save(_snapshot("v1", "DEACTIVATED", "REVOKED"))
    with pytest.raises(PersistedStateInconsistentError) as exc:
        _boot("primary", source_versions, store)
    assert exc.value.code.value == "STATE_INCONSISTENT"
    log_case("restart-zero-active-refused-inmemory",
             verdict=exc.value.code.value)


# --------------------------------------------------------------------------- #
# Alignment: first boot from config enforces the very same invariant
# --------------------------------------------------------------------------- #
def test_first_boot_source_with_two_active_also_refused():
    with pytest.raises(ConfigurationError) as exc:
        _boot("primary", make_inline_versions("ACTIVE", "ACTIVE"),
              InMemoryStateStore())
    assert exc.value.code.value == "CONFIG_INVALID"
    log_case("first-boot-two-active-refused", verdict=exc.value.code.value)


# --------------------------------------------------------------------------- #
# Legal historical states keep booting; current never regresses
# --------------------------------------------------------------------------- #
def test_legal_history_reboots_with_current_intact(state_path, source_versions):
    m1 = _boot("primary", source_versions, FileStateStore(state_path))
    revoked_token = m1.encrypt(b"revoked-era", CTX)
    m1.rotate()  # v2
    deactivated_token = m1.encrypt(b"deactivated-era", CTX)
    m1.rotate()  # v3 current
    m1.revoke("v1")

    # Restart over the legal snapshot: v1 REVOKED, v2 DEACTIVATED, v3 ACTIVE.
    m2 = _boot("primary", source_versions, FileStateStore(state_path))
    assert m2.current_version() == "v3"  # latest stays current, no rollback
    states = {v.version: v.state for v in m2.list_versions()}
    assert states == {"v1": KeyState.REVOKED, "v2": KeyState.DEACTIVATED,
                      "v3": KeyState.ACTIVE}
    active = [v.version for v in m2.list_versions()
              if v.state is KeyState.ACTIVE]
    assert active == ["v3"]  # exactly one encrypt-capable version
    # Historical ciphertexts follow their own rules, unchanged by the hardening.
    with pytest.raises(KeyRevokedError):
        m2.decrypt(revoked_token, CTX)
    assert m2.decrypt(deactivated_token, CTX) == b"deactivated-era"
    fresh = m2.encrypt(b"post-restart", CTX)
    assert m2.decrypt(fresh, CTX) == b"post-restart"
    log_case("restart-legal-history-ok", current="v3",
             states={k: s.value for k, s in states.items()})


def test_legal_snapshot_file_untouched_by_restart(state_path, source_versions):
    m1 = _boot("primary", source_versions, FileStateStore(state_path))
    m1.rotate()
    before = _read_doc(state_path)
    m2 = _boot("primary", source_versions, FileStateStore(state_path))
    assert m2.current_version() == "v2"
    assert _read_doc(state_path) == before  # restart never rewrites state
    log_case("restart-legal-snapshot-untouched", current="v2")
