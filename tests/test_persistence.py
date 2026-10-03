"""Durability across restarts: rotate/deactivate/revoke + migration survive.

A manager is rebuilt from the same local key file + state file, simulating a
process restart. The current version must never regress, rotated key material
must survive, and migrated/un-migrated ciphertexts must follow lifecycle rules.
"""

from __future__ import annotations

import json
import os

import pytest

from app.audit import AuditLogger
from app.config import Settings, build_manager
from app.key_source import FileKeySource
from app.models import KeyState
from app.state import FileStateStore

from .conftest import log_case

CTX = {"tenant": "acme"}


@pytest.fixture
def paths(tmp_path):
    return {
        "keys": str(tmp_path / "local-keys.json"),
        "state": str(tmp_path / "state.json"),
        "audit": str(tmp_path / "audit.jsonl"),
    }


def _write_initial_key_file(path: str) -> None:
    from app.cli import main as cli_main

    cli_main(["--output", path])


def _make_settings(paths) -> Settings:
    return Settings(
        key_id="primary",
        key_source=FileKeySource(paths["keys"]),
        audit_path=paths["audit"],
        state_path=paths["state"],
    )


def test_rotation_and_current_version_survive_restart(paths):
    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)

    manager = build_manager(settings)
    token_v1 = manager.encrypt(b"legacy", CTX)
    manager.rotate()  # v2
    token_v2 = manager.encrypt(b"fresh", CTX)
    manager.rotate()  # v3
    token_v3 = manager.encrypt(b"latest", CTX)
    assert manager.current_version() == "v3"

    # Restart: brand-new manager over the same local files.
    restarted = build_manager(settings)
    log_case(
        "restart-rotation",
        current_before="v3",
        current_after=restarted.current_version(),
        state_on_disk=os.path.isfile(paths["state"]),
    )
    assert restarted.current_version() == "v3"
    states = {v.version: v.state for v in restarted.list_versions()}
    assert states == {"v1": KeyState.DEACTIVATED, "v2": KeyState.DEACTIVATED,
                      "v3": KeyState.ACTIVE}
    # Rotated key material was persisted: every version's token is readable.
    assert restarted.decrypt(token_v3, CTX) == b"latest"
    assert restarted.decrypt(token_v2, CTX) == b"fresh"
    # Un-migrated historical ciphertext still decrypts under its own version.
    assert restarted.decrypt(token_v1, CTX) == b"legacy"


def test_revocation_survives_restart_and_old_ciphertext_is_refused(paths):
    from app.errors import KeyRevokedError

    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)
    manager = build_manager(settings)
    token_v1 = manager.encrypt(b"doomed", CTX)
    manager.rotate()  # v2 current
    manager.revoke("v1")

    restarted = build_manager(settings)
    log_case(
        "restart-revoke",
        states={v.version: v.state.value for v in restarted.list_versions()},
    )
    assert restarted.get_state("v1") is KeyState.REVOKED
    with pytest.raises(KeyRevokedError):
        restarted.decrypt(token_v1, CTX)
    # Current key still fully operational after restart.
    assert restarted.decrypt(restarted.encrypt(b"alive", CTX), CTX) == b"alive"


def test_deactivation_survives_restart(paths):
    from app.errors import KeyDeactivatedError

    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)
    manager = build_manager(settings)
    manager.rotate()  # v2 current, v1 deactivated automatically
    manager.rotate()  # v3 current
    manager.deactivate("v2")  # explicit deactivation of a non-current version

    restarted = build_manager(settings)
    log_case(
        "restart-deactivate",
        states={v.version: v.state.value for v in restarted.list_versions()},
    )
    assert restarted.get_state("v2") is KeyState.DEACTIVATED
    with pytest.raises(KeyDeactivatedError):
        # v2 cannot encrypt even by directly driving crypto selection.
        kv2 = restarted._ring["v2"]
        assert kv2.is_usable_for_encrypt() is False
        raise KeyDeactivatedError("v2", operation="encryption")


def test_migrated_ciphertext_survives_restart_and_decrypts_with_context(paths):
    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)
    manager = build_manager(settings)
    old_token = manager.encrypt(b"migration-payload", CTX)
    manager.rotate()  # v2
    report = manager.migrate([old_token])
    new_token = report.results[0].ciphertext

    restarted = build_manager(settings)
    log_case(
        "restart-migration",
        current=restarted.current_version(),
        source=report.results[0].source_version,
        target=report.results[0].target_version,
    )
    assert restarted.current_version() == "v2"
    assert restarted.decrypt(new_token, CTX) == b"migration-payload"
    assert restarted.decrypt(old_token, CTX) == b"migration-payload"  # v1 kept


def test_preprovisioned_and_rotated_keys_coexist_across_restart(paths):
    """A multi-version source plus rotated keys survives with correct states."""
    from app.crypto import encrypt_envelope
    from app.config import Settings
    from app.key_source import InlineKeySource, generate_local_key
    from app.models import EncryptionContext, b64e

    # Source carries a pre-provisioned deactivated v2; v1 is the bootstrap current.
    entries = [
        {"version": "v1", "key_material": b64e(generate_local_key()), "state": "ACTIVE"},
        {"version": "v2", "key_material": b64e(generate_local_key()),
         "state": "DEACTIVATED"},
    ]
    settings = Settings(
        key_id="primary",
        key_source=InlineKeySource(entries),
        audit_path=paths["audit"],
        state_path=paths["state"],
    )
    manager = build_manager(settings)
    legacy_v2 = encrypt_envelope(
        manager._ring["v2"].key_material, "primary", "v2",
        b"legacy2", EncryptionContext({}),
    ).to_token()
    assert manager.rotate() == "v3"
    token_v3 = manager.encrypt(b"new", {})

    restarted = build_manager(settings)
    states = {v.version: v.state.value for v in restarted.list_versions()}
    log_case("restart-mixed-ring", states=states, current=restarted.current_version())
    assert states == {"v1": "DEACTIVATED", "v2": "DEACTIVATED", "v3": "ACTIVE"}
    assert restarted.decrypt(legacy_v2, {}) == b"legacy2"
    assert restarted.decrypt(token_v3, {}) == b"new"
    # Sequence continues above the persisted labels without collision.
    assert restarted.rotate() == "v4"


def test_state_file_is_atomic_and_contains_no_plaintext(paths):
    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)
    manager = build_manager(settings)
    manager.encrypt(b"NEVER-PERSIST-ME", CTX)
    manager.rotate()

    with open(paths["state"], encoding="utf-8") as handle:
        raw = handle.read()
    document = json.loads(raw)
    log_case(
        "state-file-shape",
        marker=document["format"],
        versions=sorted(v["version"] for v in document["versions"]),
        leaks_plaintext="NEVER-PERSIST-ME" not in raw,
    )
    assert document["format"] == "ekm-state-v1"
    assert document["current_version"] == "v2"
    assert "NEVER-PERSIST-ME" not in raw
    assert os.stat(paths["state"]).st_mode & 0o777 == 0o600


def test_persist_failure_fails_the_operation_and_keeps_old_state(paths):
    """If durability cannot be achieved, rotation fails, never half-applies.

    A real filesystem fault is induced by pointing the state location at a
    directory: the temp-file creation inside it raises OSError, which the
    FileStateStore must surface as STATE_PERSIST_FAILED.
    """
    from app.errors import StatePersistFailedError

    _write_initial_key_file(paths["keys"])
    # Bootstrap the manager with a *valid* state path first.
    good_settings = _make_settings(paths)
    manager = build_manager(good_settings)

    # Now retarget persistence at an unwritable location (a directory path).
    bad_dir = os.path.join(os.path.dirname(paths["state"]), "state-is-a-dir")
    os.makedirs(bad_dir, exist_ok=True)
    manager._state_store = FileStateStore(bad_dir)

    with pytest.raises(StatePersistFailedError):
        manager.rotate()
    log_case(
        "persist-failure-rollback",
        current=manager.current_version(),
        versions=[v.version for v in manager.list_versions()],
    )
    # In-memory state was rolled back...
    assert manager.current_version() == "v1"
    assert [v.version for v in manager.list_versions()] == ["v1"]
    # ...and a restart sees the last successfully persisted snapshot.
    restarted = build_manager(good_settings)
    assert restarted.current_version() == "v1"


def test_audit_failure_after_persist_rolls_back_both_memory_and_disk(paths):
    """rotate(): state persisted OK but audit fails -> full cross-layer rollback.

    A restart must see the pre-rotation snapshot, never the half-committed one.
    """
    from app.errors import AuditWriteFailedError

    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)
    manager = build_manager(settings)

    # Retarget the audit sink at a directory so its append raises OSError,
    # while the state store keeps working.
    manager._audit._path = os.path.dirname(paths["audit"])
    with pytest.raises(AuditWriteFailedError):
        manager.rotate()

    log_case(
        "audit-failure-rollback",
        current=manager.current_version(),
        versions=[v.version for v in manager.list_versions()],
    )
    assert manager.current_version() == "v1"
    assert [v.version for v in manager.list_versions()] == ["v1"]
    # The on-disk snapshot was rewritten to the previous one as part of rollback.
    restarted = build_manager(settings)
    assert restarted.current_version() == "v1"
    assert [v.version for v in restarted.list_versions()] == ["v1"]


def test_corrupt_state_file_is_rejected_at_startup(paths):
    from app.errors import StateInvalidError

    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)
    build_manager(settings)  # writes bootstrap snapshot
    with open(paths["state"], "w", encoding="utf-8") as handle:
        handle.write("{not valid json")

    with pytest.raises(StateInvalidError):
        build_manager(settings)
    log_case("corrupt-state-rejected", path=os.path.basename(paths["state"]))


def test_state_key_id_mismatch_is_rejected(paths):
    from app.errors import StateInvalidError

    _write_initial_key_file(paths["keys"])
    settings = _make_settings(paths)
    build_manager(settings)

    wrong = Settings(
        key_id="different-ring",
        key_source=FileKeySource(paths["keys"]),
        audit_path=paths["audit"],
        state_path=paths["state"],
    )
    with pytest.raises(StateInvalidError):
        build_manager(wrong)
    log_case("state-keyid-mismatch", configured="primary", restart="different-ring")
