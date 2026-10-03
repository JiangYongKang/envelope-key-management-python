"""Restart consistency: lifecycle + migration outcomes survive a restart."""

from __future__ import annotations

import json

import pytest

from app.audit import NullAuditLogger
from app.errors import ConfigurationError, KeyRevokedError, StatePersistFailedError
from app.key_source import InlineKeySource, LocalKeySource
from app.manager import KeyManager
from app.models import KeyState
from app.state_store import FileStateStore, InMemoryStateStore

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


# --------------------------------------------------------------------------- #
# Lifecycle outcomes survive restart
# --------------------------------------------------------------------------- #
def test_rotation_and_revoke_survive_restart(state_path, source_versions):
    store = FileStateStore(state_path)
    m1 = _boot("primary", source_versions, store)
    old_token = m1.encrypt(b"old-data", CTX)
    m1.rotate()  # v2
    mid_token = m1.encrypt(b"mid-data", CTX)
    m1.rotate()  # v3
    m1.revoke("v1")

    # Simulate a restart: a brand-new manager over the same store + source.
    m2 = _boot("primary", source_versions, FileStateStore(state_path))
    assert m2.current_version() == "v3"  # never falls back to source's v1
    states = {v.version: v.state for v in m2.list_versions()}
    assert states == {"v1": KeyState.REVOKED, "v2": KeyState.DEACTIVATED,
                      "v3": KeyState.ACTIVE}
    # Historical ciphertexts follow their own rules after restart.
    with pytest.raises(KeyRevokedError):
        m2.decrypt(old_token, CTX)
    assert m2.decrypt(mid_token, CTX) == b"mid-data"
    log_case("restart-lifecycle", current="v3", states={k: s.value for k, s in states.items()})


def test_migration_outcome_survives_restart(state_path, source_versions):
    store = FileStateStore(state_path)
    m1 = _boot("primary", source_versions, store)
    old_token = m1.encrypt(b"migrate-me", CTX)
    m1.rotate()  # v2 current
    migrated = m1.migrate([old_token]).items[0].ciphertext

    m2 = _boot("primary", source_versions, FileStateStore(state_path))
    # Migrated token: decrypts with the original context, same plaintext.
    assert m2.decrypt(migrated, CTX) == b"migrate-me"
    # Unmigrated historical token: still decrypts (v1 only deactivated).
    assert m2.decrypt(old_token, CTX) == b"migrate-me"
    # New writes after restart use the restored current version.
    fresh = m2.encrypt(b"post-restart", CTX)
    assert m2.decrypt(fresh, CTX) == b"post-restart"
    log_case("restart-migration", current=m2.current_version())


def test_first_boot_persists_initial_snapshot(state_path, source_versions):
    _boot("primary", source_versions, FileStateStore(state_path))
    with open(state_path, encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["key_id"] == "primary"
    assert document["current_version"] == "v1"
    assert [v["version"] for v in document["versions"]] == ["v1"]
    log_case("restart-initial-snapshot")


def test_restart_works_even_if_key_source_breaks(state_path, source_versions):
    """Once a snapshot exists, the ring no longer depends on the source."""
    m1 = _boot("primary", source_versions, FileStateStore(state_path))
    m1.rotate()
    token = m1.encrypt(b"durable", CTX)

    class BrokenSource(LocalKeySource):
        def load(self):  # would fail if consulted
            raise ConfigurationError("source disappeared")

    m2 = KeyManager("primary", BrokenSource(), NullAuditLogger(),
                    FileStateStore(state_path))
    assert m2.current_version() == "v2"
    assert m2.decrypt(token, CTX) == b"durable"
    log_case("restart-source-independent")


def test_snapshot_key_id_mismatch_refuses_boot(state_path, source_versions):
    _boot("primary", source_versions, FileStateStore(state_path))
    with pytest.raises(ConfigurationError) as exc:
        _boot("other-key", source_versions, FileStateStore(state_path))
    assert exc.value.code.value == "CONFIG_INVALID"
    log_case("restart-key-id-mismatch")


# --------------------------------------------------------------------------- #
# Persistence failure => the operation fails, nothing half-applied
# --------------------------------------------------------------------------- #
class FailingStore(InMemoryStateStore):
    def save(self, snapshot):
        raise StatePersistFailedError("disk full (simulated)")


def test_rotate_fails_when_state_cannot_be_persisted(source_versions):
    manager = _boot("primary", source_versions, None)
    # Swap in a store that starts failing AFTER bootstrap.
    manager._store = FailingStore()
    with pytest.raises(StatePersistFailedError) as exc:
        manager.rotate()
    assert exc.value.code.value == "STATE_PERSIST_FAILED"
    # In-memory state rolled back: no phantom version, current unchanged.
    assert manager.current_version() == "v1"
    assert [v.version for v in manager.list_versions()] == ["v1"]
    # And the manager keeps working once the store recovers.
    manager._store = InMemoryStateStore()
    assert manager.rotate() == "v2"
    log_case("persist-failure-rotate-rollback")


def test_revoke_fails_when_state_cannot_be_persisted(source_versions):
    manager = _boot("primary", source_versions, None)
    manager.rotate()
    manager._store = FailingStore()
    with pytest.raises(StatePersistFailedError):
        manager.revoke("v1")
    assert manager.get_state("v1") is KeyState.DEACTIVATED  # rolled back
    log_case("persist-failure-revoke-rollback")


def test_bootstrap_fails_when_initial_snapshot_cannot_be_persisted(source_versions):
    with pytest.raises(StatePersistFailedError):
        _boot("primary", source_versions, FailingStore())
    log_case("persist-failure-bootstrap")


def test_file_state_store_survives_corrupt_snapshot(state_path, source_versions):
    with open(state_path, "w", encoding="utf-8") as handle:
        handle.write("{not json")
    with pytest.raises(ConfigurationError):
        _boot("primary", source_versions, FileStateStore(state_path))
    log_case("restart-corrupt-snapshot")
