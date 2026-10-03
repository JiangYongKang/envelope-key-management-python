"""Ciphertext migration: batch upgrade of historical tokens to the current key."""

from __future__ import annotations

import pytest

from app.crypto import encrypt_envelope
from app.errors import KeyManagementError
from app.models import (
    EncryptionContext,
    KeyOperation,
    KeyState,
    MigrationStatus,
    OperationResult,
)

from .conftest import log_case, retarget_token, tamper_token

CTX = {"tenant": "acme", "dataset": "orders"}


@pytest.fixture
def rotated_manager(manager_factory):
    """Manager with v1 (deactivated) + v2 (current) and a v1 token."""
    manager = manager_factory(("ACTIVE",))
    old_token = manager.encrypt(b"legacy-payload", CTX)
    manager.rotate()  # v2 current, v1 deactivated
    return manager, old_token


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_migrate_upgrades_old_token_and_preserves_plaintext(rotated_manager):
    manager, old_token = rotated_manager
    report = manager.migrate([old_token])

    assert report.total == 1 and report.migrated == 1 and report.failed == 0
    item = report.items[0]
    assert item.status is MigrationStatus.MIGRATED
    assert item.key_version == "v1" and item.target_version == "v2"
    # New token decrypts with the ORIGINAL context to the SAME plaintext.
    assert manager.decrypt(item.ciphertext, CTX) == b"legacy-payload"
    # The old token remains decryptable too (v1 is deactivated, not revoked).
    assert manager.decrypt(old_token, CTX) == b"legacy-payload"
    log_case("migrate-upgrade", old="v1", new="v2", token=old_token)


def test_migrate_report_never_contains_plaintext(rotated_manager):
    manager, old_token = rotated_manager
    report = manager.migrate([old_token])
    rendered = str(report.to_dict())
    assert "legacy-payload" not in rendered
    log_case("migrate-no-plaintext-leak")


def test_migrate_without_context_reuses_bound_context(rotated_manager):
    """Caller supplies no plaintext and no context; the token's own context
    stays bound, so decryption with the original context keeps working."""
    manager, old_token = rotated_manager
    new_token = manager.migrate([old_token]).items[0].ciphertext
    assert manager.decrypt(new_token, CTX) == b"legacy-payload"
    # ... and a wrong context is still rejected afterwards.
    with pytest.raises(KeyManagementError) as exc:
        manager.decrypt(new_token, {"tenant": "acme", "dataset": "other"})
    assert exc.value.code.value == "CONTEXT_MISMATCH"
    log_case("migrate-keeps-context")


def test_migrate_with_matching_context_guard_succeeds(rotated_manager):
    manager, old_token = rotated_manager
    report = manager.migrate([old_token], context=dict(CTX))
    assert report.migrated == 1
    log_case("migrate-context-guard-ok")


def test_migrate_with_wrong_context_guard_fails_item(rotated_manager):
    manager, old_token = rotated_manager
    report = manager.migrate([old_token], context={"tenant": "someone-else"})
    assert report.failed == 1
    item = report.items[0]
    assert item.status is MigrationStatus.FAILED
    assert item.error_code == "CONTEXT_MISMATCH"
    assert item.ciphertext is None
    log_case("migrate-context-guard-mismatch")


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #
def test_remigrating_current_token_is_idempotent_noop(rotated_manager):
    manager, old_token = rotated_manager
    first = manager.migrate([old_token]).items[0].ciphertext
    second = manager.migrate([first])
    item = second.items[0]
    assert item.status is MigrationStatus.ALREADY_CURRENT
    assert item.ciphertext == first  # unchanged, no gratuitous re-encryption
    assert manager.decrypt(item.ciphertext, CTX) == b"legacy-payload"
    log_case("migrate-idempotent", status=item.status.value)


def test_repeated_batch_migration_is_explainable(rotated_manager):
    manager, old_token = rotated_manager
    batch = [old_token, old_token]
    first = manager.migrate(batch)
    assert first.migrated == 2
    second = manager.migrate([i.ciphertext for i in first.items])
    assert second.already_current == 2 and second.migrated == 0
    log_case("migrate-repeat-batch", first=first.migrated,
             second_already=second.already_current)


# --------------------------------------------------------------------------- #
# Per-item failure classification
# --------------------------------------------------------------------------- #
def test_migrate_classifies_each_bad_item(rotated_manager):
    manager, old_token = rotated_manager
    kv2 = manager._ring["v2"]

    foreign = encrypt_envelope(kv2.key_material, "other-ring", "v2", b"x",
                               EncryptionContext(CTX)).to_token()
    unknown_ver = encrypt_envelope(kv2.key_material, manager.key_id, "v404", b"x",
                                   EncryptionContext(CTX)).to_token()
    tokens = [
        old_token,                 # 0: ok -> MIGRATED
        "not-a-token",             # 1: CIPHERTEXT_INVALID
        tamper_token(old_token),   # 2: CIPHERTEXT_TAMPERED
        foreign,                   # 3: KEY_ID_MISMATCH
        unknown_ver,               # 4: KEY_VERSION_NOT_FOUND
        retarget_token(old_token, version="v2"),  # 5: AAD mismatch -> TAMPERED
    ]
    report = manager.migrate(tokens)

    assert report.total == len(tokens)
    assert report.migrated == 1
    assert report.failed == 5
    codes = [item.error_code for item in report.items]
    assert codes == [
        None,
        "CIPHERTEXT_INVALID",
        "CIPHERTEXT_TAMPERED",
        "KEY_ID_MISMATCH",
        "KEY_VERSION_NOT_FOUND",
        "CIPHERTEXT_TAMPERED",
    ]
    # Successes and failures are reported per item; no silent skips.
    assert [i.index for i in report.items] == list(range(len(tokens)))
    assert report.items[0].ciphertext is not None
    assert all(i.ciphertext is None for i in report.items[1:])
    log_case("migrate-classify", codes=[c for c in codes if c])


def test_migrate_revoked_source_version_fails_item(manager_factory):
    manager = manager_factory(("ACTIVE",))
    old_token = manager.encrypt(b"doomed", CTX)
    manager.rotate()
    manager.revoke("v1")
    report = manager.migrate([old_token])
    item = report.items[0]
    assert item.status is MigrationStatus.FAILED
    assert item.error_code == "KEY_REVOKED"
    assert item.ciphertext is None
    log_case("migrate-source-revoked")


def test_migrate_unusable_target_fails_instead_of_bad_ciphertext(rotated_manager):
    """If the target (current) version is not ACTIVE at migration time, the
    item must fail explicitly — never emit an undecryptable token."""
    manager, old_token = rotated_manager
    current = manager.current_version()
    kv = manager._ring[current]
    # Simulate a corrupted ring where the current pointer hits a revoked key.
    from app.models import KeyVersion
    manager._ring[current] = KeyVersion(
        version=kv.version, key_material=kv.key_material,
        state=KeyState.REVOKED, created_at=kv.created_at,
    )
    report = manager.migrate([old_token])
    item = report.items[0]
    assert item.status is MigrationStatus.FAILED
    assert item.error_code == "KEY_REVOKED"
    assert item.ciphertext is None
    log_case("migrate-target-revoked", target=current)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def test_migration_is_audited_per_item(rotated_manager, null_audit):
    manager, old_token = rotated_manager
    manager.migrate([old_token, "garbage"])
    records = [r for r in null_audit.read_all()
               if r.operation is KeyOperation.MIGRATE]
    assert len(records) == 2
    success = [r for r in records if r.result is OperationResult.SUCCESS]
    failure = [r for r in records if r.result is OperationResult.FAILURE]
    assert len(success) == 1 and success[0].key_version == "v1"
    assert "target=v2" in success[0].detail
    assert len(failure) == 1 and failure[0].error_code == "CIPHERTEXT_INVALID"
    # Digests only, never plaintext.
    assert all("legacy-payload" not in (r.detail or "") for r in records)
    log_case("migrate-audit", records=len(records))


def test_migrate_rejects_non_list_input(manager):
    with pytest.raises(TypeError):
        manager.migrate("not-a-list")  # type: ignore[arg-type]
    log_case("migrate-bad-input-type")
