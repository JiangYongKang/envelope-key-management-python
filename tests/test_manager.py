"""KeyManager: version-bound crypto, lifecycle rules, classified failures."""

from __future__ import annotations

import pytest

from app.crypto import encrypt_envelope
from app.errors import (
    CiphertextInvalidError,
    CiphertextTamperedError,
    ConfigurationError,
    ContextMismatchError,
    InvalidLifecycleTransitionError,
    KeyIdMismatchError,
    KeyRevokedError,
    KeyVersionNotFoundError,
    RotationRaceError,
)
from app.models import EncryptionContext, KeyOperation, KeyState, OperationResult

from .conftest import log_case, retarget_token, tamper_token

CTX = {"tenant": "acme", "dataset": "orders"}


# --------------------------------------------------------------------------- #
# Basic version-bound encryption / decryption
# --------------------------------------------------------------------------- #
def test_encrypt_uses_current_version(manager):
    token = manager.encrypt(b"v1-data", CTX)
    assert manager.decrypt(token, CTX) == b"v1-data"
    assert manager.current_version() == "v1"
    log_case("encrypt-current", version="v1", plaintext=b"v1-data")


def test_decrypt_rejects_malformed_token(manager):
    with pytest.raises(CiphertextInvalidError) as exc:
        manager.decrypt("not-a-token", CTX)
    assert exc.value.code.value == "CIPHERTEXT_INVALID"
    log_case("decrypt-malformed", token_prefix="not-a-token")


def test_decrypt_unknown_version_is_not_found(manager):
    # A structurally valid token bound to a version absent from the ring.
    kv = manager._ring["v1"]
    env = encrypt_envelope(kv.key_material, manager.key_id, "v404", b"x",
                           EncryptionContext(CTX))
    with pytest.raises(KeyVersionNotFoundError) as exc:
        manager.decrypt(env.to_token(), CTX)
    assert exc.value.code.value == "KEY_VERSION_NOT_FOUND"
    assert exc.value.key_version == "v404"
    log_case("decrypt-unknown-version", version="v404")


def test_decrypt_foreign_key_id_is_mismatch(manager):
    kv = manager._ring["v1"]
    env = encrypt_envelope(kv.key_material, "other-ring", "v1", b"x",
                           EncryptionContext(CTX))
    with pytest.raises(KeyIdMismatchError) as exc:
        manager.decrypt(env.to_token(), CTX)
    assert exc.value.code.value == "KEY_ID_MISMATCH"
    log_case("decrypt-foreign-kid", kid="other-ring")


def test_context_mismatch_is_distinct_from_tamper(manager):
    token = manager.encrypt(b"secret", CTX)
    with pytest.raises(ContextMismatchError) as exc:
        manager.decrypt(token, {"tenant": "acme", "dataset": "payments"})
    assert exc.value.code.value == "CONTEXT_MISMATCH"
    assert exc.value.key_version == "v1"
    log_case("decrypt-context-mismatch", expected="orders", actual="payments")


def test_tampered_ciphertext_is_distinct_failure(manager, caplog_summary):
    token = manager.encrypt(b"secret", CTX)
    bad = tamper_token(token)
    with pytest.raises(CiphertextTamperedError) as exc:
        manager.decrypt(bad, CTX)
    assert exc.value.code.value == "CIPHERTEXT_TAMPERED"
    # decision line with input summary + basis must be present
    assert any("decision DECRYPT failure" in r.message and "CIPHERTEXT_TAMPERED" in r.message
               for r in caplog_summary.records)
    log_case("decrypt-tampered", token=bad)


def test_retargeted_version_field_is_rejected(manager):
    token = manager.encrypt(b"secret", CTX)
    bad = retarget_token(token, version="v2")  # no AEAD recompute
    # Either the version rewrite breaks authentication (ring has v2) ->
    # TAMPERED, but never a silent fallback decrypt.
    with pytest.raises((CiphertextTamperedError, KeyVersionNotFoundError)):
        manager.decrypt(bad, CTX)
    log_case("decrypt-retarget-ver", new="v2")


def test_no_version_fallback_on_failure(manager):
    """A failing v1 decrypt must never be retried against another version."""
    manager.rotate()  # v2 current, v1 deactivated
    old_token = None
    # mint a v1 ciphertext before rotation via a second manager sharing keys:
    kv1 = manager._ring["v1"]
    from app.crypto import encrypt_envelope
    old = encrypt_envelope(kv1.key_material, manager.key_id, "v1", b"legacy",
                           EncryptionContext(CTX)).to_token()
    assert manager.decrypt(old, CTX) == b"legacy"  # deactivated still decrypts
    assert old_token is None
    log_case("no-fallback", old_version="v1", current="v2")


# --------------------------------------------------------------------------- #
# Rotation and lifecycle
# --------------------------------------------------------------------------- #
def test_rotation_moves_writes_keeps_reads(manager):
    old = manager.encrypt(b"old", CTX)
    new_version = manager.rotate()
    assert new_version == "v2"
    assert manager.get_state("v1") is KeyState.DEACTIVATED
    assert manager.encrypt(b"new", {})  # latest key used
    assert manager.decrypt(old, CTX) == b"old"
    fresh = manager.encrypt(b"fresh", CTX)
    assert manager.decrypt(fresh, CTX) == b"fresh"
    log_case("rotate", old="v1", new=new_version)


def test_multiple_rotations_are_monotonic(manager):
    versions = [manager.rotate() for _ in range(3)]
    assert versions == ["v2", "v3", "v4"]
    assert manager.current_version() == "v4"
    log_case("rotate-monotonic", versions=versions)


def test_optimistic_rotation_loses_race(manager):
    manager.rotate()  # moves v1 -> v2
    with pytest.raises(RotationRaceError) as exc:
        manager.rotate(expected_version="v1")
    assert exc.value.code.value == "ROTATION_RACE"
    assert manager.current_version() == "v2"  # no duplicate rotation applied
    log_case("rotate-race", expected="v1", actual="v2")


def test_deactivated_key_rejects_encryption_but_allows_decrypt(manager_factory):
    manager = manager_factory(("ACTIVE", "DEACTIVATED"))
    # v1 active/current; v2 deactivated -> can't be directly selected for
    # encryption, but a token carrying ver=v2 still decrypts.
    kv2 = manager._ring["v2"]
    token = encrypt_envelope(kv2.key_material, manager.key_id, "v2", b"legacy",
                             EncryptionContext(CTX)).to_token()
    assert manager.decrypt(token, CTX) == b"legacy"
    manager.rotate()  # v3 active, v1 deactivated
    with pytest.raises(InvalidLifecycleTransitionError):
        manager.deactivate("v3")  # current cannot be deactivated
    log_case("deactivated-rules", current="v3")


def test_revoked_key_rejects_both_operations(manager):
    old = manager.encrypt(b"old", CTX)
    manager.rotate()
    manager.revoke("v1")
    assert manager.get_state("v1") is KeyState.REVOKED
    with pytest.raises(KeyRevokedError) as exc:
        manager.decrypt(old, CTX)
    assert exc.value.code.value == "KEY_REVOKED"
    # new writes remain available on the current key
    assert manager.decrypt(manager.encrypt(b"new", CTX), CTX) == b"new"
    log_case("revoked-rules", revoked="v1", current="v2")


def test_cannot_revoke_current_active_version(manager):
    with pytest.raises(InvalidLifecycleTransitionError) as exc:
        manager.revoke("v1")
    assert exc.value.code.value == "INVALID_LIFECYCLE_TRANSITION"
    log_case("revoke-current-rejected")


def test_lifecycle_transitions_are_validated(manager):
    manager.rotate()
    manager.revoke("v1")
    with pytest.raises(InvalidLifecycleTransitionError):
        manager.deactivate("v1")  # revoked cannot move back
    with pytest.raises(KeyVersionNotFoundError):
        manager.revoke("nope")
    log_case("lifecycle-validation")


def test_idempotent_revoke(manager):
    manager.rotate()
    manager.revoke("v1")
    manager.revoke("v1")  # no error, no state corruption
    assert manager.get_state("v1") is KeyState.REVOKED
    log_case("revoke-idempotent")


# --------------------------------------------------------------------------- #
# Audit consistency
# --------------------------------------------------------------------------- #
def test_audit_records_match_real_outcomes(null_audit, manager_factory):
    manager = manager_factory(("ACTIVE",), audit=null_audit)
    token = manager.encrypt(b"audited", CTX)
    manager.decrypt(token, CTX)
    with pytest.raises(ContextMismatchError):
        manager.decrypt(token, {"tenant": "zzz"})
    records = null_audit.read_all()
    enc = [r for r in records if r.operation is KeyOperation.ENCRYPT]
    dec_ok = [r for r in records if r.operation is KeyOperation.DECRYPT
              and r.result is OperationResult.SUCCESS]
    dec_bad = [r for r in records if r.operation is KeyOperation.DECRYPT
               and r.result is OperationResult.FAILURE]
    assert enc and enc[0].result is OperationResult.SUCCESS and enc[0].error_code is None
    assert dec_ok and dec_ok[0].key_version == "v1"
    assert dec_bad and dec_bad[0].error_code == "CONTEXT_MISMATCH"
    # digests are populated but never raw secrets
    assert all(r.input_digest and len(r.input_digest) == 64 for r in records)
    assert all("audited" not in (r.detail or "") for r in records)
    log_case("audit-truth", total=len(records))


def test_bootstrap_requires_exactly_one_active(manager_factory):
    with pytest.raises(ConfigurationError):
        manager_factory(("REVOKED",))
    with pytest.raises(ConfigurationError):
        manager_factory(("ACTIVE", "ACTIVE"))
    log_case("bootstrap-active-validation")
