"""Batch migration (re-encryption to the current version).

Covers: upgrade without plaintext exchange, per-item failure classification,
no silent skipping / no blanket success, idempotent re-runs, revocation of the
source version, empty batches and audit truth per item.
"""

from __future__ import annotations

import pytest

from app.models import (
    EnvelopeCiphertext,
    KeyOperation,
    MigrationStatus,
    OperationResult,
)

from .conftest import log_case, tamper_token

CTX = {"tenant": "acme", "dataset": "orders"}


# --------------------------------------------------------------------------- #
# Happy path + plaintext never leaves the service
# --------------------------------------------------------------------------- #
def test_migrating_ciphertexts_upgrades_to_current_and_preserves_plaintext(manager):
    pairs = [(CTX if i % 2 else {}, f"secret-{i}".encode()) for i in range(4)]
    old_tokens = [manager.encrypt(plaintext, ctx) for ctx, plaintext in pairs]
    old_versions = {EnvelopeCiphertext.from_token(t).key_version for t in old_tokens}
    assert old_versions == {"v1"}

    new_version = manager.rotate()  # v2 current, v1 DEACTIVATED
    assert new_version == "v2"

    # Bare tokens: caller provides no plaintext and no context; the service
    # reuses the context bound inside each token.
    report = manager.migrate(old_tokens)

    log_case(
        "migrate-upgrade",
        target=report.target_version,
        total=report.total,
        reencrypted=report.reencrypted_count,
        inputs=[t[: 12] for t in old_tokens],
    )
    assert report.all_succeeded
    assert report.reencrypted_count == 4
    assert report.already_current_count == 0
    assert report.failed_count == 0
    for (ctx, plaintext), old, item in zip(pairs, old_tokens, report.results):
        assert item.status is MigrationStatus.REENCRYPTED
        assert item.source_version == "v1"
        assert item.target_version == "v2"
        assert item.ciphertext is not None and item.ciphertext != old
        assert EnvelopeCiphertext.from_token(item.ciphertext).key_version == "v2"
        # Upgraded token decrypts with the ORIGINAL context to the SAME bytes.
        assert manager.decrypt(item.ciphertext, ctx) == plaintext


def test_migrate_accepts_item_objects_with_context_and_item_id(manager):
    token = manager.encrypt(b"bound", CTX)
    manager.rotate()
    report = manager.migrate(
        [{"ciphertext": token, "context": CTX, "item_id": "record-77"}]
    )
    item = report.results[0]
    assert item.status is MigrationStatus.REENCRYPTED
    assert item.item_id == "record-77"
    assert manager.decrypt(item.ciphertext, CTX) == b"bound"
    log_case("migrate-item-object", item_id=item.item_id, source=item.source_version)


def test_migrate_never_returns_plaintext(manager):
    token = manager.encrypt(b"TOPSECRET-PAYLOAD", CTX)
    manager.rotate()
    report = manager.migrate([token])
    serialised = str(report.to_dict())
    assert "TOPSECRET-PAYLOAD" not in serialised
    assert report.results[0].ciphertext is not None
    log_case("migrate-no-plaintext", leaked=False)


def test_empty_batch_is_a_valid_noop(manager):
    manager.rotate()
    report = manager.migrate([])
    assert report.total == 0
    assert report.all_succeeded
    assert report.to_dict()["items"] == []
    log_case("migrate-empty", target=report.target_version)


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #
def test_migrating_twice_is_idempotent_and_explainable(manager):
    token = manager.encrypt(b"once", CTX)
    manager.rotate()
    first = manager.migrate([token])
    upgraded = first.results[0].ciphertext

    second = manager.migrate([upgraded])
    item = second.results[0]
    log_case(
        "migrate-idempotent",
        first=first.results[0].status.value,
        second=item.status.value,
    )
    assert first.results[0].status is MigrationStatus.REENCRYPTED
    assert item.status is MigrationStatus.ALREADY_CURRENT
    assert item.ciphertext == upgraded  # token returned unchanged
    assert manager.decrypt(item.ciphertext, CTX) == b"once"


def test_migrating_mixed_batch_repeat_leaves_good_items_untouched(manager):
    a = manager.encrypt(b"a", {})
    b = manager.encrypt(b"b", {})
    manager.rotate()
    report = manager.migrate([a, b])
    upgraded_a, upgraded_b = (r.ciphertext for r in report.results)

    again = manager.migrate([upgraded_a, b])  # one migrated, one still legacy
    statuses = [r.status for r in again.results]
    log_case("migrate-mixed-repeat", statuses=[s.value for s in statuses])
    assert statuses == [MigrationStatus.ALREADY_CURRENT, MigrationStatus.REENCRYPTED]


# --------------------------------------------------------------------------- #
# Per-item failure classification — no blanket success, nothing skipped
# --------------------------------------------------------------------------- #
def test_each_unmigratable_item_is_classified_individually(manager):
    from app.errors import ErrorCode
    from .conftest import retarget_token

    good = manager.encrypt(b"good", CTX)
    manager.rotate()  # v2 current
    # v1 is DEACTIVATED (still a valid migration source).

    foreign = retarget_token(good, kid="other-ring")
    unknown_ver = retarget_token(good, version="v404")
    tampered = tamper_token(good)
    wrong_ctx_item = {"ciphertext": good, "context": {"tenant": "someone-else"}}

    report = manager.migrate(
        [good, "not-a-token", foreign, unknown_ver, tampered, wrong_ctx_item]
    )
    by_status = {
        r.index: (r.status, r.error_code) for r in report.results
    }
    log_case(
        "migrate-failure-matrix",
        matrix={r.index: r.error_code for r in report.results},
        inputs=[good[:10], "not-a-token", foreign[:10], unknown_ver[:10],
                tampered[:10], "ctx-item"],
    )
    # Nothing is silently dropped: every index has a verdict.
    assert sorted(by_status) == [0, 1, 2, 3, 4, 5]
    # And nothing is falsely reported as success.
    assert report.all_succeeded is False
    assert report.failed_count == 5
    assert report.reencrypted_count == 1

    assert by_status[0] == (MigrationStatus.REENCRYPTED, None)
    assert by_status[1][1] == ErrorCode.CIPHERTEXT_INVALID.value
    assert by_status[2][1] == ErrorCode.KEY_ID_MISMATCH.value
    assert by_status[3][1] == ErrorCode.KEY_VERSION_NOT_FOUND.value
    assert by_status[4][1] == ErrorCode.CIPHERTEXT_TAMPERED.value
    assert by_status[5][1] == ErrorCode.CONTEXT_MISMATCH.value

    # Failed items return no new token; the successful one is readable.
    for i in (1, 2, 3, 4, 5):
        assert report.results[i].ciphertext is None
    assert manager.decrypt(report.results[0].ciphertext, CTX) == b"good"


def test_malformed_item_object_is_invalid_not_fatal(manager):
    manager.rotate()
    report = manager.migrate([{"no_ciphertext": 1}, 12345, None])
    log_case(
        "migrate-bad-items",
        codes=[r.error_code for r in report.results],
    )
    assert report.failed_count == 3
    assert all(r.error_code == "CIPHERTEXT_INVALID" for r in report.results)


def test_revoked_source_version_blocks_only_that_item(manager):
    old = manager.encrypt(b"legacy", CTX)
    other = manager.encrypt(b"other", CTX)
    manager.rotate()
    manager.revoke("v1")  # source v1 gone for good
    report = manager.migrate([old, other])
    log_case(
        "migrate-revoked-source",
        statuses=[r.status.value for r in report.results],
        codes=[r.error_code for r in report.results],
    )
    assert report.failed_count == 2  # both tokens lived on revoked v1
    assert all(r.error_code == "KEY_REVOKED" for r in report.results)
    assert all(r.ciphertext is None for r in report.results)


def test_migration_does_not_change_key_states(manager):
    token = manager.encrypt(b"x", CTX)
    manager.rotate()
    manager.migrate([token])
    states = {v.version: v.state for v in manager.list_versions()}
    assert states["v1"].value == "DEACTIVATED"
    assert states["v2"].value == "ACTIVE"
    log_case("migrate-states-unchanged", states={k: v.value for k, v in states.items()})


# --------------------------------------------------------------------------- #
# Audit: one truthful entry per item, digests only
# --------------------------------------------------------------------------- #
def test_migration_audit_entries_match_item_outcomes(null_audit, manager_factory):
    manager = manager_factory(("ACTIVE",), audit=null_audit)
    token = manager.encrypt(b"audited", CTX)
    manager.rotate()
    manager.migrate([token, "garbage"])

    records = [
        r for r in null_audit.read_all()
        if r.operation is KeyOperation.MIGRATE
    ]
    log_case("migrate-audit", records=len(records))
    assert len(records) == 2
    success = [r for r in records if r.result is OperationResult.SUCCESS]
    failure = [r for r in records if r.result is OperationResult.FAILURE]
    assert len(success) == 1 and success[0].key_version == "v2"
    assert len(failure) == 1 and failure[0].error_code == "CIPHERTEXT_INVALID"
    for r in records:
        assert r.input_digest and len(r.input_digest) == 64
        assert "audited" not in (r.detail or "")
