"""Concurrency: migration vs rotation/revoke, parallel migrations, no unreadable
ciphertexts, no double-migration, version-state sanity under mixed workloads."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import (
    EnvelopeCiphertext,
    KeyState,
    MigrationStatus,
)

from .conftest import log_case

CTX = {"tenant": "acme"}


def _version_of(token: str) -> str:
    return EnvelopeCiphertext.from_token(token).key_version


# --------------------------------------------------------------------------- #
# Deterministic narrow-window races via the pre-commit hook
# --------------------------------------------------------------------------- #
def test_migration_fails_when_target_is_rotated_in_commit_window(manager):
    """A rotation landing between re-encrypt and commit must fail the item.

    The token was sealed under v2, which the rotation leaves DEACTIVATED
    (decrypt-only), so returning it would hand back a token that cannot serve
    new encryption and was never the committed migration result: reported as
    KEY_DEACTIVATED with no token emitted.
    """
    token = manager.encrypt(b"racing", CTX)
    manager.rotate()  # migration target starts as v2

    def hook(index, source, target):
        manager.rotate()  # v3 becomes current; v2 deactivated

    manager.migrate_pre_commit_hook = hook
    report = manager.migrate([token])
    item = report.results[0]
    log_case(
        "migrate-race-rotate",
        status=item.status.value, code=item.error_code, target=item.target_version,
    )
    assert item.status is MigrationStatus.FAILED
    assert item.error_code == "KEY_DEACTIVATED"
    assert item.ciphertext is None
    # No unreadable token was handed out; current is v3 and original survives.
    assert manager.current_version() == "v3"
    assert manager.decrypt(token, CTX) == b"racing"


def test_migration_fails_when_target_is_revoked_in_commit_window(manager):
    """Revoke of the target right before commit -> clear KEY_REVOKED failure."""
    token = manager.encrypt(b"racing", CTX)
    v2 = manager.rotate()

    def hook(index, source, target):
        manager.rotate()        # v3 current so v2 becomes revocable
        manager.revoke(target)  # revoke v2, the migration target

    manager.migrate_pre_commit_hook = hook
    report = manager.migrate([token])
    item = report.results[0]
    log_case(
        "migrate-race-revoke",
        status=item.status.value, code=item.error_code, target=item.target_version,
    )
    assert item.status is MigrationStatus.FAILED
    assert item.error_code == "KEY_REVOKED"
    assert item.target_version == "v2"
    assert item.ciphertext is None
    # We must never have emitted a token sealed by now-revoked v2.
    assert manager.get_state("v2") is KeyState.REVOKED


def test_migration_fails_when_target_is_deactivated_in_commit_window(manager):
    """Deactivate of target (via rotation) is classified distinctly."""
    token = manager.encrypt(b"racing", CTX)
    manager.rotate()  # v2

    def hook(index, source, target):
        manager.rotate()  # v3 current, v2 deactivated (not revoked)

    manager.migrate_pre_commit_hook = hook
    report = manager.migrate([token])
    item = report.results[0]
    log_case(
        "migrate-race-deactivate",
        status=item.status.value, code=item.error_code,
    )
    # current moved to v3 and v2 (the sealed key) is DEACTIVATED -> distinct
    # KEY_DEACTIVATED classification, not a blanket race or a readable token.
    assert item.status is MigrationStatus.FAILED
    assert item.error_code == "KEY_DEACTIVATED"
    assert item.ciphertext is None
    assert manager.get_state("v2") is KeyState.DEACTIVATED


# --------------------------------------------------------------------------- #
# Real-thread workloads
# --------------------------------------------------------------------------- #
def test_concurrent_migrations_never_emit_unreadable_tokens(manager):
    """Many threads migrate the same legacy batch while rotations happen.

    Every successful item must decrypt; a failure must be an explainable
    target/source lifecycle reason, never a silently broken ciphertext.
    """
    tokens = [manager.encrypt(f"payload-{i}".encode(), CTX) for i in range(20)]
    manager.rotate()  # v2

    upgraded: list[str] = []
    failures: list[str] = []
    lock = threading.Lock()

    def migrate_worker():
        report = manager.migrate(list(tokens))
        with lock:
            for r in report.results:
                if r.ciphertext is not None:
                    upgraded.append(r.ciphertext)
                else:
                    failures.append(r.error_code or "?")

    def rotate_worker():
        for _ in range(3):
            manager.rotate()

    with ThreadPoolExecutor(max_workers=8) as pool:
        migrators = [pool.submit(migrate_worker) for _ in range(6)]
        rotator = pool.submit(rotate_worker)
        for f in migrators:
            f.result()
        rotator.result()

    log_case(
        "concurrent-migrate-rotate",
        upgraded=len(upgraded), failures=len(failures),
        failure_codes=sorted(set(failures)),
        current=manager.current_version(),
    )
    # Every token returned as success decrypts under a live, usable version.
    for tok in upgraded:
        assert manager.decrypt(tok, CTX).startswith(b"payload-")
    # No failure classification outside the expected concurrency set.
    assert set(failures) <= {"ROTATION_RACE", "KEY_REVOKED", "KEY_DEACTIVATED"}
    # Nothing revoked in this test, so those classes should not appear.
    assert "KEY_REVOKED" not in failures


def test_repeated_concurrent_migration_is_idempotent(manager):
    """Re-running migration over migrated output is stable and explainable.

    The batch is migrated many times concurrently and then *chained*: each
    round migrates the previous round's output. Once on the current version,
    every subsequent outcome is ALREADY_CURRENT and the token is byte-identical
    — no double re-encryption, no drift.
    """
    tokens = [manager.encrypt(f"d-{i}".encode(), CTX) for i in range(10)]
    manager.rotate()  # v2

    # Round 0: many threads migrate the original legacy batch at once.
    first_reports: list = []
    lock = threading.Lock()

    def first_wave():
        report = manager.migrate(list(tokens))
        with lock:
            first_reports.append(report)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: first_wave(), range(8)))

    # Pick one consistent set of upgraded tokens from a single report.
    upgraded_tokens = [
        r.ciphertext for r in first_reports[0].results
    ]
    assert all(t is not None for t in upgraded_tokens)

    # Round 1+: chained concurrent re-migration of already-current tokens.
    current_tokens: list[str] = upgraded_tokens  # type: ignore[assignment]
    round_statuses = []
    for round_no in range(3):
        wave: list = []

        def re_wave(batch=list(current_tokens)):
            wave.append(manager.migrate(batch))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: re_wave(), range(6)))
        statuses = [r.status for report in wave for r in report.results]
        round_statuses.append(statuses)
        current_tokens = [
            r.ciphertext for r in wave[0].results
        ]

    flat = [s for statuses in round_statuses for s in statuses]
    log_case(
        "concurrent-migrate-idempotent",
        first_wave_runs=len(first_reports),
        first_wave_failed=sum(r.failed_count for r in first_reports),
        chained_statuses={s.value: flat.count(s) for s in set(flat)},
    )
    assert sum(r.failed_count for r in first_reports) == 0
    assert flat and all(s is MigrationStatus.ALREADY_CURRENT for s in flat)
    # Tokens returned by every later report are byte-identical (no churn).
    assert current_tokens == upgraded_tokens
    # Original plaintext still verifies through the migrated tokens.
    for i, tok in enumerate(current_tokens):
        assert manager.decrypt(tok, CTX) == f"d-{i}".encode()


def test_mixed_encrypt_decrypt_migrate_rotate_stays_consistent(manager):
    """No version-state corruption and no unreadable token under mixed load."""
    legacy = [manager.encrypt(f"old-{i}".encode(), CTX) for i in range(10)]
    manager.rotate()

    produced: list[str] = []
    lock = threading.Lock()
    errors: list[str] = []

    def encryptor():
        for _ in range(30):
            tok = manager.encrypt(b"hot", CTX)
            with lock:
                produced.append(tok)

    def migrator():
        report = manager.migrate(list(legacy))
        with lock:
            for r in report.results:
                if r.ciphertext is not None:
                    produced.append(r.ciphertext)
                elif r.error_code not in ("ROTATION_RACE", "KEY_DEACTIVATED"):
                    errors.append(r.error_code or "?")

    def rotator():
        for _ in range(4):
            manager.rotate()

    def decryptor():
        for _ in range(30):
            with lock:
                candidates = list(produced)
            if candidates:
                tok = candidates[len(candidates) // 2]
                try:
                    assert manager.decrypt(tok, CTX) in (b"hot",) or \
                        manager.decrypt(tok, CTX).startswith(b"old-")
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc.__class__.__name__)

    with ThreadPoolExecutor(max_workers=10) as pool:
        jobs = [pool.submit(encryptor) for _ in range(3)]
        jobs += [pool.submit(migrator) for _ in range(2)]
        jobs += [pool.submit(rotator)]
        jobs += [pool.submit(decryptor) for _ in range(3)]
        for f in jobs:
            f.result()

    states = {v.version: v.state for v in manager.list_versions()}
    active = [v for v, s in states.items() if s is KeyState.ACTIVE]
    log_case(
        "mixed-workload",
        tokens=len(produced), errors=errors,
        current=manager.current_version(), active=active,
    )
    assert active == [manager.current_version()]  # exactly one ACTIVE
    assert errors == []


def test_migration_after_revoke_of_old_version_reports_per_item(manager):
    """Concurrent-style scenario: source revoked mid-lifecycle, items explained."""
    a = manager.encrypt(b"a", CTX)
    b = manager.encrypt(b"b", CTX)
    manager.rotate()  # v2
    manager.revoke("v1")
    report = manager.migrate([a, b])
    log_case(
        "migrate-source-revoked-batch",
        codes=[r.error_code for r in report.results],
    )
    assert report.failed_count == 2
    assert all(r.error_code == "KEY_REVOKED" for r in report.results)
    # New writes and current-version operations unaffected.
    assert manager.decrypt(manager.encrypt(b"new", CTX), CTX) == b"new"
