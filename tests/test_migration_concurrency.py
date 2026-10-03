"""Concurrency: migration vs rotation / revocation / duplicate batches."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import KeyState, MigrationStatus

from .conftest import log_case

CTX = {"tenant": "acme"}


def _mint_batch(manager, count, tag):
    return [manager.encrypt(f"{tag}-{i}".encode(), CTX) for i in range(count)]


def test_concurrent_migration_of_same_batch(manager_factory, file_audit):
    """Many workers migrate the same tokens: every reported token decrypts
    to the original plaintext; no item is lost or corrupted."""
    manager = manager_factory(("ACTIVE",), audit=file_audit)
    tokens = _mint_batch(manager, 20, "dup")
    manager.rotate()  # v2 current; all tokens on v1

    def worker(_):
        return manager.migrate(tokens)

    with ThreadPoolExecutor(max_workers=8) as pool:
        reports = list(pool.map(worker, range(8)))

    for report in reports:
        assert report.total == 20 and report.failed == 0
        for i, item in enumerate(report.items):
            assert item.status in (MigrationStatus.MIGRATED,
                                   MigrationStatus.ALREADY_CURRENT)
            assert manager.decrypt(item.ciphertext, CTX) == f"dup-{i}".encode()
    log_case("conc-migrate-same-batch", workers=8, batch=20)


def test_migration_during_rotation_never_yields_unreadable_token(manager_factory,
                                                                 file_audit):
    manager = manager_factory(("ACTIVE",), audit=file_audit)
    tokens = _mint_batch(manager, 40, "rot")
    failures: list[BaseException] = []
    stop = threading.Event()

    def rotator():
        while not stop.is_set():
            manager.rotate()

    def migrator():
        while not stop.is_set():
            report = manager.migrate(tokens)
            for i, item in enumerate(report.items):
                if item.status is MigrationStatus.FAILED:
                    failures.append(AssertionError(
                        f"migration failed during rotation: {item.error_code}"))
                    continue
                try:
                    assert manager.decrypt(item.ciphertext, CTX) == f"rot-{i}".encode()
                except Exception as exc:  # noqa: BLE001
                    failures.append(exc)

    threads = [threading.Thread(target=rotator)]
    threads += [threading.Thread(target=migrator) for _ in range(4)]
    for t in threads:
        t.start()
    threading.Event().wait(1.5)
    stop.set()
    for t in threads:
        t.join()

    assert not failures, failures[:3]
    # Every target version ever handed out still exists and decrypts.
    final_report = manager.migrate(tokens)
    assert final_report.failed == 0
    ring_versions = {v.version for v in manager.list_versions()}
    for item in final_report.items:
        assert item.target_version in ring_versions
    log_case("conc-migrate-rotate", versions=len(ring_versions))


def test_migration_concurrent_with_revoke_is_classified(manager_factory, file_audit):
    """Revoking the source version mid-migration: items either completed
    before the revoke (token decrypts) or fail with KEY_REVOKED — never a
    'successful' token that cannot be decrypted."""
    manager = manager_factory(("ACTIVE",), audit=file_audit)
    tokens = _mint_batch(manager, 30, "rev")
    manager.rotate()  # v2 current, v1 deactivated
    outcomes: list[str] = []
    lock = threading.Lock()

    def migrator():
        report = manager.migrate(tokens)
        with lock:
            for item in report.items:
                if item.status is MigrationStatus.FAILED:
                    outcomes.append(item.error_code)
                else:
                    # Any token reported as a success MUST decrypt.
                    manager.decrypt(item.ciphertext, CTX)
                    outcomes.append("OK")

    def revoker():
        manager.revoke("v1")

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(migrator) for _ in range(4)]
        futures.append(pool.submit(revoker))
        for f in futures:
            f.result()

    assert manager.get_state("v1") is KeyState.REVOKED
    assert outcomes  # something happened
    assert set(outcomes) <= {"OK", "KEY_REVOKED"}
    # After the revoke, migration of v1 tokens fails cleanly and explicitly.
    report = manager.migrate(tokens)
    assert report.failed == len(tokens)
    assert all(i.error_code == "KEY_REVOKED" for i in report.items)
    log_case("conc-migrate-revoke", ok=outcomes.count("OK"),
             revoked=outcomes.count("KEY_REVOKED"))


def test_duplicate_batch_migration_is_idempotent_under_concurrency(manager_factory):
    """Re-running the same migration twice (even concurrently) is a no-op
    the second time and every result is explainable."""
    manager = manager_factory(("ACTIVE",))
    tokens = _mint_batch(manager, 15, "idem")
    manager.rotate()

    first = manager.migrate(tokens)
    assert first.migrated == 15
    migrated_tokens = [i.ciphertext for i in first.items]

    def worker(_):
        return manager.migrate(migrated_tokens)

    with ThreadPoolExecutor(max_workers=6) as pool:
        reports = list(pool.map(worker, range(6)))

    for report in reports:
        assert report.failed == 0
        assert report.migrated == 0
        assert report.already_current == 15
        for i, item in enumerate(report.items):
            assert item.ciphertext == migrated_tokens[i]
            assert manager.decrypt(item.ciphertext, CTX) == f"idem-{i}".encode()
    log_case("conc-migrate-idempotent", workers=6)


def test_migration_during_encrypt_decrypt_load(manager_factory, file_audit):
    """Mixed workload: encrypt + decrypt + migrate concurrently; nothing
    becomes unreadable and versions stay consistent."""
    manager = manager_factory(("ACTIVE",), audit=file_audit)
    old_tokens = _mint_batch(manager, 10, "mix")
    manager.rotate()
    errors: list[BaseException] = []
    stop = threading.Event()

    def encryptor():
        while not stop.is_set():
            try:
                token = manager.encrypt(b"hot", CTX)
                assert manager.decrypt(token, CTX) == b"hot"
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def migrator():
        while not stop.is_set():
            try:
                report = manager.migrate(old_tokens)
                for i, item in enumerate(report.items):
                    if item.status is not MigrationStatus.FAILED:
                        assert manager.decrypt(item.ciphertext, CTX) == f"mix-{i}".encode()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def rotator():
        while not stop.is_set():
            manager.rotate()

    threads = ([threading.Thread(target=encryptor) for _ in range(3)]
               + [threading.Thread(target=migrator) for _ in range(2)]
               + [threading.Thread(target=rotator)])
    for t in threads:
        t.start()
    threading.Event().wait(1.5)
    stop.set()
    for t in threads:
        t.join()

    assert not errors, errors[:3]
    currents = [v for v in manager.list_versions() if v.is_current]
    assert len(currents) == 1 and currents[0].state is KeyState.ACTIVE
    log_case("conc-mixed-workload", versions=len(manager.list_versions()))
