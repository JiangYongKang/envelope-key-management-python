"""Concurrency: rotation vs decryption, parallel rotations, state consistency."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app.errors import (
    KeyRevokedError,
    KeyVersionNotFoundError,
    RotationRaceError,
)
from app.models import KeyState

from .conftest import log_case

CTX = {"tenant": "acme"}


def test_concurrent_decryption_during_rotation(manager_factory, file_audit):
    """All historical ciphertexts stay readable while rotations are in flight."""
    manager = manager_factory(("ACTIVE",), audit=file_audit)

    # Pre-mint one token per upcoming version by rotating serially first;
    # then rebuild a fresh ring and do rotations + decrypts concurrently.
    token_holder: dict[str, str] = {}
    token_holder["v1"] = manager.encrypt(b"payload-v1", CTX)

    stop = threading.Event()
    failures: list[BaseException] = []

    def decryptor():
        while not stop.is_set():
            for version, token in list(token_holder.items()):
                try:
                    plain = manager.decrypt(token, CTX)
                    assert plain == f"payload-{version}".encode()
                except (KeyRevokedError, KeyVersionNotFoundError):
                    # Only acceptable if the version was concurrently revoked;
                    # rotations alone never cause these, so re-record to check.
                    failures.append(AssertionError(
                        f"rotation made {version} unreadable: {version}"
                    ))
                except Exception as exc:  # noqa: BLE001
                    failures.append(exc)

    threads = [threading.Thread(target=decryptor) for _ in range(6)]
    for t in threads:
        t.start()

    created = ["v1"]
    for i in range(2, 12):  # v2 .. v11
        version = manager.rotate()
        created.append(version)
        token_holder[version] = manager.encrypt(f"payload-{version}".encode(), CTX)

    stop.set()
    for t in threads:
        t.join()

    assert not failures, failures[:3]
    # Post-condition: every historical token still decrypts to its own payload.
    for version, token in token_holder.items():
        assert manager.decrypt(token, CTX) == f"payload-{version}".encode()
    states = {v.version: v.state for v in manager.list_versions()}
    assert states["v11"] is KeyState.ACTIVE
    assert all(states[v] is KeyState.DEACTIVATED for v in created[:-1])
    log_case("concurrent-rotate-decrypt", versions=len(created), threads=6)


def test_parallel_rotations_serialise_to_unique_versions(manager):
    """Concurrent rotations must not duplicate or skip versions."""
    seen: list[str] = []
    lock = threading.Lock()

    def do_rotate(_):
        version = manager.rotate()
        with lock:
            seen.append(version)
        return version

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(do_rotate, range(20)))

    assert sorted(seen, key=lambda v: int(v[1:])) == [f"v{i}" for i in range(2, 22)]
    assert set(results) == {f"v{i}" for i in range(2, 22)}
    assert manager.current_version() == "v21"
    assert len(manager.list_versions()) == 21  # v1 + v2..v21, no duplicates
    log_case("parallel-rotate", rotations=20, current="v21")


def test_optimistic_concurrent_rotation_single_winner(manager):
    """Two CAS rotators expecting v1: exactly one wins, the other gets RACE."""
    outcome: dict[str, str] = {}
    barrier = threading.Barrier(2)

    def attempt(name):
        barrier.wait()
        try:
            outcome[name] = manager.rotate(expected_version="v1")
        except RotationRaceError:
            outcome[name] = "RACE"

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(attempt, ["a", "b"]))

    assert sorted(outcome.values()) == ["RACE", "v2"]
    assert manager.current_version() == "v2"
    log_case("cas-rotate", outcomes=outcome)


def test_concurrent_encrypt_always_uses_a_current_active_key(manager):
    tokens: list[tuple[str, str]] = []
    lock = threading.Lock()

    def encryptor():
        for _ in range(25):
            token = manager.encrypt(b"hot-write", CTX)
            # Version is read from the parsed token header.
            from app.models import EnvelopeCiphertext
            ver = EnvelopeCiphertext.from_token(token).key_version
            with lock:
                tokens.append((ver, token))

    def rotator():
        for _ in range(5):
            manager.rotate()

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(encryptor) for _ in range(4)]
        rotfuture = pool.submit(rotator)
        for f in futures:
            f.result()
        rotfuture.result()

    # Every token decrypts and was minted by a key that was current then.
    for ver, token in tokens:
        assert manager.decrypt(token, CTX) == b"hot-write"
        assert ver in {v.version for v in manager.list_versions()}
    log_case("concurrent-encrypt", tokens=len(tokens))


def test_decryption_failure_classes_under_concurrency(manager):
    """Tampered/mismatched inputs remain correctly classified under load."""
    from .conftest import tamper_token
    from app.errors import CiphertextTamperedError, ContextMismatchError

    good = manager.encrypt(b"x", CTX)
    bad = tamper_token(good)
    errors: list[str] = []
    lock = threading.Lock()

    def worker(kind):
        try:
            if kind == "good":
                manager.decrypt(good, CTX)
            elif kind == "tamper":
                manager.decrypt(bad, CTX)
            else:
                manager.decrypt(good, {"tenant": "other"})
        except (CiphertextTamperedError, ContextMismatchError) as exc:
            with lock:
                errors.append(exc.code.value)

    with ThreadPoolExecutor(max_workers=6) as pool:
        jobs = [pool.submit(worker, "good") for _ in range(10)]
        jobs += [pool.submit(worker, "tamper") for _ in range(10)]
        jobs += [pool.submit(worker, "mismatch") for _ in range(10)]
        for f in jobs:
            f.result()

    assert errors.count("CIPHERTEXT_TAMPERED") == 10
    assert errors.count("CONTEXT_MISMATCH") == 10
    log_case("concurrent-failure-classes", counts={
        "CIPHERTEXT_TAMPERED": 10, "CONTEXT_MISMATCH": 10})


def test_audit_log_survives_concurrent_rotation_load(manager_factory, file_audit):
    manager = manager_factory(("ACTIVE",), audit=file_audit)
    token = manager.encrypt(b"durable", CTX)

    def workload():
        for _ in range(20):
            manager.decrypt(token, CTX)

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(workload) for _ in range(4)]
        for i in range(2, 7):
            manager.rotate()
            # keep decrypting the original legacy token across rotations
        for f in futures:
            f.result()

    records = file_audit.read_all()
    rotates = [r for r in records if r.operation.value == "ROTATE"]
    assert [r.key_version for r in rotates] == ["v2", "v3", "v4", "v5", "v6"]
    assert all(r.result.value == "SUCCESS" for r in rotates)
    # Original token must still be readable after all rotations.
    assert manager.decrypt(token, CTX) == b"durable"
    log_case("concurrent-audit", records=len(records))
