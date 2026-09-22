"""轮换与解密并发：数据可读、无重复轮换、状态不错乱。"""

from __future__ import annotations

import threading

from app.config import build_settings, build_manager


def test_concurrent_decrypt_during_rotation_all_succeed(tmp_path):
    settings = build_settings(
        key_file=str(tmp_path / "k.json"),
        audit_file=str(tmp_path / "a.jsonl"),
        bootstrap=True,
    )
    manager = build_manager(settings)

    # 先各自产生密文（不同明文，相同上下文）。
    envelopes = [
        manager.encrypt(f"payload-{i}".encode(), context={"job": "nightly"})
        for i in range(20)
    ]
    old = manager.encrypt(b"history", context={"job": "nightly"})

    n_workers = 20
    n_rotators = 3
    start = threading.Barrier(n_workers + n_rotators + 1)  # 含主线程
    errors: list[tuple[str, str]] = []
    oks: list[int] = []
    rotated: list[int] = []

    def decrypt_worker(i: int) -> None:
        start.wait()
        try:
            out = manager.decrypt(envelopes[i], expected_context={"job": "nightly"})
            assert out == f"payload-{i}".encode()
            oks.append(i)
        except Exception as exc:  # noqa: BLE001
            errors.append((f"decrypt-{i}", type(exc).__name__))

    def rotate_worker() -> None:
        start.wait()
        try:
            rotated.append(manager.rotate().version)
        except Exception as exc:  # noqa: BLE001
            errors.append(("rotate", type(exc).__name__))

    threads = [
        *[threading.Thread(target=decrypt_worker, args=(i,)) for i in range(n_workers)],
        *[threading.Thread(target=rotate_worker) for _ in range(n_rotators)],
    ]
    for t in threads:
        t.start()

    # 最后一票由主线程投下，所有线程同一时刻放行。
    start.wait()
    for t in threads:
        t.join()

    assert errors == [], f"轮换期间存在不可读数据: {errors}"
    assert len(oks) == 20
    # 3 个轮换同时发起：必须收敛为同一次轮换（不产生重复/错乱版本）。
    assert sorted(set(rotated)) == [2], rotated
    assert manager.latest_version() == 2
    # 历史密文始终可由其绑定版本解密，绝不因轮换丢失。
    assert manager.decrypt(old, expected_context={"job": "nightly"}) == b"history"
    # 并发窗口结束后再串行轮换，版本继续单调递增。
    assert manager.rotate().version == 3
    print("轮换期间 20 路并发解密全部 SUCCESS，3 路同时轮换收敛为 v2，历史密文可读")


def test_simultaneous_rotation_coalesces_to_single_version(tmp_path):
    settings = build_settings(
        in_memory=True,
        audit_file=str(tmp_path / "a.jsonl"),
        bootstrap=True,
    )
    manager = build_manager(settings)

    n = 16
    begin = threading.Barrier(n)
    results: list[int] = []
    errors: list[str] = []

    def rotate_worker() -> None:
        begin.wait()
        try:
            results.append(manager.rotate().version)
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)

    threads = [threading.Thread(target=rotate_worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert results == [2] * n, f"并发轮换未收敛: {results}"
    assert manager.latest_version() == 2

    # 轮换之后再串行调用，应正常产生 v3（收敛机制不影响后续轮换）。
    assert manager.rotate().version == 3
    print(f"{n} 路同时轮换全部收敛到 v2，后续串行轮换得到 v3（无重复轮换）")


def test_decrypt_uses_bound_version_under_rotation(tmp_path):
    """即使最新版本变化，解密严格使用密文绑定版本，结果稳定。"""
    settings = build_settings(
        in_memory=True,
        audit_file=str(tmp_path / "a.jsonl"),
        bootstrap=True,
    )
    manager = build_manager(settings)
    env_v1 = manager.encrypt(b"v1-data", context={"k": "v"})

    manager.rotate()
    env_v2 = manager.encrypt(b"v2-data", context={"k": "v"})
    manager.rotate()
    env_v3 = manager.encrypt(b"v3-data", context={"k": "v"})

    assert env_v1.key_version == 1
    assert env_v2.key_version == 2
    assert env_v3.key_version == 3
    assert manager.decrypt(env_v1, expected_context={"k": "v"}) == b"v1-data"
    assert manager.decrypt(env_v2, expected_context={"k": "v"}) == b"v2-data"
    assert manager.decrypt(env_v3, expected_context={"k": "v"}) == b"v3-data"
    print("多版本并存：每份密文按其绑定版本解密，互不串扰")
