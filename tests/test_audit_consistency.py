"""审计落盘失败时：操作按失败处理，变更回滚，绝不“记成功却失败”或反之。"""

from __future__ import annotations

import pytest

from app.audit import AuditSink, Auditer
from app.errors import AuditFailureError
from app.keystore import InMemoryKeySource
from app.manager import KeyManager
from app.models import KeyStatus


class FailingAuditSink(AuditSink):
    """始终写入失败的审计落盘。"""

    def write(self, event) -> None:  # type: ignore[override]
        raise AuditFailureError("audit disk unavailable")


def _manager_with_failing_audit() -> KeyManager:
    manager = KeyManager(InMemoryKeySource(), Auditer(FailingAuditSink()))
    manager.load()
    manager.bootstrap()  # bootstrap 不经过审计通道
    return manager


def test_encrypt_fails_when_audit_write_fails():
    manager = _manager_with_failing_audit()
    with pytest.raises(AuditFailureError) as ei:
        manager.encrypt(b"secret", context={"k": "v"})
    assert ei.value.code.value == "AUDIT_FAILURE"
    # 密钥版本状态不受影响。
    assert manager.versions[1].status is KeyStatus.ENABLED


def test_rotate_rolls_back_when_audit_write_fails():
    manager = _manager_with_failing_audit()
    with pytest.raises(AuditFailureError):
        manager.rotate()
    # 轮换“未审计成功”即“未发生”：仍是单一版本 v1，无 v2 残留。
    assert sorted(manager.versions) == [1]
    assert manager.latest_version() == 1


def test_status_change_rolls_back_when_audit_write_fails():
    manager = _manager_with_failing_audit()
    with pytest.raises(AuditFailureError):
        manager.disable(1)
    # 回滚后 v1 仍为 enabled（内存与来源都没有留下 disabled 状态）。
    assert manager.versions[1].status is KeyStatus.ENABLED
    # 仍可正常加解密。
    # 注意：审计仍失败，故这里直接验证来源层状态，而非走 encrypt。
    assert manager._source.load()[1].status is KeyStatus.ENABLED


def test_successful_operation_with_working_sink_records_success(tmp_path):
    from app.audit import FileAuditSink
    from app.config import build_manager, build_settings

    manager = build_manager(
        build_settings(
            key_file=str(tmp_path / "k.json"),
            audit_file=str(tmp_path / "a.jsonl"),
            bootstrap=True,
        )
    )
    env = manager.encrypt(b"ok", context={"k": "v"})
    assert manager.decrypt(env, expected_context={"k": "v"}) == b"ok"

    import json
    records = [json.loads(x) for x in (tmp_path / "a.jsonl").read_text().splitlines()]
    assert [r["success"] for r in records] == [True, True]
    print("审计可用时成功操作如实记录 success=True")
