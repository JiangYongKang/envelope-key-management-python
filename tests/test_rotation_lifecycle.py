"""轮换、历史密文可读、停用/撤销规则与审计一致性。"""

from __future__ import annotations

import dataclasses

import pytest

from app.errors import (
    ConfigInvalidError,
    KeyDisabledError,
    KeyRevokedError,
    KeyStoreEmptyError,
    KeyVersionNotFoundError,
)

CONTEXT = {"tenant": "acme"}


def test_empty_store_refuses_with_default_key(manager_factory):
    mgr = manager_factory(bootstrap=False)
    with pytest.raises(KeyStoreEmptyError) as ei:
        mgr.encrypt(b"x", context={})
    assert ei.value.code.value == "KEY_STORE_EMPTY"
    print("空库且未引导 -> 判定 DENIED KEY_STORE_EMPTY（不使用默认密钥）")


def test_rotate_uses_latest_for_new_writes_but_keeps_history(manager):
    old_env = manager.encrypt(b"before-rotation", context=CONTEXT)
    assert old_env.key_version == 1

    new_kv = manager.rotate()
    assert new_kv.version == 2

    new_env = manager.encrypt(b"after-rotation", context=CONTEXT)
    assert new_env.key_version == 2
    assert manager.decrypt(new_env, expected_context=CONTEXT) == b"after-rotation"
    # 历史密文仍由其绑定的旧版本解密。
    assert manager.decrypt(old_env, expected_context=CONTEXT) == b"before-rotation"
    print("轮换后：新写走 v2，v1 历史密文仍可读")


def test_version_not_found_never_falls_back(manager):
    with pytest.raises(KeyVersionNotFoundError) as ei:
        manager.encrypt(b"x", context=CONTEXT, key_version=99)
    assert ei.value.key_version == 99
    print("指定不存在版本 99 -> DENIED KEY_VERSION_NOT_FOUND（不回退到最新版）")


def test_disabled_key_rejects_encrypt_and_decrypt(manager):
    envelope = manager.encrypt(b"data", context=CONTEXT)
    manager.disable(1)

    with pytest.raises(KeyDisabledError) as ei_enc:
        manager.encrypt(b"data", context=CONTEXT, key_version=1)
    assert ei_enc.value.code.value == "KEY_DISABLED"

    with pytest.raises(KeyDisabledError) as ei_dec:
        manager.decrypt(envelope, expected_context=CONTEXT)
    assert ei_dec.value.code.value == "KEY_DISABLED"
    print("已停用 v1：加密与解密均 DENIED KEY_DISABLED，判定可解释")

    # 重新启用后恢复。
    manager.enable(1)
    assert manager.decrypt(envelope, expected_context=CONTEXT) == b"data"


def test_revoked_key_is_terminal(manager):
    envelope = manager.encrypt(b"data", context=CONTEXT)
    manager.revoke(1)

    with pytest.raises(KeyRevokedError) as ei_enc:
        manager.encrypt(b"data", context=CONTEXT, key_version=1)
    assert ei_enc.value.code.value == "KEY_REVOKED"
    with pytest.raises(KeyRevokedError) as ei_dec:
        manager.decrypt(envelope, expected_context=CONTEXT)
    assert ei_dec.value.code.value == "KEY_REVOKED"

    with pytest.raises(ConfigInvalidError):
        manager.enable(1)
    with pytest.raises(ConfigInvalidError):
        manager.disable(1)
    print("已撤销 v1：加解密均 DENIED KEY_REVOKED，且撤销为终态")


def test_audit_matches_actual_outcome(manager, audit_records):
    envelope = manager.encrypt(b"audit-me", context=CONTEXT)
    manager.rotate()
    manager.revoke(1)

    # 实际失败的解密，必须有一条 success=False、错误码精确匹配的审计。
    with pytest.raises(KeyRevokedError):
        manager.decrypt(envelope, expected_context=CONTEXT)

    records = audit_records()
    ops = [(r["operation"], r["success"], r["error_code"]) for r in records]
    assert ("encrypt", True, None) in ops
    assert ("rotate", True, None) in ops
    denied = [r for r in records if not r["success"]]
    assert any(
        r["operation"] == "decrypt"
        and r["error_code"] == "KEY_REVOKED"
        and r["key_version"] == 1
        for r in denied
    )
    # 审计里只有摘要，没有明文本身。
    raw = open(manager._auditer.sink.path, encoding="utf-8").read()
    assert "audit-me" not in raw
    print("审计与实际结果一致：", ops)
