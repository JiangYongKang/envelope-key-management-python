"""本地密钥来源与配置完整性：缺失/不完整配置必须拒绝启用。"""

from __future__ import annotations

import json

import pytest

from app.config import build_manager, build_settings
from app.errors import ConfigInvalidError, KeySourceFailureError
from app.file_source import FileKeySource
from app.keystore import generate_version


def test_missing_key_source_config_refuses():
    with pytest.raises(ConfigInvalidError) as ei:
        build_settings()  # 既无 key_file 也未声明 in_memory
    assert ei.value.code.value == "CONFIG_INVALID"
    print("未配置本地密钥来源 -> DENIED CONFIG_INVALID（不使用默认密钥）")


def test_persistence_roundtrip_across_restart(tmp_path):
    key_file = tmp_path / "keys.json"
    settings = build_settings(
        key_file=str(key_file),
        audit_file=str(tmp_path / "audit.jsonl"),
        bootstrap=True,
    )
    manager = build_manager(settings)
    envelope = manager.encrypt(b"persisted", context={"t": "1"})
    manager.rotate()

    # 模拟进程重启：从同一本地文件重新加载。
    manager2 = build_manager(settings)
    assert manager2.latest_version() == 2
    assert manager2.decrypt(envelope, expected_context={"t": "1"}) == b"persisted"
    print("重启后本地密钥与历史密文均可用")


def test_broken_key_file_is_rejected(tmp_path):
    key_file = tmp_path / "keys.json"
    key_file.write_text("{not-json", encoding="utf-8")
    with pytest.raises(KeySourceFailureError):
        FileKeySource(key_file).load()
    print("密钥文件损坏 -> DENIED KEY_SOURCE_FAILURE")


@pytest.mark.parametrize(
    "payload",
    [
        {"nope": []},
        {"versions": [{"version": 1, "status": "enabled", "created_at": "t"}]},  # 缺 material
        {"versions": [
            {"version": 1, "material": "AAAA", "status": "enabled", "created_at": "t"}
        ]},  # material 长度错
        {"versions": [
            {
                "version": 2,
                "material": __import__("base64").b64encode(b"k" * 32).decode(),
                "status": "enabled",
                "created_at": "t",
            }
        ]},  # 版本不从 1 起
    ],
)
def test_incomplete_or_invalid_config_rejected(tmp_path, payload):
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises((ConfigInvalidError, KeySourceFailureError)):
        build_manager(build_settings(key_file=str(key_file)))
    print("不完整/非法密钥配置 -> 拒绝启用")


def test_non_contiguous_versions_rejected(tmp_path):
    key_file = tmp_path / "keys.json"
    source = FileKeySource(key_file)
    source.save({1: generate_version(1), 3: generate_version(3)})  # 缺 v2
    with pytest.raises(ConfigInvalidError):
        build_manager(build_settings(key_file=str(key_file)))
    print("版本序列不连续 -> DENIED CONFIG_INVALID")
