"""配置与装配：配置缺失或不完整时显式拒绝启用，绝不使用隐式默认密钥。"""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.audit import Auditer, FileAuditSink
from app.errors import ConfigInvalidError
from app.file_source import FileKeySource
from app.keystore import InMemoryKeySource, KeySource
from app.manager import KeyManager


@dataclass(frozen=True)
class Settings:
    """服务运行配置。"""

    key_source: KeySource
    auditer: Auditer
    bootstrap: bool = False  # 仅在显式允许时，空库引导首个版本


def build_settings(
    *,
    key_file: str | None = None,
    audit_file: str | None = None,
    bootstrap: bool = False,
    in_memory: bool = False,
) -> Settings:
    """根据本地配置装配 :class:`Settings`。

    规则：
    - ``in_memory=True``：使用进程内空密钥来源（测试用途），通常配合
      ``bootstrap=True`` 或随后显式 :meth:`KeyManager.bootstrap`；
    - 指定 ``key_file``：使用本地 JSON 文件密钥来源；
    - 两者都没有：配置不完整，抛出 :class:`ConfigInvalidError`——服务拒绝
      启用，而不是悄悄使用默认密钥。
    """
    if in_memory:
        source: KeySource = InMemoryKeySource()
    elif key_file:
        source = FileKeySource(key_file)
    else:
        raise ConfigInvalidError(
            "未配置任何本地密钥来源：请设置 key_file 或显式使用 in_memory"
        )

    sink = FileAuditSink(audit_file) if audit_file else FileAuditSink(None)
    auditer = Auditer(sink)
    return Settings(key_source=source, auditer=auditer, bootstrap=bootstrap)


def build_settings_from_env() -> Settings:
    """从环境变量装配配置（本地运行入口）。

    - ``EKM_KEY_FILE``：本地密钥文件路径（必填，除非显式 ``EKM_IN_MEMORY=1``）；
    - ``EKM_AUDIT_FILE``：审计 JSON Lines 文件路径（建议必填；缺省时仅打日志）；
    - ``EKM_BOOTSTRAP``：``1`` 时允许在空库中引导首个密钥版本。

    缺少 ``EKM_KEY_FILE`` 且未声明内存模式时抛出 :class:`ConfigInvalidError`。
    """
    return build_settings(
        key_file=os.environ.get("EKM_KEY_FILE"),
        audit_file=os.environ.get("EKM_AUDIT_FILE"),
        bootstrap=os.environ.get("EKM_BOOTSTRAP", "") == "1",
        in_memory=os.environ.get("EKM_IN_MEMORY", "") == "1",
    )


def build_manager(settings: Settings) -> KeyManager:
    """按 Settings 创建并加载 Manager；空库且未显式允许引导时拒绝启动。"""
    manager = KeyManager(settings.key_source, settings.auditer)
    manager.load()
    if not manager.versions and settings.bootstrap:
        manager.bootstrap()
    return manager
