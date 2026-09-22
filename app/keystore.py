"""密钥来源与存储抽象（全部为本地，不依赖任何外部密钥服务）。"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Protocol

from app.errors import ConfigInvalidError
from app.models import KeyStatus, KeyVersion

#: KEK 长度固定为 32 字节（AES-256）。
KEK_SIZE = 32

#: 合法的生命周期迁移。REVOKED 为终态，不可恢复；
#: DISABLED 可重新 ENABLED，也可直接 REVOKED。
_ALLOWED_TRANSITIONS: dict[KeyStatus, frozenset[KeyStatus]] = {
    KeyStatus.ENABLED: frozenset({KeyStatus.DISABLED, KeyStatus.REVOKED}),
    KeyStatus.DISABLED: frozenset({KeyStatus.ENABLED, KeyStatus.REVOKED}),
    KeyStatus.REVOKED: frozenset(),
}


class KeySource(Protocol):
    """本地密钥来源协议：负责加载与（可选地）持久化密钥版本。"""

    def load(self) -> dict[int, KeyVersion]:
        """一次性加载全部密钥版本；无密钥时返回空字典。"""
        ...

    def save(self, versions: dict[int, KeyVersion]) -> None:
        """原子持久化全部版本；只读来源可抛出异常。"""
        ...


class InMemoryKeySource:
    """进程内密钥来源，用于测试与默认本地运行。"""

    def __init__(self, versions: dict[int, KeyVersion] | None = None) -> None:
        self._versions = dict(versions or {})

    def load(self) -> dict[int, KeyVersion]:
        # 返回拷贝，避免调用方绕过 save 直接改动来源。
        return dict(self._versions)

    def save(self, versions: dict[int, KeyVersion]) -> None:
        self._versions = dict(versions)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_version(version: int, created_at: str | None = None) -> KeyVersion:
    """在本地生成一个新的 ENABLED 密钥版本（材料仅来自本地 CSPRNG）。"""
    if version < 1:
        raise ConfigInvalidError(f"密钥版本号必须 >= 1，实际为 {version}")
    return KeyVersion(
        version=version,
        material=os.urandom(KEK_SIZE),
        status=KeyStatus.ENABLED,
        created_at=created_at or _utc_now_iso(),
    )


def next_version(existing: dict[int, KeyVersion]) -> int:
    """计算下一个版本号（单调递增，从 1 开始）。"""
    return (max(existing) + 1) if existing else 1


def transition(current: KeyStatus, target: KeyStatus) -> KeyStatus:
    """校验生命周期状态迁移是否合法；非法迁移抛出 ConfigInvalidError。

    相同状态不视为非法迁移（由上层做幂等处理）。
    """
    if current is target:
        return target
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise ConfigInvalidError(
            f"非法的密钥生命周期迁移: {current.value} -> {target.value}"
        )
    return target
