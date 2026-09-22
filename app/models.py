"""领域模型：密钥版本、信封密文、审计事件。"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

#: 当前信封密文格式版本，便于未来演进。
ENVELOPE_FORMAT_VERSION = 1


class KeyStatus(str, Enum):
    """密钥生命周期状态。

    - ENABLED: 正常可用，可加密、可解密；
    - DISABLED: 已停用，禁止加密与解密（保留密钥材料，可重新启用）；
    - REVOKED: 已撤销，永久失效，加密与解密一律拒绝。
    """

    ENABLED = "enabled"
    DISABLED = "disabled"
    REVOKED = "revoked"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d_raw(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


@dataclass(frozen=True)
class KeyVersion:
    """一个密钥版本及其状态。"""

    version: int
    material: bytes          # 32 字节 KEK 原始材料，仅存在于本地
    status: KeyStatus
    created_at: str          # ISO-8601 UTC 时间戳

    def is_usable_for_encrypt(self) -> bool:
        return self.status is KeyStatus.ENABLED

    def is_usable_for_decrypt(self) -> bool:
        # 已停用与已撤销均不可用于解密，绝不回退。
        return self.status is KeyStatus.ENABLED


@dataclass(frozen=True)
class Envelope:
    """信封密文，密文自描述其所属密钥版本与绑定的上下文。"""

    key_version: int
    context: dict[str, str]
    iv: bytes                # 明文加密所用随机 IV
    wrap_iv: bytes           # KEK 包装 DEK 所用随机 IV
    encrypted_dek: bytes     # KEK 加密后的 DEK（含 GCM 标签）
    ciphertext: bytes
    tag: bytes
    format_version: int = ENVELOPE_FORMAT_VERSION

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "key_version": self.key_version,
            "context": self.context,
            "iv": b64e(self.iv),
            "wrap_iv": b64e(self.wrap_iv),
            "encrypted_dek": b64e(self.encrypted_dek),
            "ciphertext": b64e(self.ciphertext),
            "tag": b64e(self.tag),
        }

    @classmethod
    def from_json(cls, text: str) -> "Envelope":
        return cls.from_dict(json.loads(text))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Envelope":
        try:
            return cls(
                format_version=int(data["format_version"]),
                key_version=int(data["key_version"]),
                context={str(k): str(v) for k, v in dict(data["context"]).items()},
                iv=b64d_raw(str(data["iv"])),
                wrap_iv=b64d_raw(str(data["wrap_iv"])),
                encrypted_dek=b64d_raw(str(data["encrypted_dek"])),
                ciphertext=b64d_raw(str(data["ciphertext"])),
                tag=b64d_raw(str(data["tag"])),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            # 延迟导入以避免骨架阶段的循环依赖；错误模块无依赖。
            from app.errors import CiphertextInvalidError

            raise CiphertextInvalidError(f"密文格式损坏: {exc}") from exc


@dataclass(frozen=True)
class AuditEvent:
    """一次密钥操作的审计记录。"""

    timestamp: str
    operation: str                       # encrypt / decrypt / rotate / disable / revoke / enable
    success: bool
    key_version: int | None
    context_hash: str | None = None      # 上下文的短摘要（不含明文）
    plaintext_hash: str | None = None    # 明文摘要（仅用于测试可解释性）
    error_code: str | None = None
    detail: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "operation": self.operation,
            "success": self.success,
            "key_version": self.key_version,
            "context_hash": self.context_hash,
            "plaintext_hash": self.plaintext_hash,
            "error_code": self.error_code,
            "detail": self.detail,
            "extra": self.extra,
        }

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)
