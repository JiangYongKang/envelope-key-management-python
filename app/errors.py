"""统一的错误分类。

所有面向调用方的失败都抛出 :class:`KMSError` 的子类，并携带稳定的
``code``，使各类入口（SDK、HTTP、测试）得到一致且可区分的失败原因。
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    """稳定的错误码，禁止在不更新文档的前提下改变其含义。"""

    CONFIG_INVALID = "CONFIG_INVALID"          # 配置缺失或不完整
    KEY_VERSION_NOT_FOUND = "KEY_VERSION_NOT_FOUND"  # 指定版本不存在，不回退
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"      # 加密/解密上下文不一致
    CIPHERTEXT_INVALID = "CIPHERTEXT_INVALID"  # 密文格式损坏或被篡改
    KEY_DISABLED = "KEY_DISABLED"              # 已停用密钥：禁止加解密
    KEY_REVOKED = "KEY_REVOKED"                # 已撤销密钥：禁止加密，解密同样拒绝
    ROTATION_CONFLICT = "ROTATION_CONFLICT"    # 并发轮换冲突（默认收敛，不对外暴露）
    AUDIT_FAILURE = "AUDIT_FAILURE"            # 审计写入失败
    KEY_SOURCE_FAILURE = "KEY_SOURCE_FAILURE"  # 本地密钥来源读取/写入失败
    KEY_STORE_EMPTY = "KEY_STORE_EMPTY"        # 密钥库中不存在任何版本


class KMSError(Exception):
    """所有业务错误的基类。"""

    code: ErrorCode = ErrorCode.CONFIG_INVALID

    def __init__(self, message: str, *, key_version: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.key_version = key_version

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "message": self.message,
            "key_version": self.key_version,
        }


class ConfigInvalidError(KMSError):
    code = ErrorCode.CONFIG_INVALID


class KeyVersionNotFoundError(KMSError):
    code = ErrorCode.KEY_VERSION_NOT_FOUND


class ContextMismatchError(KMSError):
    code = ErrorCode.CONTEXT_MISMATCH


class CiphertextInvalidError(KMSError):
    code = ErrorCode.CIPHERTEXT_INVALID


class KeyDisabledError(KMSError):
    code = ErrorCode.KEY_DISABLED


class KeyRevokedError(KMSError):
    code = ErrorCode.KEY_REVOKED


class RotationConflictError(KMSError):
    code = ErrorCode.ROTATION_CONFLICT


class AuditFailureError(KMSError):
    code = ErrorCode.AUDIT_FAILURE


class KeySourceFailureError(KMSError):
    code = ErrorCode.KEY_SOURCE_FAILURE


class KeyStoreEmptyError(KMSError):
    code = ErrorCode.KEY_STORE_EMPTY


def http_status_for(code: ErrorCode) -> int:
    """把错误码映射为稳定的 HTTP 状态码。"""
    mapping = {
        ErrorCode.CONFIG_INVALID: 500,
        ErrorCode.KEY_VERSION_NOT_FOUND: 404,
        ErrorCode.CONTEXT_MISMATCH: 409,
        ErrorCode.CIPHERTEXT_INVALID: 422,
        ErrorCode.KEY_DISABLED: 423,
        ErrorCode.KEY_REVOKED: 423,
        ErrorCode.ROTATION_CONFLICT: 409,
        ErrorCode.AUDIT_FAILURE: 500,
        ErrorCode.KEY_SOURCE_FAILURE: 500,
        ErrorCode.KEY_STORE_EMPTY: 503,
    }
    return mapping[code]
