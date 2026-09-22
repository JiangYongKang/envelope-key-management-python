"""纯密码学原语：信封加密（DEK + KEK 两层结构）与摘要。

本模块不持有任何状态，也不访问密钥来源；由上层 Manager 负责选版本、
查状态、绑定上下文与审计。

密文结构（自描述）::

    明文 --AES-256-GCM(随机 DEK, IV, AAD)--> 密文 + tag
    DEK  --AES-256-GCM(KEK[v], wrapIV, AAD)--> encrypted_dek（内含 GCM tag）

AAD 在两处均为::

    b"ekm-v1|" + format_version + b"|" + key_version + b"|" + 规范化上下文

因此：换密钥版本、改上下文、改任一字段都会在认证阶段失败，且不存在
“换个 KEK 也能解开”的回退路径。
"""

from __future__ import annotations

import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.errors import (
    CiphertextInvalidError,
    ContextMismatchError,
)
from app.models import ENVELOPE_FORMAT_VERSION, Envelope

_AAD_PREFIX = b"ekm-v1"


def digest(data: bytes) -> str:
    """返回数据的短摘要（SHA-256 前 16 字节的十六进制），用于日志可解释性。"""
    return hashlib.sha256(data).hexdigest()[:32]


def digest_context(context: dict[str, str]) -> str:
    """对上下文做规范化摘要，保证键序不影响结果。"""
    return digest(_canonical_context(context))


def random_dek() -> bytes:
    """生成 32 字节随机数据加密密钥（DEK）。"""
    return os.urandom(32)


def _canonical_context(context: dict[str, str]) -> bytes:
    # sort_keys 保证同一逻辑上下文序列化结果逐字节一致。
    return json.dumps(
        context, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _aad(envelope: Envelope, context: dict[str, str]) -> bytes:
    return b"|".join(
        (
            _AAD_PREFIX,
            str(envelope.format_version).encode("ascii"),
            str(envelope.key_version).encode("ascii"),
            _canonical_context(context),
        )
    )


def seal(plaintext: bytes, *, kek: bytes, key_version: int,
         context: dict[str, str]) -> Envelope:
    """信封加密：随机 DEK 加密明文，KEK 包装 DEK；上下文经 AAD 绑定。"""
    if len(kek) != 32:
        raise CiphertextInvalidError("KEK 长度必须为 32 字节（AES-256）")

    dek = random_dek()
    iv = os.urandom(12)
    wrap_iv = os.urandom(12)

    data_aead = AESGCM(dek)
    envelope = Envelope(
        key_version=key_version,
        context=dict(context),
        iv=iv,
        wrap_iv=wrap_iv,
        encrypted_dek=b"",
        ciphertext=b"",
        tag=b"",
    )
    aad = _aad(envelope, context)

    # 明文层：AES-GCM 输出 密文||tag，这里拆开存储以便自描述。
    sealed = data_aead.encrypt(iv, plaintext, aad)
    ciphertext, tag = sealed[:-16], sealed[-16:]

    # KEK 层：包装 DEK。
    encrypted_dek = AESGCM(kek).encrypt(wrap_iv, dek, aad)

    return Envelope(
        key_version=key_version,
        context=dict(context),
        iv=iv,
        wrap_iv=wrap_iv,
        encrypted_dek=encrypted_dek,
        ciphertext=ciphertext,
        tag=tag,
    )


def open_envelope(envelope: Envelope, *, kek: bytes,
                 expected_context: dict[str, str]) -> bytes:
    """信封解密。

    判定顺序（对应可区分错误码）：
    1. 格式版本不被支持 -> CIPHERTEXT_INVALID；
    2. 上下文与密文绑定不一致 -> CONTEXT_MISMATCH（在碰密码学之前先判定）；
    3. KEK 解包 DEK 认证失败（版本不符/encrypted_dek 被篡改）
       -> CIPHERTEXT_INVALID；
    4. DEK 解密明文认证失败（ciphertext/tag/iv 被篡改）
       -> CIPHERTEXT_INVALID。
    """
    if envelope.format_version != ENVELOPE_FORMAT_VERSION:
        raise CiphertextInvalidError(
            f"不支持的信封格式版本: {envelope.format_version}",
            key_version=envelope.key_version,
        )

    if envelope.context != dict(expected_context):
        raise ContextMismatchError(
            "解密上下文与密文绑定的上下文不一致",
            key_version=envelope.key_version,
        )

    if len(kek) != 32:
        raise CiphertextInvalidError(
            "KEK 长度必须为 32 字节（AES-256）",
            key_version=envelope.key_version,
        )

    aad = _aad(envelope, envelope.context)

    try:
        dek = AESGCM(kek).decrypt(envelope.wrap_iv, envelope.encrypted_dek, aad)
    except InvalidTag as exc:
        raise CiphertextInvalidError(
            "DEK 包装认证失败：密钥版本不匹配或 encrypted_dek 已被篡改",
            key_version=envelope.key_version,
        ) from exc

    sealed = envelope.ciphertext + envelope.tag
    try:
        return AESGCM(dek).decrypt(envelope.iv, sealed, aad)
    except InvalidTag as exc:
        raise CiphertextInvalidError(
            "明文认证失败：ciphertext/tag/iv 已被篡改",
            key_version=envelope.key_version,
        ) from exc
