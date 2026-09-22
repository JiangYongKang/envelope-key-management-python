"""信封加解密、版本绑定、上下文绑定与密文篡改的错误分类。"""

from __future__ import annotations

import dataclasses

import pytest

from app import crypto
from app.errors import CiphertextInvalidError, ContextMismatchError
from app.models import Envelope

CONTEXT = {"tenant": "acme", "purpose": "backup"}


def test_seal_open_roundtrip():
    kek = b"k" * 32
    plaintext = b"order-12345"
    envelope = crypto.seal(plaintext, kek=kek, key_version=7, context=CONTEXT)
    assert envelope.key_version == 7
    assert envelope.context == CONTEXT
    assert crypto.open_envelope(envelope, kek=kek, expected_context=CONTEXT) == plaintext
    print(
        "输入摘要 pt=%s ctx=%s -> 判定 SUCCESS key_version=7",
        crypto.digest(plaintext),
        crypto.digest_context(CONTEXT),
    )


def test_context_mismatch_is_distinct_error():
    kek = b"k" * 32
    envelope = crypto.seal(b"data", kek=kek, key_version=1, context=CONTEXT)
    with pytest.raises(ContextMismatchError) as ei:
        crypto.open_envelope(
            envelope, kek=kek, expected_context={"tenant": "acme", "purpose": "evil"}
        )
    assert ei.value.code.value == "CONTEXT_MISMATCH"
    assert ei.value.key_version == 1
    print("输入 ctx=%s -> 判定 DENIED CONTEXT_MISMATCH", crypto.digest_context(CONTEXT))


@pytest.mark.parametrize(
    "field,mutator",
    [
        ("ciphertext", lambda e: b"x" + e.ciphertext[1:]),
        ("tag", lambda e: bytes([e.tag[0] ^ 0xFF]) + e.tag[1:]),
        ("encrypted_dek", lambda e: bytes([e.encrypted_dek[0] ^ 1]) + e.encrypted_dek[1:]),
        ("iv", lambda e: bytes([e.iv[0] ^ 1]) + e.iv[1:]),
    ],
)
def test_tampered_fields_rejected_as_ciphertext_invalid(field, mutator):
    kek = b"k" * 32
    envelope = crypto.seal(b"data", kek=kek, key_version=3, context=CONTEXT)
    tampered = dataclasses.replace(envelope, **{field: mutator(envelope)})
    with pytest.raises(CiphertextInvalidError) as ei:
        crypto.open_envelope(tampered, kek=kek, expected_context=CONTEXT)
    assert ei.value.code.value == "CIPHERTEXT_INVALID"
    print(
        "篡改字段=%s key_version=3 -> 判定 DENIED CIPHERTEXT_INVALID: %s",
        field,
        ei.value.message,
    )


def test_wrong_kek_rejected_and_no_version_fallback():
    envelope = crypto.seal(b"data", kek=b"a" * 32, key_version=1, context=CONTEXT)
    with pytest.raises(CiphertextInvalidError) as ei:
        crypto.open_envelope(envelope, kek=b"b" * 32, expected_context=CONTEXT)
    assert ei.value.code.value == "CIPHERTEXT_INVALID"
    print("用其它版本材料解密 -> 判定 DENIED CIPHERTEXT_INVALID（无回退）")


def test_context_field_tamper_fails_aad():
    # 即便调用方按“被篡改后的上下文”发起解密，AAD 仍与密文认证不一致。
    kek = b"k" * 32
    envelope = crypto.seal(b"data", kek=kek, key_version=1, context=CONTEXT)
    forged = dataclasses.replace(envelope, context={"tenant": "mallory", "purpose": "backup"})
    with pytest.raises((CiphertextInvalidError, ContextMismatchError)):
        crypto.open_envelope(
            forged, kek=kek, expected_context={"tenant": "mallory", "purpose": "backup"}
        )


def test_serialized_envelope_roundtrip():
    kek = b"k" * 32
    envelope = crypto.seal(b"json-able", kek=kek, key_version=2, context={"a": "b"})
    restored = Envelope.from_json(envelope.to_json())
    assert crypto.open_envelope(restored, kek=kek, expected_context={"a": "b"}) == b"json-able"


def test_malformed_serialized_envelope_rejected():
    with pytest.raises(CiphertextInvalidError):
        Envelope.from_dict({"format_version": 1})  # 缺字段
    print("残缺密文 -> 判定 DENIED CIPHERTEXT_INVALID（解析阶段）")
