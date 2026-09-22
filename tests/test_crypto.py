"""AES-GCM envelope: binding of version/context and tamper classification."""

from __future__ import annotations

import os

import pytest

from app.crypto import decrypt_envelope, encrypt_envelope
from app.errors import CiphertextTamperedError
from app.models import EncryptionContext, EnvelopeCiphertext

from .conftest import log_case


@pytest.fixture
def key() -> bytes:
    return os.urandom(32)


def _with(env, **changes) -> EnvelopeCiphertext:
    values = {
        "key_id": env.key_id,
        "key_version": env.key_version,
        "nonce": env.nonce,
        "ciphertext": env.ciphertext,
        "tag": env.tag,
        "context": env.context,
    }
    values.update(changes)
    return EnvelopeCiphertext(**values)


def test_encrypt_decrypt_roundtrip(key):
    ctx = EncryptionContext({"tenant": "acme", "purpose": "pii"})
    env = encrypt_envelope(key, "kid", "v2", b"payload", ctx)
    assert decrypt_envelope(key, env) == b"payload"
    log_case("crypto-roundtrip", plaintext=b"payload", version="v2")


def test_ciphertext_byte_flip_is_tampered(key):
    ctx = EncryptionContext({})
    env = encrypt_envelope(key, "kid", "v1", b"payload", ctx)
    flipped = bytes([env.ciphertext[0] ^ 1]) + env.ciphertext[1:]
    with pytest.raises(CiphertextTamperedError) as exc:
        decrypt_envelope(key, _with(env, ciphertext=flipped))
    assert exc.value.code.value == "CIPHERTEXT_TAMPERED"
    assert exc.value.key_version == "v1"
    log_case("crypto-tamper-ct", version="v1")


def test_tag_flip_is_tampered(key):
    env = encrypt_envelope(key, "kid", "v1", b"payload", EncryptionContext({}))
    bad_tag = bytes([env.tag[0] ^ 1]) + env.tag[1:]
    with pytest.raises(CiphertextTamperedError):
        decrypt_envelope(key, _with(env, tag=bad_tag))
    log_case("crypto-tamper-tag", version="v1")


def test_version_retarget_fails_authentication(key):
    env = encrypt_envelope(key, "kid", "v1", b"payload", EncryptionContext({}))
    with pytest.raises(CiphertextTamperedError):
        decrypt_envelope(key, _with(env, key_version="v2"))
    log_case("crypto-retarget-version", old="v1", new="v2")


def test_context_swap_fails_authentication(key):
    env = encrypt_envelope(
        key, "kid", "v1", b"payload", EncryptionContext({"env": "prod"})
    )
    with pytest.raises(CiphertextTamperedError):
        decrypt_envelope(key, _with(env, context=EncryptionContext({"env": "dev"})))
    log_case("crypto-context-swap", old="prod", new="dev")


def test_wrong_key_is_tampered(key):
    env = encrypt_envelope(key, "kid", "v1", b"payload", EncryptionContext({}))
    with pytest.raises(CiphertextTamperedError):
        decrypt_envelope(os.urandom(32), env)
    log_case("crypto-wrong-key", version="v1")


def test_key_size_enforced(key):
    env = encrypt_envelope(key, "kid", "v1", b"x", EncryptionContext({}))
    with pytest.raises(ValueError):
        decrypt_envelope(b"too-short", env)
    log_case("crypto-key-size", size=len(b"too-short"))


def test_nonce_is_randomised(key):
    a = encrypt_envelope(key, "kid", "v1", b"same", EncryptionContext({}))
    b = encrypt_envelope(key, "kid", "v1", b"same", EncryptionContext({}))
    assert a.nonce != b.nonce and a.to_token() != b.to_token()
    assert decrypt_envelope(key, a) == decrypt_envelope(key, b) == b"same"
    log_case("crypto-nonce-uniqueness")
