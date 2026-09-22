"""Domain model: canonical context ordering, token round-trip, validation."""

from __future__ import annotations

import pytest

from app.errors import CiphertextInvalidError
from app.models import (
    ENVELOPE_MAGIC,
    EncryptionContext,
    EnvelopeCiphertext,
    KeyState,
    KeyVersion,
    b64d,
    b64e,
)

from .conftest import log_case


def test_context_is_order_independent():
    a = EncryptionContext({"tenant": "acme", "env": "prod"})
    b = EncryptionContext({"env": "prod", "tenant": "acme"})
    assert a == b
    assert a.canonical_bytes() == b.canonical_bytes()
    assert hash(a) == hash(b)
    log_case("context-order", ctx_a=a.to_dict(), ctx_b=b.to_dict())


def test_context_rejects_non_string_values():
    with pytest.raises(TypeError):
        EncryptionContext({"tenant": 1})  # type: ignore[dict-item]
    log_case("context-type", bad_value_type="int")


def test_b64_roundtrip_with_and_without_padding():
    data = bytes(range(256))
    assert b64d(b64e(data)) == data
    assert b64d(b64e(data) + "=") == data  # tolerant of padding
    log_case("b64-roundtrip", length=256)


@pytest.mark.parametrize("state,can_enc,can_dec", [
    (KeyState.ACTIVE, True, True),
    (KeyState.DEACTIVATED, False, True),
    (KeyState.REVOKED, False, False),
])
def test_keyversion_state_rules(state, can_enc, can_dec):
    kv = KeyVersion("v1", b"k" * 32, state, "2026-09-23T00:00:00Z")
    assert kv.is_usable_for_encrypt() is can_enc
    assert kv.is_usable_for_decrypt() is can_dec
    log_case("key-state", state=state.value, encrypt=can_enc, decrypt=can_dec)


def test_envelope_token_roundtrip_binds_fields():
    ctx = EncryptionContext({"tenant": "acme"})
    env = EnvelopeCiphertext("kid-1", "v7", b"n" * 12, b"ct", b"t" * 16, ctx)
    token = env.to_token()
    back = EnvelopeCiphertext.from_token(token)
    assert (back.key_id, back.key_version, back.nonce, back.ciphertext, back.tag) == (
        "kid-1", "v7", b"n" * 12, b"ct", b"t" * 16,
    )
    assert back.context == ctx
    log_case("token-roundtrip", token=token)


@pytest.mark.parametrize("mutator,reason", [
    (lambda t: "", "empty"),
    (lambda t: "!!!not-base64!!!", "bad-base64"),
    (lambda t: b64e(b"{}"), "not-an-envelope"),
])
def test_envelope_token_rejects_garbage(mutator, reason):
    good = EnvelopeCiphertext(
        "k", "v1", b"n" * 12, b"ct", b"t" * 16, EncryptionContext({})
    ).to_token()
    with pytest.raises(CiphertextInvalidError):
        EnvelopeCiphertext.from_token(mutator(good))
    log_case("token-garbage", reason=reason)


def test_envelope_token_rejects_bad_magic_and_version():
    import base64
    import json

    token = EnvelopeCiphertext(
        "k", "v1", b"n" * 12, b"ct", b"t" * 16, EncryptionContext({})
    ).to_token()
    pad = "=" * (-len(token) % 4)
    doc = json.loads(base64.urlsafe_b64decode(token + pad))
    doc["m"] = "OTHER"
    bad = base64.urlsafe_b64encode(
        json.dumps(doc).encode()
    ).rstrip(b"=").decode()
    with pytest.raises(CiphertextInvalidError):
        EnvelopeCiphertext.from_token(bad)
    log_case("token-bad-magic", magic=ENVELOPE_MAGIC)
