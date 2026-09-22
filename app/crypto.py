"""Envelope encryption primitives (AES-256-GCM, local only).

All cryptographic operations happen in-process with key material that came
from a :class:`~app.key_source.LocalKeySource`. Nothing here performs network
IO or calls an external key service.

The authenticated data binds the ciphertext to *both* its key id / version
and the canonical encryption context, so a retargeted token or swapped
context fails authentication instead of being silently decrypted.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import CiphertextTamperedError
from .models import (
    ENVELOPE_FORMAT_VERSION,
    ENVELOPE_MAGIC,
    EncryptionContext,
    EnvelopeCiphertext,
)

_KEY_SIZE = 32  # AES-256
_NONCE_SIZE = 12  # 96-bit nonce recommended for GCM


def _aad(key_id: str, key_version: str, context: EncryptionContext) -> bytes:
    """Assemble version + context bound authenticated data.

    Layout (length-prefixed to remove any ambiguity)::

        b"EKM-v1" | u16(len(kid)) | kid | u16(len(ver)) | ver | ctx
    """
    kid = key_id.encode("utf-8")
    ver = key_version.encode("utf-8")
    if len(kid) > 0xFFFF or len(ver) > 0xFFFF:
        raise ValueError("key id / version too long")
    header = f"{ENVELOPE_MAGIC}-v{ENVELOPE_FORMAT_VERSION}".encode("ascii")
    return (
        header
        + len(kid).to_bytes(2, "big") + kid
        + len(ver).to_bytes(2, "big") + ver
        + context.canonical_bytes()
    )


def _validate_key(key_material: bytes) -> None:
    if not isinstance(key_material, (bytes, bytearray)):
        raise TypeError("key material must be bytes")
    if len(key_material) != _KEY_SIZE:
        raise ValueError(f"AES-256 key must be exactly {_KEY_SIZE} bytes")


def encrypt_envelope(
    key_material: bytes,
    key_id: str,
    key_version: str,
    plaintext: bytes,
    context: EncryptionContext,
) -> EnvelopeCiphertext:
    """Encrypt locally with AES-256-GCM, binding version + context as AAD."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    _validate_key(key_material)

    import os

    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(bytes(key_material))
    sealed = aesgcm.encrypt(
        nonce,
        plaintext,
        _aad(key_id, key_version, context),
    )
    # AESGCM appends the 16-byte tag to the ciphertext.
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return EnvelopeCiphertext(
        key_id=key_id,
        key_version=key_version,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        context=context,
    )


def decrypt_envelope(key_material: bytes, token: EnvelopeCiphertext) -> bytes:
    """Decrypt locally.

    Raises :class:`CiphertextTamperedError` when authentication fails, which
    covers a flipped ciphertext byte, a retargeted key version/id, or a
    mismatched context.
    """
    _validate_key(key_material)
    aesgcm = AESGCM(bytes(key_material))
    sealed = bytes(token.ciphertext) + bytes(token.tag)
    try:
        return aesgcm.decrypt(
            bytes(token.nonce),
            sealed,
            _aad(token.key_id, token.key_version, token.context),
        )
    except Exception as exc:  # cryptography raises InvalidTag (and bad nonce len)
        raise CiphertextTamperedError(token.key_version) from exc
