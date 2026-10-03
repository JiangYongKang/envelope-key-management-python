"""Core domain model: key lifecycle states, key versions, ciphertext, audit."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

# Wire format version for the envelope token produced by this service.
ENVELOPE_FORMAT_VERSION = 1
ENVELOPE_MAGIC = "EKM"


class KeyState(str, Enum):
    """Lifecycle state of a key version.

    ACTIVE      - usable for both encryption and decryption.
    DEACTIVATED - legacy version: decryption only, new encryption forbidden.
    REVOKED     - permanently disabled: neither encryption nor decryption.
    """

    ACTIVE = "ACTIVE"
    DEACTIVATED = "DEACTIVATED"
    REVOKED = "REVOKED"


class KeyOperation(str, Enum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    ROTATE = "ROTATE"
    DEACTIVATE = "DEACTIVATE"
    REVOKE = "REVOKE"
    MIGRATE = "MIGRATE"


class OperationResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


def b64e(data: bytes) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    """Decode base64url with or without padding; raise ValueError on garbage."""
    if not isinstance(text, str):
        raise ValueError("base64 field must be a string")
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def digest_hex(data: bytes) -> str:
    """Short SHA-256 hex digest used for input summaries in logs/audit."""
    return hashlib.sha256(data).hexdigest()


class EncryptionContext:
    """Immutable, order-independent encryption context (used as AAD).

    Only ``str -> str`` mappings are accepted so the canonical encoding is
    unambiguous. Two contexts are equal when they contain the same pairs,
    regardless of insertion order.
    """

    __slots__ = ("_values", "_canonical")

    def __init__(self, values: dict[str, str] | None = None) -> None:
        if values is None:
            values = {}
        if not isinstance(values, dict):
            raise TypeError("encryption context must be a dict[str, str]")
        normalised: dict[str, str] = {}
        for key, value in values.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("encryption context keys and values must be strings")
            normalised[key] = value
        self._values = dict(sorted(normalised.items()))
        self._canonical = json.dumps(
            self._values,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def canonical_bytes(self) -> bytes:
        """Deterministic byte encoding used as additional authenticated data."""
        return self._canonical

    def digest(self) -> str:
        return digest_hex(self._canonical)

    def to_dict(self) -> dict[str, str]:
        return dict(self._values)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EncryptionContext):
            return NotImplemented
        return self._values == other._values

    def __hash__(self) -> int:
        return hash(tuple(self._values.items()))

    def __repr__(self) -> str:
        return f"EncryptionContext({self._values!r})"


@dataclass(frozen=True)
class KeyVersion:
    """One version of a data-encryption key held entirely in local memory."""

    version: str
    key_material: bytes
    state: KeyState
    created_at: str

    def is_usable_for_encrypt(self) -> bool:
        return self.state is KeyState.ACTIVE

    def is_usable_for_decrypt(self) -> bool:
        return self.state in (KeyState.ACTIVE, KeyState.DEACTIVATED)


@dataclass(frozen=True)
class EnvelopeCiphertext:
    """Ciphertext bound to a key version and an encryption context.

    Token layout (base64url of a JSON document)::

        {"m":"EKM","v":1,"kid":"<key-id>","ver":"<key-version>",
         "iv":b64,"ct":b64,"tag":b64,"ctx":{...}}

    The key id, key version and canonical context are also passed as AES-GCM
    additional authenticated data, so changing any of them in the token makes
    authentication fail (reported as CIPHERTEXT_TAMPERED).
    """

    key_id: str
    key_version: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    context: EncryptionContext

    def to_token(self) -> str:
        document = {
            "m": ENVELOPE_MAGIC,
            "v": ENVELOPE_FORMAT_VERSION,
            "kid": self.key_id,
            "ver": self.key_version,
            "iv": b64e(self.nonce),
            "ct": b64e(self.ciphertext),
            "tag": b64e(self.tag),
            "ctx": self.context.to_dict(),
        }
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return b64e(raw)

    @classmethod
    def from_token(cls, token: str) -> "EnvelopeCiphertext":
        from .errors import CiphertextInvalidError

        if not isinstance(token, str) or not token:
            raise CiphertextInvalidError("token is empty or not a string")
        try:
            raw = b64d(token)
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CiphertextInvalidError(f"token is not valid base64/json: {exc}") from exc

        if not isinstance(document, dict):
            raise CiphertextInvalidError("token payload is not a JSON object")
        if document.get("m") != ENVELOPE_MAGIC:
            raise CiphertextInvalidError("missing or bad envelope magic marker")
        if document.get("v") != ENVELOPE_FORMAT_VERSION:
            raise CiphertextInvalidError(
                f"unsupported envelope format version: {document.get('v')!r}"
            )
        for field_name in ("kid", "ver"):
            if not isinstance(document.get(field_name), str) or not document[field_name]:
                raise CiphertextInvalidError(f"missing or invalid field '{field_name}'")
        ctx_value = document.get("ctx")
        if not isinstance(ctx_value, dict):
            raise CiphertextInvalidError("missing or invalid field 'ctx'")
        try:
            context = EncryptionContext(ctx_value)  # type: ignore[arg-type]
            nonce = b64d(document["iv"])
            ciphertext = b64d(document["ct"])
            tag = b64d(document["tag"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CiphertextInvalidError(f"missing or malformed field: {exc}") from exc

        return cls(
            key_id=document["kid"],
            key_version=document["ver"],
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            context=context,
        )


class MigrationStatus(str, Enum):
    """Per-item outcome of a ciphertext migration batch."""

    MIGRATED = "MIGRATED"                # re-encrypted under the target version
    ALREADY_CURRENT = "ALREADY_CURRENT"  # already on the target; returned as-is
    FAILED = "FAILED"                    # classified failure, see error_code


@dataclass(frozen=True)
class MigrationItemResult:
    """One item of a migration batch; exactly one entry per input token."""

    index: int
    status: MigrationStatus
    key_version: str | None        # version embedded in the input token
    target_version: str | None     # current ACTIVE version when processed
    ciphertext: str | None         # new token (MIGRATED) / original (ALREADY_CURRENT)
    error_code: str | None
    detail: str
    input_digest: str              # sha256 of the input token (never plaintext)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "status": self.status.value,
            "key_version": self.key_version,
            "target_version": self.target_version,
            "ciphertext": self.ciphertext,
            "error_code": self.error_code,
            "detail": self.detail,
            "input_digest": self.input_digest,
        }


@dataclass(frozen=True)
class MigrationReport:
    """Aggregate of a migration batch; counts always match the item list."""

    items: tuple[MigrationItemResult, ...]

    @property
    def total(self) -> int:
        return len(self.items)

    @property
    def migrated(self) -> int:
        return sum(1 for i in self.items if i.status is MigrationStatus.MIGRATED)

    @property
    def already_current(self) -> int:
        return sum(1 for i in self.items if i.status is MigrationStatus.ALREADY_CURRENT)

    @property
    def failed(self) -> int:
        return sum(1 for i in self.items if i.status is MigrationStatus.FAILED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "migrated": self.migrated,
            "already_current": self.already_current,
            "failed": self.failed,
            "items": [i.to_dict() for i in self.items],
        }


@dataclass(frozen=True)
class AuditRecord:
    """One audit entry; result must match the actual operation outcome."""

    timestamp: str
    operation: KeyOperation
    result: OperationResult
    key_version: str | None
    context_digest: str | None
    error_code: str | None
    detail: str
    input_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "operation": self.operation.value,
            "result": self.result.value,
            "key_version": self.key_version,
            "context_digest": self.context_digest,
            "error_code": self.error_code,
            "detail": self.detail,
            "input_digest": self.input_digest,
        }
