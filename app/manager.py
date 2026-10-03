"""Thread-safe key lifecycle + envelope encryption service core.

Concurrency model
-----------------
A single re-entrant lock guards the in-memory key ring and the current-version
pointer. All state transitions (rotate / deactivate / revoke) and the lookup
half of encrypt/decrypt run under that lock, so:

* rotation and decryption never interleave into an unreadable state —
  decryption always sees a consistent (version -> key material, state) view;
* concurrent rotations are serialised and produce distinct monotonic
  versions (optimistic ``expected_version`` additionally rejects a lost
  rotation race with ROTATION_RACE instead of overwriting progress);
* every encryption uses exactly the current ACTIVE key at call time.
"""

from __future__ import annotations

import datetime as _dt
import logging
import threading
from dataclasses import dataclass

from .audit import AuditLogger, NullAuditLogger
from .crypto import decrypt_envelope, encrypt_envelope
from .errors import (
    CiphertextInvalidError,
    CiphertextTamperedError,
    ConfigurationError,
    ContextMismatchError,
    InvalidLifecycleTransitionError,
    KeyDeactivatedError,
    KeyIdMismatchError,
    KeyRevokedError,
    KeyVersionNotFoundError,
    NoActiveKeyError,
    RotationRaceError,
    StateInvalidError,
)
from .key_source import LocalKeySource, generate_local_key
from .models import (
    EncryptionContext,
    KeyOperation,
    KeyState,
    KeyVersion,
    MigrationItem,
    MigrationItemResult,
    MigrationReport,
    MigrationStatus,
    OperationResult,
    AuditRecord,
    digest_hex,
)
from .state import InMemoryStateStore, PersistedState, StateStore

logger = logging.getLogger("ekm")


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class VersionInfo:
    version: str
    state: KeyState
    created_at: str
    is_current: bool


class KeyManager:
    """Owns the in-memory key ring and serialises all state transitions."""

    def __init__(
        self,
        key_id: str,
        key_source: LocalKeySource,
        audit_logger: AuditLogger | NullAuditLogger,
        state_store: StateStore | None = None,
    ) -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ConfigurationError("key id must be a non-empty string")
        self._key_id = key_id
        self._key_source = key_source
        self._audit = audit_logger
        self._state_store: StateStore = state_store or InMemoryStateStore()
        self._lock = threading.RLock()
        self._ring: dict[str, KeyVersion] = {}
        self._current_version: str | None = None
        self._sequence = 0
        # Test-only hook fired after re-encryption but before the commit gate,
        # letting deterministic tests race a rotation/deactivation/revoke into
        # the exact window. Always None in production.
        self.migrate_pre_commit_hook: object = None
        self._bootstrap()

    # ------------------------------------------------------------------ #
    # Bootstrap
    # ------------------------------------------------------------------ #
    def _bootstrap(self) -> None:
        """Load durable state if present; otherwise initialise from source.

        A persisted snapshot always wins over the static local key source:
        rotations/deactivations/revocations survive restarts and the current
        version never regresses. The key source is still validated (it defines
        the trust boundary and the fallback for a never-before-persisted run).
        """
        sourced = self._key_source.load()  # raises ConfigurationError on bad config
        self._validate_source(sourced)

        persisted = self._state_store.load()  # None or raises STATE_INVALID
        if persisted is not None:
            self._restore_persisted(persisted, sourced)
            return

        ring: dict[str, KeyVersion] = {}
        for sk in sourced:
            ring[sk.version] = KeyVersion(
                version=sk.version,
                key_material=sk.key_material,
                state=sk.state,
                created_at=_utc_now(),
            )
        active_versions = [s.version for s in sourced if s.state is KeyState.ACTIVE]
        self._ring = ring
        self._current_version = active_versions[0]
        self._sequence = self._initial_sequence([s.version for s in sourced])

        # Make the bootstrap snapshot durable up front: a later rotation must
        # never be the first write (that would let a crash confuse "fresh" and
        # "rotated" starts). Failure here aborts startup.
        self._persist_locked()
        logger.info(
            "key manager bootstrapped key_id=%s current=%s versions=%d",
            self._key_id, self._current_version, len(self._ring),
        )

    @staticmethod
    def _validate_source(sourced: list) -> None:
        """Enforce the source invariants (exactly one ACTIVE, no duplicates)."""
        active_versions = [s.version for s in sourced if s.state is KeyState.ACTIVE]
        if not active_versions:
            raise ConfigurationError(
                "local key source provides no ACTIVE key version; "
                "refusing to start without an encrypt-capable key"
            )
        if len(active_versions) > 1:
            raise ConfigurationError(
                "local key source declares multiple ACTIVE versions "
                f"{active_versions}; exactly one current version is required"
            )

    def _restore_persisted(self, persisted: PersistedState, sourced: list) -> None:
        """Rehydrate from an on-disk snapshot, checking it against the source."""
        if persisted.key_id != self._key_id:
            raise StateInvalidError(
                f"state file belongs to key id '{persisted.key_id}' but this "
                f"service manages '{self._key_id}'"
            )
        source_material = {s.version: s.key_material for s in sourced}
        for kv in persisted.versions:
            configured = source_material.get(kv.version)
            if configured is not None and configured != kv.key_material:
                raise StateInvalidError(
                    f"persisted key material for version '{kv.version}' differs "
                    "from the local key source; refusing to mix key sets"
                )
            # Versions created by past rotations are not in the static source;
            # their material comes from the state file itself (local disk).
        self._ring = {kv.version: kv for kv in persisted.versions}
        self._current_version = persisted.current_version
        self._sequence = persisted.sequence
        logger.info(
            "key manager restored durable state key_id=%s current=%s versions=%d",
            self._key_id, self._current_version, len(self._ring),
        )

    @staticmethod
    def _initial_sequence(labels: list[str]) -> int:
        highest = 0
        for label in labels:
            if label.startswith("v") and label[1:].isdigit():
                highest = max(highest, int(label[1:]))
        return highest

    def _persist_locked(self) -> None:
        """Durably persist the current ring snapshot (caller holds the lock)."""
        assert self._current_version is not None
        self._state_store.save(
            key_id=self._key_id,
            current_version=self._current_version,
            sequence=self._sequence,
            versions=list(self._ring.values()),
        )

    # ------------------------------------------------------------------ #
    # Lifecycle transitions
    # ------------------------------------------------------------------ #
    def rotate(self, *, expected_version: str | None = None) -> str:
        """Create a new ACTIVE version and deactivate the previous current.

        With ``expected_version`` set, the call is an optimistic compare-and-
        swap: when the current version has already moved on, ROTATION_RACE is
        raised instead of stacking another rotation (prevents duplicate/
        conflicting rotations).
        """
        with self._lock:
            old_version = self._current_version
            if expected_version is not None and expected_version != old_version:
                err = RotationRaceError(
                    f"rotation conflict: expected current '{expected_version}' but it is "
                    f"'{old_version}'; no new version was created"
                )
                self._failure_record(
                    KeyOperation.ROTATE, old_version, err,
                    detail="optimistic rotation lost the race",
                )
                raise err

            self._sequence += 1
            new_label = f"v{self._sequence}"
            if new_label in self._ring:  # extremely defensive
                raise RotationRaceError(f"generated duplicate version label '{new_label}'")

            new_kv = KeyVersion(
                version=new_label,
                key_material=generate_local_key(),
                state=KeyState.ACTIVE,
                created_at=_utc_now(),
            )
            # Stage the new key while the old one is still current so an audit
            # failure never leaves the ring without an active current key.
            self._ring[new_label] = new_kv
            old_kv = self._ring[old_version] if old_version is not None else None
            if old_kv is not None and old_kv.state is KeyState.ACTIVE:
                self._ring[old_version] = KeyVersion(
                    version=old_kv.version,
                    key_material=old_kv.key_material,
                    state=KeyState.DEACTIVATED,
                    created_at=old_kv.created_at,
                )
            self._current_version = new_label

            try:
                # Durability first: a restart must not forget this rotation.
                self._persist_locked()
            except Exception:
                self._current_version = old_version
                if old_kv is not None:
                    self._ring[old_version] = old_kv
                del self._ring[new_label]
                self._sequence -= 1
                raise
            try:
                self._audit.append(
                    self._make_record(
                        KeyOperation.ROTATE, OperationResult.SUCCESS,
                        key_version=new_label, error_code=None,
                        detail=f"rotated current from '{old_version}' to '{new_label}'",
                        context_digest=None, input_digest=None,
                    )
                )
            except Exception:
                # Roll the state transition back (in memory AND on disk) so
                # audit truth == state truth across a restart.
                self._current_version = old_version
                if old_kv is not None:
                    self._ring[old_version] = old_kv
                del self._ring[new_label]
                self._sequence -= 1
                try:
                    self._persist_locked()
                except Exception:  # noqa: BLE001 - surface the original failure
                    logger.exception("failed to roll back persisted state after audit failure")
                raise
            logger.info("rotation %s -> %s key_id=%s", old_version, new_label, self._key_id)
            return new_label

    def deactivate(self, version: str) -> None:
        """Move an ACTIVE, non-current version to DEACTIVATED (decrypt only)."""
        self._transition(
            version,
            KeyOperation.DEACTIVATE,
            target=KeyState.DEACTIVATED,
            allowed_from=(KeyState.ACTIVE,),
            reject_current=True,
        )

    def revoke(self, version: str) -> None:
        """Permanently revoke a version (no encrypt and no decrypt afterwards)."""
        with self._lock:
            if self._current_version == version:
                raise InvalidLifecycleTransitionError(
                    version,
                    from_state=KeyState.ACTIVE.value,
                    to_state=KeyState.REVOKED.value,
                )
            self._transition(
                version,
                KeyOperation.REVOKE,
                target=KeyState.REVOKED,
                allowed_from=(KeyState.ACTIVE, KeyState.DEACTIVATED),
                reject_current=False,
            )

    def _transition(
        self,
        version: str,
        operation: KeyOperation,
        *,
        target: KeyState,
        allowed_from: tuple[KeyState, ...],
        reject_current: bool,
    ) -> None:
        with self._lock:
            kv = self._ring.get(version)
            if kv is None:
                err = KeyVersionNotFoundError(version)
                self._failure_record(operation, version, err, detail="unknown version")
                raise err
            if reject_current and self._current_version == version:
                err = InvalidLifecycleTransitionError(
                    version, from_state=kv.state.value, to_state=target.value
                )
                self._failure_record(
                    operation, version, err,
                    detail="cannot change state of the current active version",
                )
                raise err
            if kv.state is target:
                # Idempotent no-op: nothing changed, record success honestly.
                self._audit.append(
                    self._make_record(
                        operation, OperationResult.SUCCESS, version, None,
                        detail=f"version already in target state {target.value}",
                        context_digest=None, input_digest=None,
                    )
                )
                return
            if kv.state not in allowed_from:
                err = InvalidLifecycleTransitionError(
                    version, from_state=kv.state.value, to_state=target.value
                )
                self._failure_record(operation, version, err, detail="illegal transition")
                raise err

            new_kv = KeyVersion(
                version=kv.version,
                key_material=kv.key_material,
                state=target,
                created_at=kv.created_at,
            )
            self._ring[version] = new_kv
            try:
                # The lifecycle change only commits once durable.
                self._persist_locked()
            except Exception:
                self._ring[version] = kv
                raise
            try:
                self._audit.append(
                    self._make_record(
                        operation, OperationResult.SUCCESS, version, None,
                        detail=f"state {kv.state.value} -> {target.value}",
                        context_digest=None, input_digest=None,
                    )
                )
            except Exception:
                self._ring[version] = kv  # rollback memory, then disk, then surface
                try:
                    self._persist_locked()
                except Exception:  # noqa: BLE001 - surface the original failure
                    logger.exception("failed to roll back persisted state after audit failure")
                raise
            logger.info("key %s %s -> %s", version, kv.state.value, target.value)

    # ------------------------------------------------------------------ #
    # Encryption / decryption
    # ------------------------------------------------------------------ #
    def encrypt(self, plaintext: bytes | str, context: dict[str, str] | EncryptionContext) -> str:
        """Encrypt under the current ACTIVE key; new writes always use latest."""
        ctx = self._coerce_context(context)
        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        if not isinstance(data, bytes):
            raise TypeError("plaintext must be bytes or str")
        input_digest = digest_hex(data)

        with self._lock:
            version = self._current_version
            if version is None:
                err = NoActiveKeyError(self._key_id)
                self._failure_record(
                    KeyOperation.ENCRYPT, None, err,
                    detail="no current active key",
                    context_digest=ctx.digest(), input_digest=input_digest,
                )
                raise err
            kv = self._ring.get(version)
            assert kv is not None  # current always points into the ring
            if kv.state is KeyState.REVOKED:
                err = KeyRevokedError(version, operation="encryption")
                self._failure_record(KeyOperation.ENCRYPT, version, err, "current key revoked",
                                     ctx.digest(), input_digest)
                raise err
            if not kv.is_usable_for_encrypt():
                err = KeyDeactivatedError(version, operation="encryption")
                self._failure_record(KeyOperation.ENCRYPT, version, err, "current key not active",
                                     ctx.digest(), input_digest)
                raise err

        # AES-GCM is pure computation; do it outside the ring lock.
        envelope = encrypt_envelope(
            kv.key_material, self._key_id, version, data, ctx
        )
        token = envelope.to_token()
        try:
            self._audit.append(
                self._make_record(
                    KeyOperation.ENCRYPT, OperationResult.SUCCESS, version, None,
                    detail="encrypted under current key",
                    context_digest=ctx.digest(), input_digest=input_digest,
                )
            )
        except Exception:
            # The token is only handed out after the success audit is durable.
            raise
        logger.debug(
            "decision ENCRYPT success version=%s ctx=%s input=%s",
            version, ctx.digest()[:12], input_digest[:12],
        )
        return token

    def decrypt(self, token: str, context: dict[str, str] | EncryptionContext) -> bytes:
        """Decrypt strictly with the version embedded in the token.

        There is deliberately no fallback to other versions: if the embedded
        version is missing/revoked or authentication fails, the operation is
        rejected with its specific reason.
        """
        ctx = self._coerce_context(context)
        token_digest = digest_hex(token.encode("utf-8")) if isinstance(token, str) else None

        # 1. Structural validation -> CIPHERTEXT_INVALID (no version guessing).
        try:
            envelope = _parse_envelope(token)
        except CiphertextInvalidError as err:
            self._decision_log("DECRYPT", "failure", None, err.code.value,
                               ctx.digest(), token_digest)
            self._failure_record(
                KeyOperation.DECRYPT, getattr(err, "key_version", None), err,
                detail=err.message, context_digest=ctx.digest(), input_digest=token_digest,
            )
            raise

        version = envelope.key_version

        # 2. Key identity binding: a token minted for another key ring is
        #    rejected rather than interpreted against this ring.
        if envelope.key_id != self._key_id:
            err = KeyIdMismatchError(
                version, expected=self._key_id, actual=envelope.key_id
            )
            self._decision_log("DECRYPT", "failure", version, err.code.value,
                               ctx.digest(), token_digest)
            self._failure_record(KeyOperation.DECRYPT, version, err,
                                 detail=err.message,
                                 context_digest=ctx.digest(), input_digest=token_digest)
            raise err

        # 3. Context binding: the caller's context must equal the bound one.
        if envelope.context != ctx:
            err = ContextMismatchError(version)
            self._decision_log("DECRYPT", "failure", version, err.code.value,
                               ctx.digest(), token_digest)
            self._failure_record(KeyOperation.DECRYPT, version, err,
                                 detail="provided context differs from bound context",
                                 context_digest=ctx.digest(), input_digest=token_digest)
            raise err

        # 4. Version existence and lifecycle state (no fallback).
        with self._lock:
            kv = self._ring.get(version)
            if kv is None:
                err = KeyVersionNotFoundError(version)
                self._decision_log("DECRYPT", "failure", version, err.code.value,
                                   ctx.digest(), token_digest)
                self._failure_record(KeyOperation.DECRYPT, version, err,
                                     detail="embedded version absent from key ring",
                                     context_digest=ctx.digest(), input_digest=token_digest)
                raise err
            if kv.state is KeyState.REVOKED:
                err = KeyRevokedError(version, operation="decryption")
                self._decision_log("DECRYPT", "failure", version, err.code.value,
                                   ctx.digest(), token_digest)
                self._failure_record(KeyOperation.DECRYPT, version, err,
                                     detail="embedded version revoked",
                                     context_digest=ctx.digest(), input_digest=token_digest)
                raise err
            # DEACTIVATED is allowed for decrypt; ACTIVE too.
            if not kv.is_usable_for_decrypt():
                err = KeyDeactivatedError(version, operation="decryption")
                self._decision_log("DECRYPT", "failure", version, err.code.value,
                                   ctx.digest(), token_digest)
                self._failure_record(KeyOperation.DECRYPT, version, err,
                                     detail="embedded version not decrypt-capable",
                                     context_digest=ctx.digest(), input_digest=token_digest)
                raise err
            key_material = kv.key_material

        # 5. AEAD verification -> CIPHERTEXT_TAMPERED for ciphertext/tag/nonce
        #    modifications (version/context swaps were already classified).
        try:
            plaintext = decrypt_envelope(key_material, envelope)
        except CiphertextTamperedError as err:
            self._decision_log("DECRYPT", "failure", version, err.code.value,
                               ctx.digest(), token_digest)
            self._failure_record(KeyOperation.DECRYPT, version, err,
                                 detail="AEAD authentication failed",
                                 context_digest=ctx.digest(), input_digest=token_digest)
            raise

        self._audit.append(
            self._make_record(
                KeyOperation.DECRYPT, OperationResult.SUCCESS, version, None,
                detail="decrypted with embedded version",
                context_digest=ctx.digest(), input_digest=token_digest,
            )
        )
        self._decision_log("DECRYPT", "success", version, None, ctx.digest(), token_digest)
        return plaintext

    # ------------------------------------------------------------------ #
    # Batch migration (re-encryption to the current version)
    # ------------------------------------------------------------------ #
    def migrate(
        self,
        items: list,
        default_context: dict[str, str] | EncryptionContext | None = None,
    ) -> MigrationReport:
        """Upgrade a batch of historical ciphertexts to the current version.

        ``items`` is a list whose entries are either:

        * an envelope token ``str`` — the context bound inside the token is
          reused, so callers never hand over plaintext (the service never
          returns it either: only new tokens come back);
        * a ``dict`` ``{"ciphertext": <token>, "context": {...},
          "item_id": <optional caller correlation id>}``;
        * a :class:`~app.models.MigrationItem`.

        ``default_context`` applies to entries that carry no explicit context;
        when supplied it must equal the bound context, exactly like decrypt().

        Every item is classified individually as REENCRYPTED, ALREADY_CURRENT
        (idempotent no-op) or FAILED with its own error code/reason. Nothing is
        silently skipped and a partial batch is reported as such via the
        returned report (``all_succeeded`` is False); the audit log records one
        MIGRATE entry per item.
        """
        if not isinstance(items, list):
            raise TypeError("migrate items must be a list")
        default_ctx = (
            self._coerce_context(default_context) if default_context is not None
            else EncryptionContext({})
        )

        with self._lock:
            target_version = self._current_version
            if target_version is None:
                raise NoActiveKeyError(self._key_id)

        default_ctx_supplied = default_context is not None
        results: list[MigrationItemResult] = []
        for index, raw in enumerate(items):
            results.append(
                self._migrate_one(
                    index, raw, default_ctx, default_ctx_supplied, target_version
                )
            )

        report = MigrationReport(target_version=target_version, results=tuple(results))
        logger.info(
            "migration batch complete target=%s total=%d reencrypted=%d "
            "already_current=%d failed=%d",
            target_version, report.total, report.reencrypted_count,
            report.already_current_count, report.failed_count,
        )
        return report

    def _migrate_one(
        self,
        index: int,
        raw: object,
        default_ctx: EncryptionContext,
        default_ctx_supplied: bool,
        target_version: str,
    ) -> MigrationItemResult:
        """Classify + upgrade one item. Never raises for item-level problems."""
        item_id: str | None = None
        token: str
        provided_ctx: EncryptionContext
        ctx_supplied: bool
        input_digest: str | None = None
        try:
            if isinstance(raw, str):
                token = raw
                provided_ctx = default_ctx
                ctx_supplied = default_ctx_supplied
            elif isinstance(raw, MigrationItem):
                token = raw.ciphertext
                item_id = raw.item_id
                if raw.context is not None:
                    provided_ctx = raw.context
                    ctx_supplied = True
                else:
                    provided_ctx = default_ctx
                    ctx_supplied = default_ctx_supplied
            elif isinstance(raw, dict):
                token_text = raw.get("ciphertext")
                if not isinstance(token_text, str):
                    raise CiphertextInvalidError("item is missing a string 'ciphertext'")
                token = token_text
                item_value = raw.get("item_id")
                item_id = item_value if isinstance(item_value, str) else None
                ctx_value = raw.get("context")
                if ctx_value is not None:
                    provided_ctx = self._coerce_context(ctx_value)
                    ctx_supplied = True
                else:
                    provided_ctx = default_ctx
                    ctx_supplied = default_ctx_supplied
            else:
                raise CiphertextInvalidError(
                    f"item must be a token string or object, got {type(raw).__name__}"
                )
        except CiphertextInvalidError as err:
            return self._migrate_failure(
                index, item_id, None, target_version, err,
                detail=err.message, context_digest=None, input_digest=None,
            )
        except (TypeError, ValueError) as err:
            cierr = CiphertextInvalidError(str(err))
            return self._migrate_failure(
                index, item_id, None, target_version, cierr,
                detail=cierr.message, context_digest=None, input_digest=None,
            )
        input_digest = digest_hex(token.encode("utf-8"))

        ctx_digest = provided_ctx.digest()

        # 1. Structural validation (same order as decrypt; no version guessing).
        try:
            envelope = _parse_envelope(token)
        except CiphertextInvalidError as err:
            return self._migrate_failure(
                index, item_id, getattr(err, "key_version", None), target_version,
                err, detail=err.message,
                context_digest=ctx_digest, input_digest=input_digest,
            )
        source_version = envelope.key_version

        # 2. Key identity binding.
        if envelope.key_id != self._key_id:
            err = KeyIdMismatchError(
                source_version, expected=self._key_id, actual=envelope.key_id
            )
            return self._migrate_failure(
                index, item_id, source_version, target_version, err,
                detail=err.message, context_digest=ctx_digest, input_digest=input_digest,
            )

        # 3. Context binding: only verified when the caller supplied a context
        #    (per-item or batch default). A bare token is a pure server-side
        #    upgrade — the bound context is reused as-is, no plaintext exposed.
        if ctx_supplied and envelope.context != provided_ctx:
            err = ContextMismatchError(source_version)
            return self._migrate_failure(
                index, item_id, source_version, target_version, err,
                detail="provided context differs from bound context",
                context_digest=ctx_digest, input_digest=input_digest,
            )
        # From here on operate on the bound context for digest/re-encryption.
        bound_ctx = envelope.context
        ctx_digest = bound_ctx.digest()

        # 4. Snapshot source + target key material and states under the lock.
        with self._lock:
            source_kv = self._ring.get(source_version)
            target_kv = self._ring.get(target_version)
            assert target_kv is not None
            if source_kv is None:
                err = KeyVersionNotFoundError(source_version)
                return self._migrate_failure(
                    index, item_id, source_version, target_version, err,
                    detail="embedded version absent from key ring",
                    context_digest=ctx_digest, input_digest=input_digest,
                )
            if source_kv.state is KeyState.REVOKED:
                err = KeyRevokedError(source_version, operation="migration source decryption")
                return self._migrate_failure(
                    index, item_id, source_version, target_version, err,
                    detail="embedded source version is revoked",
                    context_digest=ctx_digest, input_digest=input_digest,
                )
            if not source_kv.is_usable_for_decrypt():
                err = KeyDeactivatedError(source_version, operation="migration source decryption")
                return self._migrate_failure(
                    index, item_id, source_version, target_version, err,
                    detail="embedded source version is not decrypt-capable",
                    context_digest=ctx_digest, input_digest=input_digest,
                )
            # Target's own state is the stronger failure reason (a revoked or
            # deactivated target must never seal a new token).
            if target_kv.state is KeyState.REVOKED:
                err = KeyRevokedError(target_version, operation="migration target encryption")
                return self._migrate_failure(
                    index, item_id, source_version, target_version, err,
                    detail="migration target version is revoked",
                    context_digest=ctx_digest, input_digest=input_digest,
                )
            if not target_kv.is_usable_for_encrypt():
                err = KeyDeactivatedError(target_version, operation="migration target encryption")
                return self._migrate_failure(
                    index, item_id, source_version, target_version, err,
                    detail="migration target version is no longer ACTIVE",
                    context_digest=ctx_digest, input_digest=input_digest,
                )
            if self._current_version != target_version:
                err = RotationRaceError(
                    f"migration target moved from '{target_version}' to "
                    f"'{self._current_version}' while the batch was running"
                )
                return self._migrate_failure(
                    index, item_id, source_version, target_version, err,
                    detail="current version changed during migration",
                    context_digest=ctx_digest, input_digest=input_digest,
                )
            source_material = source_kv.key_material
            target_material = target_kv.key_material

        # 5. Idempotent fast path: already on target -> validate first, then
        #    return the unchanged token. Re-running a migrated batch is safe
        #    and fully explainable.
        if source_version == target_version:
            # Still prove authenticity so garbage on the current version is
            # reported rather than silently "kept".
            try:
                decrypt_envelope(source_material, envelope)
            except CiphertextTamperedError as err:
                return self._migrate_failure(
                    index, item_id, source_version, target_version, err,
                    detail="AEAD authentication failed",
                    context_digest=ctx_digest, input_digest=input_digest,
                )
            return self._migrate_success(
                index, item_id, source_version, target_version, token,
                status=MigrationStatus.ALREADY_CURRENT,
                detail="ciphertext already on the current version; verified unchanged",
                context_digest=ctx_digest, input_digest=input_digest,
            )

        # 6. Pure AEAD work outside the lock: decrypt old, re-encrypt new.
        try:
            plaintext = decrypt_envelope(source_material, envelope)
        except CiphertextTamperedError as err:
            return self._migrate_failure(
                index, item_id, source_version, target_version, err,
                detail="AEAD authentication failed",
                context_digest=ctx_digest, input_digest=input_digest,
            )
        new_envelope = encrypt_envelope(
            target_material, self._key_id, target_version, plaintext, envelope.context
        )
        new_token = new_envelope.to_token()
        # Discard the plaintext reference as soon as the token exists.
        del plaintext

        if self.migrate_pre_commit_hook is not None:
            # Hook may rotate/deactivate/revoke; failures in the hook itself
            # are treated as a migration failure rather than escaping.
            hook = self.migrate_pre_commit_hook
            hook(index, source_version, target_version)

        # 7. Commit gate: the target must STILL be current+ACTIVE, otherwise
        #    this brand-new token could become immediately unreadable.
        with self._lock:
            now_kv = self._ring.get(target_version)
            now_current = self._current_version
        committed = (
            now_current == target_version
            and now_kv is not None
            and now_kv.state is KeyState.ACTIVE
        )
        if not committed:
            # Classify by the sealed token's own key first: if THAT version is
            # revoked/deactivated, returning the token would hand out something
            # nobody (or only decrypters) can use — the stronger reason wins.
            if now_kv is not None and now_kv.state is KeyState.REVOKED:
                err = KeyRevokedError(target_version, operation="migration target encryption")
                detail = "target version revoked before migration commit"
            elif now_kv is not None and now_kv.state is KeyState.DEACTIVATED:
                err = KeyDeactivatedError(target_version, operation="migration target encryption")
                detail = "target version deactivated (current moved) before migration commit"
            else:
                err = RotationRaceError(
                    f"migration target moved from '{target_version}' to "
                    f"'{now_current}' before the item committed"
                )
                detail = "current version changed before migration commit"
            return self._migrate_failure(
                index, item_id, source_version, target_version, err,
                detail=detail, context_digest=ctx_digest, input_digest=input_digest,
            )

        return self._migrate_success(
            index, item_id, source_version, target_version, new_token,
            status=MigrationStatus.REENCRYPTED,
            detail=f"re-encrypted from '{source_version}' to '{target_version}'",
            context_digest=ctx_digest, input_digest=input_digest,
        )

    def _migrate_success(
        self,
        index: int,
        item_id: str | None,
        source_version: str,
        target_version: str,
        token: str,
        *,
        status: MigrationStatus,
        detail: str,
        context_digest: str | None,
        input_digest: str | None,
    ) -> MigrationItemResult:
        result = MigrationItemResult(
            index=index, item_id=item_id, status=status,
            source_version=source_version, target_version=target_version,
            ciphertext=token, error_code=None, reason=None,
        )
        self._audit.append(
            self._make_record(
                KeyOperation.MIGRATE, OperationResult.SUCCESS, target_version, None,
                detail=f"{status.value}: {detail}",
                context_digest=context_digest, input_digest=input_digest,
            )
        )
        logger.debug(
            "decision MIGRATE %s index=%d %s->%s ctx=%s input=%s",
            status.value, index, source_version, target_version,
            (context_digest or "")[:12], (input_digest or "")[:12],
        )
        return result

    def _migrate_failure(
        self,
        index: int,
        item_id: str | None,
        source_version: str | None,
        target_version: str,
        err: Exception,
        *,
        detail: str,
        context_digest: str | None,
        input_digest: str | None,
    ) -> MigrationItemResult:
        code = getattr(getattr(err, "code", None), "value", err.__class__.__name__)
        result = MigrationItemResult(
            index=index, item_id=item_id, status=MigrationStatus.FAILED,
            source_version=source_version, target_version=target_version,
            ciphertext=None, error_code=code, reason=detail,
        )
        self._audit.best_effort_append(
            self._make_record(
                KeyOperation.MIGRATE, OperationResult.FAILURE,
                source_version or target_version, code,
                detail=f"FAILED: {detail}",
                context_digest=context_digest, input_digest=input_digest,
            )
        )
        logger.debug(
            "decision MIGRATE FAILURE index=%d source=%s target=%s reason=%s "
            "ctx=%s input=%s",
            index, source_version, target_version, code,
            (context_digest or "")[:12], (input_digest or "")[:12],
        )
        return result

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    @property
    def key_id(self) -> str:
        return self._key_id

    def current_version(self) -> str:
        with self._lock:
            if self._current_version is None:
                raise NoActiveKeyError(self._key_id)
            return self._current_version

    def list_versions(self) -> list[VersionInfo]:
        with self._lock:
            return [
                VersionInfo(
                    version=kv.version,
                    state=kv.state,
                    created_at=kv.created_at,
                    is_current=(kv.version == self._current_version),
                )
                for kv in self._ring.values()
            ]

    def get_state(self, version: str) -> KeyState:
        with self._lock:
            kv = self._ring.get(version)
            if kv is None:
                raise KeyVersionNotFoundError(version)
            return kv.state

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _coerce_context(self, context: dict[str, str] | EncryptionContext) -> EncryptionContext:
        if isinstance(context, EncryptionContext):
            return context
        if context is None:
            return EncryptionContext({})
        if isinstance(context, dict):
            return EncryptionContext(context)
        raise TypeError("context must be a dict[str, str] or EncryptionContext")

    def _make_record(
        self,
        operation: KeyOperation,
        result: OperationResult,
        key_version: str | None,
        error_code: str | None,
        detail: str,
        context_digest: str | None,
        input_digest: str | None,
    ) -> AuditRecord:
        return AuditRecord(
            timestamp=_utc_now(),
            operation=operation,
            result=result,
            key_version=key_version,
            context_digest=context_digest,
            error_code=error_code,
            detail=detail,
            input_digest=input_digest,
        )

    def _failure_record(
        self,
        operation: KeyOperation,
        key_version: str | None,
        err: Exception,
        detail: str,
        context_digest: str | None = None,
        input_digest: str | None = None,
    ) -> None:
        code = getattr(getattr(err, "code", None), "value", err.__class__.__name__)
        # Failure records are best effort: the classified failure must reach
        # the caller even if the audit sink is broken.
        self._audit.best_effort_append(
            self._make_record(
                operation, OperationResult.FAILURE, key_version, code, detail,
                context_digest, input_digest,
            )
        )

    def _decision_log(
        self,
        operation: str,
        outcome: str,
        version: str | None,
        code: str | None,
        context_digest: str | None,
        input_digest: str | None,
    ) -> None:
        logger.debug(
            "decision %s %s version=%s reason=%s ctx=%s input=%s",
            operation, outcome, version, code,
            (context_digest or "")[:12], (input_digest or "")[:12],
        )


def _parse_envelope(token: str):
    # Thin wrapper kept module-level for readability of decrypt().
    from .models import EnvelopeCiphertext

    return EnvelopeCiphertext.from_token(token)
