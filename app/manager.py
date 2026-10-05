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
    AuditWriteFailedError,
    CiphertextInvalidError,
    CiphertextTamperedError,
    ConfigurationError,
    ContextMismatchError,
    InvalidLifecycleTransitionError,
    KeyDeactivatedError,
    KeyIdMismatchError,
    KeyManagementError,
    KeyRevokedError,
    KeyVersionNotFoundError,
    NoActiveKeyError,
    PersistedStateInconsistentError,
    RotationRaceError,
)
from .key_source import LocalKeySource, generate_local_key
from .models import (
    EncryptionContext,
    KeyOperation,
    KeyState,
    KeyVersion,
    MigrationItemResult,
    MigrationReport,
    MigrationStatus,
    OperationResult,
    AuditRecord,
    digest_hex,
)
from .state_store import (
    InMemoryStateStore,
    KeyStateStore,
    RingSnapshot,
    VersionSnapshot,
)

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
        state_store: KeyStateStore | None = None,
    ) -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ConfigurationError("key id must be a non-empty string")
        self._key_id = key_id
        self._key_source = key_source
        self._audit = audit_logger
        self._store = state_store if state_store is not None else InMemoryStateStore()
        self._lock = threading.RLock()
        self._ring: dict[str, KeyVersion] = {}
        self._current_version: str | None = None
        self._sequence = 0
        self._bootstrap()

    # ------------------------------------------------------------------ #
    # Bootstrap
    # ------------------------------------------------------------------ #
    def _bootstrap(self) -> None:
        """Load the ring: persisted snapshot wins over the key source.

        A snapshot in the state store reflects every lifecycle outcome since
        first boot, so it is authoritative; the key source is only consulted
        on the very first boot (no snapshot yet), and the resulting ring is
        immediately persisted so later restarts never fall back to stale
        source configuration.
        """
        snapshot = self._store.load()
        if snapshot is not None:
            if snapshot.key_id != self._key_id:
                raise ConfigurationError(
                    f"state store snapshot belongs to key id '{snapshot.key_id}' "
                    f"but this service is configured for '{self._key_id}'"
                )
            self._validate_snapshot_invariants(snapshot)
            self._ring = {
                v.version: KeyVersion(
                    version=v.version,
                    key_material=v.key_material,
                    state=v.state,
                    created_at=v.created_at,
                )
                for v in snapshot.versions
            }
            self._current_version = snapshot.current_version
            self._sequence = self._initial_sequence([v.version for v in snapshot.versions])
            logger.info(
                "key manager restored from state store key_id=%s current=%s versions=%d",
                self._key_id, self._current_version, len(self._ring),
            )
            return

        sourced = self._key_source.load()  # raises ConfigurationError on bad config

        ring: dict[str, KeyVersion] = {}
        for sk in sourced:
            if sk.version in ring:  # defensive; source already validates
                raise ConfigurationError(f"duplicate key version '{sk.version}' in source")
            ring[sk.version] = KeyVersion(
                version=sk.version,
                key_material=sk.key_material,
                state=sk.state,
                created_at=_utc_now(),
            )

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

        self._ring = ring
        self._current_version = active_versions[0]
        # Sequence starts above any trailing integer suffix so generated
        # labels never collide with configured ones (v1, v2, 3, ...).
        self._sequence = self._initial_sequence([s.version for s in sourced])
        # Persist the initial ring so first-boot state is also restart-safe;
        # if this fails the service refuses to start rather than run with
        # outcomes that would silently vanish on restart.
        self._persist()
        logger.info(
            "key manager bootstrapped key_id=%s current=%s versions=%d",
            self._key_id, self._current_version, len(self._ring),
        )

    def _validate_snapshot_invariants(self, snapshot: RingSnapshot) -> None:
        """Refuse to boot from a self-contradictory persisted ring.

        Same invariant enforced when first bootstrapping from the key
        source: at any moment there is exactly one ACTIVE version and it is
        the current one. A snapshot that violates this (e.g. an old version
        left ACTIVE alongside the current one after manual edits, or a
        current pointer that does not match the ACTIVE version) is
        inconsistent persisted state — startup fails with
        STATE_INCONSISTENT. The snapshot is never silently repaired,
        auto-healed or rolled back to an older version.
        """
        active = [v.version for v in snapshot.versions if v.state is KeyState.ACTIVE]
        if len(active) != 1:
            raise PersistedStateInconsistentError(
                f"persisted key-ring state for key '{snapshot.key_id}' has "
                f"{len(active)} ACTIVE versions {active}; exactly one version "
                "may be ACTIVE (the current one). The snapshot is "
                "inconsistent: repair or remove it before restarting."
            )
        if snapshot.current_version != active[0]:
            raise PersistedStateInconsistentError(
                f"persisted key-ring state for key '{snapshot.key_id}' marks "
                f"'{snapshot.current_version}' as current but the only ACTIVE "
                f"version is '{active[0]}'. The snapshot is inconsistent: "
                "repair or remove it before restarting."
            )

    @staticmethod
    def _initial_sequence(labels: list[str]) -> int:
        highest = 0
        for label in labels:
            if label.startswith("v") and label[1:].isdigit():
                highest = max(highest, int(label[1:]))
        return highest

    # ------------------------------------------------------------------ #
    # Persistence helpers
    # ------------------------------------------------------------------ #
    def _snapshot(self) -> RingSnapshot:
        """Capture the current ring (caller must hold the lock)."""
        assert self._current_version is not None
        return RingSnapshot(
            key_id=self._key_id,
            current_version=self._current_version,
            versions=tuple(
                VersionSnapshot(
                    version=kv.version,
                    key_material=kv.key_material,
                    state=kv.state,
                    created_at=kv.created_at,
                )
                for kv in self._ring.values()
            ),
        )

    def _persist(self) -> None:
        """Durably store the current ring or raise StatePersistFailedError."""
        self._store.save(self._snapshot())

    def _persist_best_effort(self) -> None:
        """Rollback helper: try to restore the persisted state, log on failure."""
        try:
            self._persist()
        except Exception as exc:  # noqa: BLE001 - rollback is best effort
            logger.error("failed to re-persist rolled-back key-ring state: %s", exc)

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
                # The transition only counts once it is durably persisted;
                # a store failure rolls the whole rotation back.
                self._persist()
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
                # Roll the state transition back so audit truth == state truth.
                self._current_version = old_version
                if old_kv is not None:
                    self._ring[old_version] = old_kv
                del self._ring[new_label]
                self._sequence -= 1
                self._persist_best_effort()  # keep disk == rolled-back memory
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
                self._persist()
            except Exception:
                self._ring[version] = kv  # rollback, then surface persist failure
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
                self._ring[version] = kv  # rollback, then surface audit failure
                self._persist_best_effort()  # keep disk == rolled-back memory
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
    # Migration (re-encrypt historical ciphertexts onto the current key)
    # ------------------------------------------------------------------ #
    def migrate(
        self,
        tokens: list[str],
        context: dict[str, str] | EncryptionContext | None = None,
    ) -> MigrationReport:
        """Re-encrypt a batch of tokens onto the current ACTIVE version.

        The caller supplies ciphertexts only — never plaintext. The plaintext
        exists only transiently in memory inside this method; results carry
        new tokens and digests, never plaintext.

        * ``context=None``: each token's bound context is reused as-is, so
          migrated tokens keep decrypting with their original context.
        * ``context={...}``: an additional guard — tokens whose bound context
          differs fail that item with CONTEXT_MISMATCH.

        Every input token produces exactly one item in the report, classified
        as MIGRATED / ALREADY_CURRENT / FAILED (with a stable error code).
        Each item is processed atomically with respect to lifecycle
        transitions: if the target version is deactivated/revoked mid-batch,
        the affected items fail explicitly instead of producing ciphertext
        that no key can decrypt. Re-migrating an already-migrated token is a
        no-op (ALREADY_CURRENT, original token returned), so re-running the
        same batch is idempotent.
        """
        if isinstance(context, (dict, EncryptionContext)):
            expected_ctx: EncryptionContext | None = self._coerce_context(context)
        elif context is None:
            expected_ctx = None
        else:
            raise TypeError("context must be a dict[str, str], EncryptionContext or None")
        if not isinstance(tokens, (list, tuple)):
            raise TypeError("tokens must be a list of envelope tokens")

        items = [
            self._migrate_one(index, token, expected_ctx)
            for index, token in enumerate(tokens)
        ]
        report = MigrationReport(items=tuple(items))
        logger.info(
            "migration batch key_id=%s total=%d migrated=%d already_current=%d failed=%d",
            self._key_id, report.total, report.migrated,
            report.already_current, report.failed,
        )
        return report

    def _migrate_one(
        self,
        index: int,
        token: object,
        expected_ctx: EncryptionContext | None,
    ) -> MigrationItemResult:
        token_digest = digest_hex(token.encode("utf-8")) if isinstance(token, str) \
            else digest_hex(repr(token).encode("utf-8"))

        def failed(err: KeyManagementError, version: str | None, detail: str,
                   target: str | None = None) -> MigrationItemResult:
            self._decision_log("MIGRATE", "failure", version, err.code.value,
                               expected_ctx.digest() if expected_ctx else None,
                               token_digest)
            self._failure_record(
                KeyOperation.MIGRATE, version, err, detail=detail,
                context_digest=expected_ctx.digest() if expected_ctx else None,
                input_digest=token_digest,
            )
            return MigrationItemResult(
                index=index, status=MigrationStatus.FAILED, key_version=version,
                target_version=target, ciphertext=None,
                error_code=err.code.value, detail=detail,
                input_digest=token_digest,
            )

        # 1. Structural validation.
        try:
            envelope = _parse_envelope(token)  # type: ignore[arg-type]
        except CiphertextInvalidError as err:
            return failed(err, getattr(err, "key_version", None), err.message)
        except (TypeError, AttributeError) as exc:
            err = CiphertextInvalidError(f"token must be a string: {exc}")
            return failed(err, None, err.message)

        version = envelope.key_version

        # 2. Key-identity binding.
        if envelope.key_id != self._key_id:
            err = KeyIdMismatchError(version, expected=self._key_id,
                                     actual=envelope.key_id)
            return failed(err, version, err.message)

        # 3. Optional context guard; otherwise reuse the bound context.
        if expected_ctx is not None and envelope.context != expected_ctx:
            err = ContextMismatchError(version)
            return failed(err, version,
                          "provided context differs from bound context")
        ctx = envelope.context

        # The remainder must be atomic w.r.t. lifecycle transitions: the
        # target version is validated and used under the same lock, so a
        # concurrent deactivate/revoke/rotate can never leave us emitting a
        # ciphertext bound to an unusable target.
        with self._lock:
            # 4. Source version must exist and be decrypt-capable.
            source_kv = self._ring.get(version)
            if source_kv is None:
                err = KeyVersionNotFoundError(version)
                return failed(err, version,
                              "embedded version absent from key ring")
            if source_kv.state is KeyState.REVOKED:
                err = KeyRevokedError(version, operation="migration")
                return failed(err, version, "source version revoked")
            if not source_kv.is_usable_for_decrypt():
                err = KeyDeactivatedError(version, operation="migration")
                return failed(err, version, "source version not decrypt-capable")

            # 5. Target is the current version; it must be ACTIVE right now.
            target_version = self._current_version
            if target_version is None:
                err = NoActiveKeyError(self._key_id)
                return failed(err, version, "no current active key to migrate to")
            target_kv = self._ring[target_version]
            if target_kv.state is KeyState.REVOKED:
                err = KeyRevokedError(target_version, operation="migration target")
                return failed(err, version, "target version revoked",
                              target=target_version)
            if not target_kv.is_usable_for_encrypt():
                err = KeyDeactivatedError(target_version, operation="migration target")
                return failed(err, version, "target version not active",
                              target=target_version)

            # 6. Idempotent no-op: already on the current version. The token
            #    is still AEAD-verified first — migration never vouches for a
            #    forged "already current" token.
            if version == target_version:
                try:
                    decrypt_envelope(target_kv.key_material, envelope)
                except CiphertextTamperedError as err:
                    return failed(err, version, "AEAD authentication failed",
                                  target=target_version)
                self._record_migrate_success(
                    version, target_version, ctx, token_digest,
                    detail="token already on current version; returned unchanged",
                )
                self._decision_log("MIGRATE", "already-current", version, None,
                                   ctx.digest(), token_digest)
                return MigrationItemResult(
                    index=index, status=MigrationStatus.ALREADY_CURRENT,
                    key_version=version, target_version=target_version,
                    ciphertext=token if isinstance(token, str) else None,
                    error_code=None,
                    detail="already encrypted under the current version",
                    input_digest=token_digest,
                )

            # 7. Decrypt with the source key, re-encrypt under the target key.
            try:
                plaintext = decrypt_envelope(source_kv.key_material, envelope)
            except CiphertextTamperedError as err:
                return failed(err, version, "AEAD authentication failed",
                              target=target_version)
            new_token = encrypt_envelope(
                target_kv.key_material, self._key_id, target_version,
                plaintext, ctx,
            ).to_token()
            del plaintext  # never leaves this scope

        # 8. Success is only reported once its audit record is durable.
        try:
            self._record_migrate_success(
                version, target_version, ctx, token_digest,
                detail=f"re-encrypted from '{version}' to '{target_version}'",
            )
        except Exception as exc:  # noqa: BLE001 - audit failure fails the item
            audit_err = AuditWriteFailedError(
                f"migration succeeded cryptographically but its audit record "
                f"could not be persisted: {exc}"
            )
            self._failure_record(
                KeyOperation.MIGRATE, version, audit_err,
                detail="audit write failed; new token withheld",
                context_digest=ctx.digest(), input_digest=token_digest,
            )
            return MigrationItemResult(
                index=index, status=MigrationStatus.FAILED, key_version=version,
                target_version=target_version, ciphertext=None,
                error_code=audit_err.code.value,
                detail="audit write failed; migration result withheld",
                input_digest=token_digest,
            )
        self._decision_log("MIGRATE", "success", version, None,
                           ctx.digest(), token_digest)
        return MigrationItemResult(
            index=index, status=MigrationStatus.MIGRATED, key_version=version,
            target_version=target_version, ciphertext=new_token, error_code=None,
            detail=f"re-encrypted from '{version}' to '{target_version}'",
            input_digest=token_digest,
        )

    def _record_migrate_success(
        self,
        source_version: str,
        target_version: str,
        ctx: EncryptionContext,
        token_digest: str,
        *,
        detail: str,
    ) -> None:
        self._audit.append(
            self._make_record(
                KeyOperation.MIGRATE, OperationResult.SUCCESS, source_version, None,
                detail=f"{detail} (target={target_version})",
                context_digest=ctx.digest(), input_digest=token_digest,
            )
        )

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
