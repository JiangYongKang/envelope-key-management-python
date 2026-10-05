"""Classified error types for key management operations.

Every failure path raises an exception carrying a stable, machine-readable
:class:`ErrorCode`, so every entry point (library call, HTTP API, test log)
can report the same distinguishable reason.
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    """Stable failure codes for envelope-key operations."""

    CONFIG_INVALID = "CONFIG_INVALID"
    KEY_ID_MISMATCH = "KEY_ID_MISMATCH"
    KEY_VERSION_NOT_FOUND = "KEY_VERSION_NOT_FOUND"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_DEACTIVATED = "KEY_DEACTIVATED"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    CIPHERTEXT_INVALID = "CIPHERTEXT_INVALID"
    CIPHERTEXT_TAMPERED = "CIPHERTEXT_TAMPERED"
    ROTATION_RACE = "ROTATION_RACE"
    AUDIT_WRITE_FAILED = "AUDIT_WRITE_FAILED"
    STATE_PERSIST_FAILED = "STATE_PERSIST_FAILED"
    STATE_INCONSISTENT = "STATE_INCONSISTENT"
    NO_ACTIVE_KEY = "NO_ACTIVE_KEY"
    INVALID_LIFECYCLE_TRANSITION = "INVALID_LIFECYCLE_TRANSITION"


class KeyManagementError(Exception):
    """Base class for all classified key-management failures."""

    def __init__(self, code: ErrorCode, message: str, *, key_version: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.key_version = key_version

    def __str__(self) -> str:
        prefix = f"[{self.code.value}]"
        if self.key_version is not None:
            prefix += f"[key_version={self.key_version}]"
        return f"{prefix} {self.message}"


class ConfigurationError(KeyManagementError):
    """Raised when local key-source configuration is missing or incomplete."""

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.CONFIG_INVALID, message)


class KeyVersionNotFoundError(KeyManagementError):
    def __init__(self, version: str) -> None:
        super().__init__(
            ErrorCode.KEY_VERSION_NOT_FOUND,
            f"key version '{version}' does not exist",
            key_version=version,
        )


class KeyRevokedError(KeyManagementError):
    def __init__(self, version: str, *, operation: str) -> None:
        super().__init__(
            ErrorCode.KEY_REVOKED,
            f"key version '{version}' is revoked; {operation} is forbidden",
            key_version=version,
        )
        self.operation = operation


class KeyDeactivatedError(KeyManagementError):
    def __init__(self, version: str, *, operation: str) -> None:
        super().__init__(
            ErrorCode.KEY_DEACTIVATED,
            f"key version '{version}' is deactivated; {operation} is forbidden",
            key_version=version,
        )
        self.operation = operation


class ContextMismatchError(KeyManagementError):
    def __init__(self, version: str) -> None:
        super().__init__(
            ErrorCode.CONTEXT_MISMATCH,
            "encryption context does not match the context bound to the ciphertext",
            key_version=version,
        )


class CiphertextInvalidError(KeyManagementError):
    def __init__(self, reason: str, *, version: str | None = None) -> None:
        super().__init__(
            ErrorCode.CIPHERTEXT_INVALID,
            f"ciphertext is malformed: {reason}",
            key_version=version,
        )
        self.reason = reason


class CiphertextTamperedError(KeyManagementError):
    def __init__(self, version: str) -> None:
        super().__init__(
            ErrorCode.CIPHERTEXT_TAMPERED,
            "ciphertext failed authentication and has been tampered with",
            key_version=version,
        )


class RotationRaceError(KeyManagementError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.ROTATION_RACE, message)


class AuditWriteFailedError(KeyManagementError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.AUDIT_WRITE_FAILED, message)


class StatePersistFailedError(KeyManagementError):
    """Raised when a lifecycle/migration outcome cannot be durably persisted.

    The in-memory state is rolled back before this is raised, so the caller
    never observes "success at runtime, lost after restart".
    """

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.STATE_PERSIST_FAILED, message)


class PersistedStateInconsistentError(ConfigurationError):
    """Raised when a persisted key-ring snapshot violates a ring invariant.

    Distinct from plain CONFIG_INVALID so operators can tell "the persisted
    state on disk is self-contradictory" apart from "the configuration is
    missing/incomplete". The service refuses to start; the snapshot is never
    silently repaired or rolled back to an older version.
    """

    def __init__(self, message: str) -> None:
        KeyManagementError.__init__(self, ErrorCode.STATE_INCONSISTENT, message)


class NoActiveKeyError(KeyManagementError):
    """Raised on encrypt when no ACTIVE key version exists."""

    def __init__(self, key_id: str) -> None:
        super().__init__(
            ErrorCode.NO_ACTIVE_KEY,
            f"no active key version exists for key '{key_id}'; rotate or configure one",
        )


class InvalidLifecycleTransitionError(KeyManagementError):
    """Raised when a state transition is not allowed (e.g. reviving revoked)."""

    def __init__(self, version: str, *, from_state: str, to_state: str) -> None:
        super().__init__(
            ErrorCode.INVALID_LIFECYCLE_TRANSITION,
            f"cannot transition key version '{version}' from {from_state} to {to_state}",
            key_version=version,
        )
        self.from_state = from_state
        self.to_state = to_state


class KeyIdMismatchError(KeyManagementError):
    """Token was minted for a different key ring (key id) than this service."""

    def __init__(self, version: str, *, expected: str, actual: str) -> None:
        super().__init__(
            ErrorCode.KEY_ID_MISMATCH,
            f"token belongs to key id '{actual}' but this service manages '{expected}'",
            key_version=version,
        )
        self.expected = expected
        self.actual = actual
