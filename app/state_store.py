"""Durable key-ring state store (local disk only).

The key source (inline config / key file) provides the *initial* ring. Every
subsequent lifecycle outcome (rotate / deactivate / revoke) must survive a
restart, so the manager mirrors the full ring — versions, key material,
states and the current-version pointer — into a state store after each
transition.

Semantics
---------
* ``load()`` returns ``None`` when no snapshot exists yet (first boot):
  the manager then bootstraps from the key source and immediately saves a
  snapshot, so later restarts never fall back to stale source config.
* ``save()`` must be atomic and durable. :class:`FileStateStore` writes a
  temp file, fsyncs it, ``os.replace``-es it over the target and fsyncs the
  directory, so a crash never leaves a half-written snapshot.
* When ``save()`` fails the manager rolls its in-memory state back and
  reports :class:`StatePersistFailedError` — an operation is only allowed to
  succeed when its outcome is actually on disk.

No network IO: snapshots live in one local JSON file (mode 0600).
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import (
    ConfigurationError,
    PersistedStateInconsistentError,
    StatePersistFailedError,
)
from .models import KeyState, b64d, b64e

_KEY_SIZE = 32


@dataclass(frozen=True)
class VersionSnapshot:
    version: str
    key_material: bytes
    state: KeyState
    created_at: str


@dataclass(frozen=True)
class RingSnapshot:
    """A complete, restart-safe picture of one key ring."""

    key_id: str
    current_version: str
    versions: tuple[VersionSnapshot, ...]


class KeyStateStore(ABC):
    """Abstract durable store for ring snapshots."""

    @abstractmethod
    def load(self) -> RingSnapshot | None:
        """Return the persisted snapshot, or ``None`` when none exists."""
        raise NotImplementedError

    @abstractmethod
    def save(self, snapshot: RingSnapshot) -> None:
        """Atomically persist the snapshot or raise StatePersistFailedError."""
        raise NotImplementedError


class InMemoryStateStore(KeyStateStore):
    """Non-durable store (tests / explicitly ephemeral deployments).

    Outcomes survive only as long as the process; callers choosing this
    store accept that restarts re-bootstrap from the key source.
    """

    def __init__(self) -> None:
        self._snapshot: RingSnapshot | None = None

    def load(self) -> RingSnapshot | None:
        return self._snapshot

    def save(self, snapshot: RingSnapshot) -> None:
        self._snapshot = snapshot


class FileStateStore(KeyStateStore):
    """Snapshot persisted as one local JSON file, replaced atomically."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise ConfigurationError("state store path must be a non-empty string")
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    # ------------------------------------------------------------------ #
    def load(self) -> RingSnapshot | None:
        if not os.path.isfile(self._path):
            return None
        try:
            with open(self._path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(
                f"state store: cannot read snapshot '{self._path}': {exc}"
            ) from exc
        return self._parse(document)

    def _parse(self, document: object) -> RingSnapshot:
        where = f"state store '{self._path}'"
        if not isinstance(document, dict):
            raise ConfigurationError(f"{where}: snapshot must be a JSON object")
        key_id = document.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ConfigurationError(f"{where}: snapshot is missing a non-empty 'key_id'")
        current = document.get("current_version")
        if not isinstance(current, str) or not current:
            raise ConfigurationError(
                f"{where}: snapshot is missing a non-empty 'current_version'"
            )
        entries = document.get("versions")
        if not isinstance(entries, list) or not entries:
            raise ConfigurationError(f"{where}: 'versions' must be a non-empty list")

        versions: list[VersionSnapshot] = []
        seen: set[str] = set()
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ConfigurationError(f"{where}: version entry {index} must be an object")
            version = entry.get("version")
            if not isinstance(version, str) or not version:
                raise ConfigurationError(
                    f"{where}: version entry {index} is missing a non-empty 'version'"
                )
            if version in seen:
                raise ConfigurationError(f"{where}: duplicate version '{version}'")
            seen.add(version)
            raw_material = entry.get("key_material")
            if not isinstance(raw_material, str) or not raw_material:
                raise ConfigurationError(
                    f"{where}: version '{version}' is missing 'key_material'"
                )
            try:
                material = b64d(raw_material)
            except Exception as exc:
                raise ConfigurationError(
                    f"{where}: version '{version}' key material is not valid base64: {exc}"
                ) from exc
            if len(material) != _KEY_SIZE:
                raise ConfigurationError(
                    f"{where}: version '{version}' key material must decode to "
                    f"{_KEY_SIZE} bytes, got {len(material)}"
                )
            state_value = entry.get("state")
            try:
                state = KeyState(state_value)
            except ValueError as exc:
                raise ConfigurationError(
                    f"{where}: version '{version}' has unknown state {state_value!r}"
                ) from exc
            created_at = entry.get("created_at")
            if not isinstance(created_at, str) or not created_at:
                raise ConfigurationError(
                    f"{where}: version '{version}' is missing 'created_at'"
                )
            versions.append(
                VersionSnapshot(
                    version=version,
                    key_material=material,
                    state=state,
                    created_at=created_at,
                )
            )

        if current not in seen:
            raise ConfigurationError(
                f"{where}: current_version '{current}' is not among the versions"
            )
        current_state = next(v.state for v in versions if v.version == current)
        if current_state is not KeyState.ACTIVE:
            raise PersistedStateInconsistentError(
                f"{where}: current version '{current}' is {current_state.value}; "
                "a snapshot's current version must be ACTIVE — the persisted "
                "state is inconsistent and the service refuses to start"
            )
        return RingSnapshot(
            key_id=key_id, current_version=current, versions=tuple(versions)
        )

    # ------------------------------------------------------------------ #
    def save(self, snapshot: RingSnapshot) -> None:
        document = {
            "key_id": snapshot.key_id,
            "current_version": snapshot.current_version,
            "versions": [
                {
                    "version": v.version,
                    "key_material": b64e(v.key_material),
                    "state": v.state.value,
                    "created_at": v.created_at,
                }
                for v in snapshot.versions
            ],
        }
        payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        directory = os.path.dirname(os.path.abspath(self._path))
        temp_path = f"{self._path}.tmp.{os.getpid()}"
        try:
            os.makedirs(directory, exist_ok=True)
            with open(temp_path, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self._path)
            # fsync the directory so the rename itself is durable.
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except OSError:
                pass
            raise StatePersistFailedError(
                f"cannot persist key-ring state to '{self._path}': {exc}"
            ) from exc
