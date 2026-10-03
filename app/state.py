"""Durable local persistence of the key ring and current-version pointer.

Lifecycle changes (rotate / deactivate / revoke) only count as committed once
the whole ring snapshot has been atomically written and fsynced to a local
JSON file; otherwise the in-memory change is rolled back and the operation
fails with STATE_PERSIST_FAILED. On startup a previously persisted snapshot is
preferred over the static key source, so the current version never regresses
after a restart.

The state file holds rotated key material in the same trust boundary as the
configured local key file: it is written to the local filesystem with 0600
permissions and never sent anywhere. No plaintext data is ever stored here.

File shape::

    {
      "format": "ekm-state-v1",
      "key_id": "primary",
      "current_version": "v3",
      "sequence": 3,
      "versions": [
        {"version": "v1", "key_material": "<b64url 32 bytes>",
         "state": "DEACTIVATED", "created_at": "..."},
        ...
      ]
    }

Persistence uses write-temp + fsync + atomic ``os.replace`` + directory
fsync, so a crash leaves either the previous snapshot or the new one — never
a torn file.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Protocol

from .errors import StateInvalidError, StatePersistFailedError
from .models import KeyState, KeyVersion, b64d, b64e

STATE_FORMAT = "ekm-state-v1"
_KEY_SIZE = 32


@dataclass(frozen=True)
class PersistedState:
    """Everything the manager needs to reconstruct its in-memory world."""

    key_id: str
    current_version: str
    sequence: int
    versions: list[KeyVersion]


class StateStore(Protocol):
    """Durable storage for the key-ring snapshot."""

    def load(self) -> PersistedState | None:
        """Return the persisted state; None when nothing has been stored yet."""
        ...

    def save(
        self,
        *,
        key_id: str,
        current_version: str,
        sequence: int,
        versions: list[KeyVersion],
    ) -> None:
        """Atomically persist the complete snapshot (temp + fsync + rename)."""
        ...


class InMemoryStateStore:
    """Ephemeral store (tests / explicitly non-durable deployments)."""

    def __init__(self) -> None:
        self._state: PersistedState | None = None

    def load(self) -> PersistedState | None:
        return self._state

    def save(
        self,
        *,
        key_id: str,
        current_version: str,
        sequence: int,
        versions: list[KeyVersion],
    ) -> None:
        self._state = PersistedState(
            key_id=key_id,
            current_version=current_version,
            sequence=sequence,
            versions=list(versions),
        )


def _document_to_state(document: object, *, path: str) -> PersistedState:
    where = f"state file '{path}'"
    if not isinstance(document, dict):
        raise StateInvalidError(f"{where}: top-level payload must be a JSON object")
    if document.get("format") != STATE_FORMAT:
        raise StateInvalidError(
            f"{where}: missing or unsupported format marker {document.get('format')!r}"
        )
    key_id = document.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise StateInvalidError(f"{where}: missing non-empty 'key_id'")
    current = document.get("current_version")
    if not isinstance(current, str) or not current:
        raise StateInvalidError(f"{where}: missing non-empty 'current_version'")
    sequence = document.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise StateInvalidError(f"{where}: 'sequence' must be a non-negative integer")
    raw_versions = document.get("versions")
    if not isinstance(raw_versions, list) or not raw_versions:
        raise StateInvalidError(f"{where}: 'versions' must be a non-empty list")

    versions: list[KeyVersion] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw_versions):
        if not isinstance(entry, dict):
            raise StateInvalidError(f"{where}: version entry {index} must be an object")
        label = entry.get("version")
        if not isinstance(label, str) or not label:
            raise StateInvalidError(f"{where}: version entry {index} has no 'version'")
        if label in seen:
            raise StateInvalidError(f"{where}: duplicate version '{label}'")
        seen.add(label)
        material_text = entry.get("key_material")
        if not isinstance(material_text, str):
            raise StateInvalidError(f"{where}: version '{label}' has no 'key_material'")
        try:
            material = b64d(material_text)
        except ValueError as exc:
            raise StateInvalidError(
                f"{where}: version '{label}' material is not valid base64: {exc}"
            ) from exc
        if len(material) != _KEY_SIZE:
            raise StateInvalidError(
                f"{where}: version '{label}' material must be {_KEY_SIZE} bytes, "
                f"got {len(material)}"
            )
        state_text = entry.get("state")
        try:
            state = KeyState(str(state_text))
        except ValueError as exc:
            raise StateInvalidError(
                f"{where}: version '{label}' has unknown state {state_text!r}"
            ) from exc
        created_at = entry.get("created_at")
        if not isinstance(created_at, str) or not created_at:
            raise StateInvalidError(
                f"{where}: version '{label}' has no 'created_at' timestamp"
            )
        versions.append(
            KeyVersion(
                version=label,
                key_material=material,
                state=state,
                created_at=created_at,
            )
        )

    labels = {v.version for v in versions}
    if current not in labels:
        raise StateInvalidError(
            f"{where}: current_version '{current}' is absent from the ring"
        )
    active = [v.version for v in versions if v.state is KeyState.ACTIVE]
    if active != [current]:
        raise StateInvalidError(
            f"{where}: exactly the current version '{current}' must be ACTIVE, "
            f"found ACTIVE={active}"
        )
    # Rotation labels generated after load must never collide with stored ones.
    highest = 0
    for label in labels:
        if label.startswith("v") and label[1:].isdigit():
            highest = max(highest, int(label[1:]))
    if sequence < highest:
        raise StateInvalidError(
            f"{where}: sequence {sequence} is below highest v-label v{highest}"
        )
    return PersistedState(
        key_id=key_id,
        current_version=current,
        sequence=sequence,
        versions=versions,
    )


class FileStateStore:
    """Atomically persisted JSON snapshot on the local filesystem."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            raise StateInvalidError("state path must be a non-empty string")
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    def load(self) -> PersistedState | None:
        if not os.path.isfile(self._path):
            return None
        try:
            with open(self._path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise StateInvalidError(f"cannot read state file '{self._path}': {exc}") from exc
        return _document_to_state(document, path=self._path)

    def save(
        self,
        *,
        key_id: str,
        current_version: str,
        sequence: int,
        versions: list[KeyVersion],
    ) -> None:
        document = {
            "format": STATE_FORMAT,
            "key_id": key_id,
            "current_version": current_version,
            "sequence": sequence,
            "versions": [
                {
                    "version": kv.version,
                    "key_material": b64e(kv.key_material),
                    "state": kv.state.value,
                    "created_at": kv.created_at,
                }
                for kv in versions
            ],
        }
        directory = os.path.dirname(os.path.abspath(self._path))
        try:
            os.makedirs(directory, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(
                prefix=".state-", suffix=".tmp", dir=directory
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(document, handle, sort_keys=True, ensure_ascii=False)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(tmp_path, 0o600)
                os.replace(tmp_path, self._path)
                self._fsync_directory(directory)
            except BaseException:
                # Never leave a temp file behind; the old snapshot stays live.
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as exc:
            raise StatePersistFailedError(
                f"cannot durably persist state to '{self._path}': {exc}"
            ) from exc

    @staticmethod
    def _fsync_directory(directory: str) -> None:
        try:
            dir_fd = os.open(directory, os.O_RDONLY)
        except OSError:
            return  # directory fsync is best effort (e.g. some platforms)
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)
