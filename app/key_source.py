"""Configurable *local* key material sources.

Key material may only originate from the local machine: either an explicit
inline value in local application configuration, or a local file on disk.
External KMS / network sources are deliberately not implemented.

Incomplete configuration is rejected with :class:`ConfigurationError` —
a missing key source never causes the service to invent a default key.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import ConfigurationError
from .models import KeyState, b64d

_KEY_SIZE = 32  # AES-256


@dataclass(frozen=True)
class SourcedKey:
    version: str
    key_material: bytes
    state: KeyState = KeyState.ACTIVE


def _decode_material(raw: object, *, where: str, index: int) -> bytes:
    if not isinstance(raw, str) or not raw:
        raise ConfigurationError(
            f"{where}: key version at index {index} is missing a non-empty "
            f"'key_material' field (base64url encoded 32-byte key)"
        )
    try:
        material = b64d(raw)
    except Exception as exc:
        raise ConfigurationError(
            f"{where}: key material at index {index} is not valid base64: {exc}"
        ) from exc
    if len(material) != _KEY_SIZE:
        raise ConfigurationError(
            f"{where}: key material at index {index} must decode to exactly "
            f"{_KEY_SIZE} bytes, got {len(material)}"
        )
    return material


def _parse_version_entry(entry: object, *, where: str, index: int) -> SourcedKey:
    if not isinstance(entry, dict):
        raise ConfigurationError(f"{where}: key entry at index {index} must be an object")
    version = entry.get("version")
    if not isinstance(version, str) or not version:
        raise ConfigurationError(
            f"{where}: key entry at index {index} is missing a non-empty 'version'"
        )
    material = _decode_material(entry.get("key_material"), where=where, index=index)
    state_value = entry.get("state", KeyState.ACTIVE.value)
    if not isinstance(state_value, str):
        raise ConfigurationError(f"{where}: state of version '{version}' must be a string")
    try:
        state = KeyState(state_value)
    except ValueError as exc:
        raise ConfigurationError(
            f"{where}: version '{version}' has unknown state {state_value!r}; "
            f"expected one of {[s.value for s in KeyState]}"
        ) from exc
    return SourcedKey(version=version, key_material=material, state=state)


def parse_versions(entries: object, *, where: str) -> list[SourcedKey]:
    """Validate the common 'versions' list used by inline/file sources."""
    if not isinstance(entries, list) or not entries:
        raise ConfigurationError(
            f"{where}: 'versions' must be a non-empty list of key entries"
        )
    parsed = [_parse_version_entry(entry, where=where, index=i) for i, entry in enumerate(entries)]
    seen: set[str] = set()
    for sk in parsed:
        if sk.version in seen:
            raise ConfigurationError(f"{where}: duplicate key version '{sk.version}'")
        seen.add(sk.version)
    return parsed


class LocalKeySource(ABC):
    """Abstract source of raw key material; implementations are always local."""

    @abstractmethod
    def load(self) -> list[SourcedKey]:
        """Return all locally configured key versions, oldest first.

        Raises :class:`ConfigurationError` when configuration is missing or
        incomplete (never silently substitutes a default key).
        """
        raise NotImplementedError


class InlineKeySource(LocalKeySource):
    """Key material supplied directly from local application configuration.

    Expected shape::

        [{"version": "v1", "key_material": "<base64url 32 bytes>",
          "state": "ACTIVE"}]
    """

    def __init__(self, versions: list[dict[str, object]]) -> None:
        self._versions = versions

    def load(self) -> list[SourcedKey]:
        return parse_versions(self._versions, where="inline key source")


class FileKeySource(LocalKeySource):
    """Key material loaded from a local JSON file, never from the network."""

    def __init__(self, path: str) -> None:
        self._path = path

    def load(self) -> list[SourcedKey]:
        if not isinstance(self._path, str) or not self._path:
            raise ConfigurationError("file key source: path is empty")
        if not os.path.isfile(self._path):
            raise ConfigurationError(
                f"file key source: key file '{self._path}' does not exist"
            )
        try:
            with open(self._path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError(
                f"file key source: cannot read '{self._path}': {exc}"
            ) from exc
        if not isinstance(document, dict):
            raise ConfigurationError(
                f"file key source: '{self._path}' must contain a JSON object"
            )
        return parse_versions(document.get("versions"), where=f"file key source '{self._path}'")


def generate_local_key(num_bytes: int = _KEY_SIZE) -> bytes:
    """Generate a fresh local random key (bootstrap / development helper).

    Uses the operating system CSPRNG. It does NOT contact any service; the
    caller is responsible for placing the key into local configuration or
    local storage explicitly.
    """
    if not isinstance(num_bytes, int) or num_bytes <= 0:
        raise ValueError("num_bytes must be a positive integer")
    return os.urandom(num_bytes)
