"""Local configuration loading and service construction.

Configuration sources (explicitly local only):

1. ``EKM_CONFIG_FILE`` -> path to a local JSON file of the shape::

       {
         "key_id": "primary",
         "key_source": {"type": "file", "path": "/etc/ekm/keys.json"}
                        | {"type": "inline", "versions": [...]},
         "audit_path": "/var/log/ekm/audit.jsonl"   # optional
       }

2. Environment shorthand for inline keys and a local key file::

       EKM_KEY_ID=primary
       EKM_INLINE_KEYS_JSON_FILE=./local-keys.json   (JSON list of versions)
       EKM_KEY_FILE=./local-keys.json                ({"versions": [...]})
       EKM_AUDIT_PATH=./audit.jsonl                  (optional)

There is no network source and no hard-coded default key: if no source can be
resolved, or the source is incomplete, :class:`ConfigurationError` is raised.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .audit import AuditLogger, NullAuditLogger
from .errors import ConfigurationError
from .key_source import FileKeySource, InlineKeySource, LocalKeySource
from .manager import KeyManager


@dataclass(frozen=True)
class Settings:
    key_id: str
    key_source: LocalKeySource
    audit_path: str | None


def _read_json_file(path: str, *, what: str) -> object:
    if not os.path.isfile(path):
        raise ConfigurationError(f"{what} file '{path}' does not exist")
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot read {what} file '{path}': {exc}") from exc


def _build_key_source(spec: object) -> LocalKeySource:
    if not isinstance(spec, dict):
        raise ConfigurationError("'key_source' must be an object with a 'type' field")
    kind = spec.get("type")
    if kind == "inline":
        return InlineKeySource(spec.get("versions"))  # type: ignore[arg-type]
    if kind == "file":
        path = spec.get("path")
        if not isinstance(path, str) or not path:
            raise ConfigurationError("file key source requires a non-empty 'path'")
        return FileKeySource(path)
    raise ConfigurationError(
        f"unsupported key source type {kind!r}; only local 'inline'/'file' are allowed"
    )


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Build settings from the process environment (or an injected mapping)."""
    environ = os.environ if env is None else env
    key_id = environ.get("EKM_KEY_ID", "primary")

    config_file = environ.get("EKM_CONFIG_FILE")
    if config_file:
        document = _read_json_file(config_file, what="config")
        if not isinstance(document, dict):
            raise ConfigurationError(f"config file '{config_file}' must contain an object")
        cfg_key_id = document.get("key_id")
        if not isinstance(cfg_key_id, str) or not cfg_key_id:
            raise ConfigurationError("config file is missing a non-empty 'key_id'")
        if "key_source" not in document:
            raise ConfigurationError("config file is missing 'key_source'")
        audit_path = document.get("audit_path")
        if audit_path is not None and (not isinstance(audit_path, str) or not audit_path):
            raise ConfigurationError("'audit_path' must be a non-empty string when provided")
        return Settings(
            key_id=cfg_key_id,
            key_source=_build_key_source(document["key_source"]),
            audit_path=audit_path,
        )

    inline_keys_file = environ.get("EKM_INLINE_KEYS_JSON_FILE")
    key_file = environ.get("EKM_KEY_FILE")
    if inline_keys_file and key_file:
        raise ConfigurationError(
            "EKM_INLINE_KEYS_JSON_FILE and EKM_KEY_FILE are mutually exclusive"
        )
    if inline_keys_file:
        entries = _read_json_file(inline_keys_file, what="inline keys")
        if not isinstance(entries, list):
            raise ConfigurationError(
                f"inline keys file '{inline_keys_file}' must contain a JSON list"
            )
        return Settings(key_id, InlineKeySource(entries), environ.get("EKM_AUDIT_PATH"))
    if key_file:
        return Settings(
            key_id,
            FileKeySource(key_file),
            environ.get("EKM_AUDIT_PATH"),
        )

    raise ConfigurationError(
        "no local key source configured: set EKM_CONFIG_FILE, "
        "EKM_INLINE_KEYS_JSON_FILE or EKM_KEY_FILE; refusing to use a default key"
    )


def build_manager(settings: Settings | None = None) -> KeyManager:
    """Construct a KeyManager from local configuration.

    Raises :class:`ConfigurationError` for missing/incomplete configuration.
    The source itself is validated during bootstrap (at least one ACTIVE
    version, exactly one current version, 32-byte base64 key material).
    """
    if settings is None:
        settings = load_settings()
    audit: AuditLogger | NullAuditLogger
    if settings.audit_path:
        audit = AuditLogger(settings.audit_path)
    else:
        audit = NullAuditLogger()
    return KeyManager(settings.key_id, settings.key_source, audit)
