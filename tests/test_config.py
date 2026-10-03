"""Configuration: local sources only, missing/incomplete config rejected."""

from __future__ import annotations

import json

import pytest

from app.config import build_manager, load_settings
from app.errors import ConfigurationError
from app.key_source import generate_local_key
from app.models import b64e

from .conftest import log_case


def _keys_file(path, *states):
    entries = [
        {"version": f"v{i}", "key_material": b64e(generate_local_key()), "state": s}
        for i, s in enumerate(states, start=1)
    ]
    path.write_text(json.dumps({"versions": entries}))
    return entries


def test_missing_configuration_is_rejected():
    with pytest.raises(ConfigurationError) as exc:
        load_settings({})
    assert "no local key source configured" in str(exc.value)
    log_case("config-missing")


def test_config_file_full_roundtrip(tmp_path):
    keys = tmp_path / "keys.json"
    _keys_file(keys, "ACTIVE", "DEACTIVATED")
    cfg = tmp_path / "config.json"
    audit = tmp_path / "audit.jsonl"
    cfg.write_text(json.dumps({
        "key_id": "kg",
        "key_source": {"type": "file", "path": str(keys)},
        "audit_path": str(audit),
    }))
    manager = build_manager(load_settings({"EKM_CONFIG_FILE": str(cfg)}))
    assert manager.key_id == "kg" and manager.current_version() == "v1"
    # durable audit configured -> rotation writes a line
    manager.rotate()
    assert audit.exists() and audit.read_text().count("\n") >= 1
    log_case("config-file-roundtrip")


def test_config_file_missing_key_source_rejected(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"key_id": "kg"}))
    with pytest.raises(ConfigurationError):
        build_manager(load_settings({"EKM_CONFIG_FILE": str(cfg)}))
    log_case("config-no-source")


def test_config_file_unknown_source_type_rejected(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "key_id": "kg",
        "key_source": {"type": "https://kms.example", "url": "nope"},
    }))
    with pytest.raises(ConfigurationError) as exc:
        build_manager(load_settings({"EKM_CONFIG_FILE": str(cfg)}))
    assert "local 'inline'/'file'" in str(exc.value)
    log_case("config-external-source-rejected")


def test_env_key_file_shorthand(tmp_path):
    keys = tmp_path / "keys.json"
    _keys_file(keys, "ACTIVE")
    manager = build_manager(load_settings(
        {"EKM_KEY_FILE": str(keys), "EKM_KEY_ID": "envkg"}))
    assert manager.key_id == "envkg"
    log_case("config-env-keyfile")


def test_state_path_enables_durability_across_rebuild(tmp_path):
    keys = tmp_path / "keys.json"
    _keys_file(keys, "ACTIVE")
    state = tmp_path / "state.json"
    env = {
        "EKM_KEY_FILE": str(keys),
        "EKM_KEY_ID": "envkg",
        "EKM_STATE_PATH": str(state),
    }
    manager = build_manager(load_settings(env))
    manager.rotate()
    assert manager.current_version() == "v2"

    restarted = build_manager(load_settings(env))
    log_case("config-state-path", current=restarted.current_version(),
             persisted=state.exists())
    assert restarted.current_version() == "v2"


def test_state_path_in_config_file(tmp_path):
    keys = tmp_path / "keys.json"
    _keys_file(keys, "ACTIVE")
    cfg = tmp_path / "config.json"
    state = tmp_path / "state.json"
    cfg.write_text(json.dumps({
        "key_id": "kg",
        "key_source": {"type": "file", "path": str(keys)},
        "state_path": str(state),
    }))
    settings = load_settings({"EKM_CONFIG_FILE": str(cfg)})
    assert settings.state_path == str(state)
    build_manager(settings).rotate()
    assert state.exists()
    log_case("config-state-file-path")


def test_blank_state_path_rejected(tmp_path):
    keys = tmp_path / "keys.json"
    _keys_file(keys, "ACTIVE")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "key_id": "kg",
        "key_source": {"type": "file", "path": str(keys)},
        "state_path": "",
    }))
    with pytest.raises(ConfigurationError):
        load_settings({"EKM_CONFIG_FILE": str(cfg)})
    log_case("config-blank-state-path")


def test_mutually_exclusive_env_sources(tmp_path):
    keys = tmp_path / "keys.json"
    _keys_file(keys, "ACTIVE")
    with pytest.raises(ConfigurationError):
        load_settings({"EKM_KEY_FILE": str(keys),
                       "EKM_INLINE_KEYS_JSON_FILE": str(keys)})
    log_case("config-ambiguous-sources")


def test_bootstrap_rejects_no_active_and_multiple_active(tmp_path):
    none = tmp_path / "none.json"
    _keys_file(none, "REVOKED", "DEACTIVATED")
    with pytest.raises(ConfigurationError):
        build_manager(load_settings({"EKM_KEY_FILE": str(none)}))

    two = tmp_path / "two.json"
    _keys_file(two, "ACTIVE", "ACTIVE")
    with pytest.raises(ConfigurationError):
        build_manager(load_settings({"EKM_KEY_FILE": str(two)}))
    log_case("config-active-constraints")
