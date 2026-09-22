"""Local key sources: inline/file loading and strict configuration rejection."""

from __future__ import annotations

import json

import pytest

from app.errors import ConfigurationError
from app.key_source import FileKeySource, InlineKeySource, generate_local_key
from app.models import KeyState, b64e

from .conftest import log_case


def _entry(version: str = "v1", material: bytes | None = None, state: str = "ACTIVE") -> dict:
    return {
        "version": version,
        "key_material": b64e(material if material is not None else generate_local_key()),
        "state": state,
    }


def test_inline_source_loads_versions_in_order():
    entries = [_entry("v1"), _entry("v2", state="DEACTIVATED")]
    loaded = InlineKeySource(entries).load()
    assert [s.version for s in loaded] == ["v1", "v2"]
    assert loaded[1].state is KeyState.DEACTIVATED
    log_case("source-inline-order", versions=["v1", "v2"])


@pytest.mark.parametrize("entries,why", [
    ([], "empty-list"),
    ([{"version": "v1"}], "missing-material"),
    ([{"version": "v1", "key_material": b64e(b"short")}], "bad-length"),
    ([{"version": "", "key_material": b64e(generate_local_key())}], "missing-version"),
    ([{"version": "v1", "key_material": "not!base64"}], "bad-base64"),
    ([{"version": "v1", "key_material": b64e(generate_local_key()), "state": "BOGUS"}], "bad-state"),
])
def test_inline_source_rejects_incomplete(entries, why):
    with pytest.raises(ConfigurationError) as exc:
        InlineKeySource(entries).load()
    assert exc.value.code.value == "CONFIG_INVALID"
    log_case("source-inline-reject", reason=why)


def test_duplicate_version_rejected():
    entries = [_entry("v1"), _entry("v1")]
    with pytest.raises(ConfigurationError):
        InlineKeySource(entries).load()
    log_case("source-duplicate-version", version="v1")


def test_file_source_roundtrip(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"versions": [_entry("v1")]}))
    loaded = FileKeySource(str(path)).load()
    assert loaded[0].version == "v1"
    log_case("source-file-ok", path=str(path))


def test_file_source_missing_file(tmp_path):
    with pytest.raises(ConfigurationError):
        FileKeySource(str(tmp_path / "nope.json")).load()
    log_case("source-file-missing")


def test_file_source_bad_json(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text("{ not json")
    with pytest.raises(ConfigurationError):
        FileKeySource(str(path)).load()
    log_case("source-file-bad-json")


def test_generated_keys_are_unique_32_bytes():
    a, b = generate_local_key(), generate_local_key()
    assert len(a) == len(b) == 32 and a != b
    log_case("source-generate", lengths=(len(a), len(b)))
