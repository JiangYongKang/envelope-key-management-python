"""FileStateStore / InMemoryStateStore: atomic writes, validation, reload."""

from __future__ import annotations

import json
import os

import pytest

from app.key_source import generate_local_key
from app.models import KeyState, KeyVersion, b64e
from app.state import (
    STATE_FORMAT,
    FileStateStore,
    InMemoryStateStore,
    _document_to_state,
)

from .conftest import log_case


def _kv(version: str, state: KeyState = KeyState.ACTIVE) -> KeyVersion:
    return KeyVersion(
        version=version,
        key_material=generate_local_key(),
        state=state,
        created_at="2026-10-03T00:00:00.000+00:00",
    )


def test_file_store_roundtrip_and_0600_permissions(tmp_path):
    path = str(tmp_path / "state.json")
    store = FileStateStore(path)
    assert store.load() is None  # nothing stored yet

    versions = [_kv("v1", KeyState.DEACTIVATED), _kv("v2", KeyState.ACTIVE)]
    store.save(key_id="primary", current_version="v2", sequence=2, versions=versions)

    reloaded = store.load()
    assert reloaded is not None
    log_case(
        "state-roundtrip",
        current=reloaded.current_version,
        versions=[v.version for v in reloaded.versions],
        mode=oct(os.stat(path).st_mode & 0o777),
    )
    assert reloaded.current_version == "v2"
    assert reloaded.sequence == 2
    assert reloaded.key_id == "primary"
    assert [v.state for v in reloaded.versions] == [
        KeyState.DEACTIVATED, KeyState.ACTIVE
    ]
    assert reloaded.versions[0].key_material == versions[0].key_material
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_in_memory_store_roundtrip():
    store = InMemoryStateStore()
    assert store.load() is None
    versions = [_kv("v1")]
    store.save(key_id="k", current_version="v1", sequence=1, versions=versions)
    assert store.load().current_version == "v1"
    log_case("state-memory-roundtrip")


def test_atomic_replace_never_leaves_temp_files(tmp_path):
    path = str(tmp_path / "state.json")
    store = FileStateStore(path)
    for seq in range(1, 6):
        store.save(
            key_id="primary", current_version=f"v{seq}", sequence=seq,
            versions=[_kv(f"v{seq}")],
        )
    leftovers = [n for n in os.listdir(tmp_path) if n.startswith(".state-")]
    log_case("state-atomic", writes=5, leftovers=leftovers)
    assert leftovers == []
    assert store.load().current_version == "v5"


@pytest.mark.parametrize(
    "mutate,expected_fragment",
    [
        (lambda d: d.update(format="wrong"), "format marker"),
        (lambda d: d.update(key_id=""), "'key_id'"),
        (lambda d: d.update(current_version="missing"), "absent from the ring"),
        (lambda d: d.update(sequence=-1), "non-negative"),
        (lambda d: d.update(versions=[]), "non-empty list"),
    ],
)
def test_corrupt_documents_are_rejected(tmp_path, mutate, expected_fragment):
    from app.errors import StateInvalidError

    path = str(tmp_path / "state.json")
    store = FileStateStore(path)
    store.save(key_id="primary", current_version="v1", sequence=1,
               versions=[_kv("v1")])
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    mutate(doc)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)

    with pytest.raises(StateInvalidError) as exc:
        store.load()
    log_case("state-reject", fragment=expected_fragment)
    assert expected_fragment in str(exc.value)


def test_two_active_versions_rejected(tmp_path):
    from app.errors import StateInvalidError

    doc = {
        "format": STATE_FORMAT,
        "key_id": "primary",
        "current_version": "v1",
        "sequence": 2,
        "versions": [
            {"version": "v1", "key_material": b64e(generate_local_key()),
             "state": "ACTIVE", "created_at": "t"},
            {"version": "v2", "key_material": b64e(generate_local_key()),
             "state": "ACTIVE", "created_at": "t"},
        ],
    }
    with pytest.raises(StateInvalidError) as exc:
        _document_to_state(doc, path="mem")
    log_case("state-two-active")
    assert "exactly the current version" in str(exc.value)


def test_bad_key_material_length_rejected(tmp_path):
    from app.errors import StateInvalidError

    path = str(tmp_path / "x.json")
    store = FileStateStore(path)
    store.save(key_id="primary", current_version="v1", sequence=1,
               versions=[_kv("v1")])
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    doc["versions"][0]["key_material"] = b64e(b"short")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    with pytest.raises(StateInvalidError):
        store.load()
    log_case("state-bad-material-length")


def test_unwritable_location_raises_persist_failed(tmp_path):
    from app.errors import StatePersistFailedError

    target_dir = tmp_path / "a-directory"
    target_dir.mkdir()
    store = FileStateStore(str(target_dir))  # path IS a directory
    with pytest.raises(StatePersistFailedError):
        store.save(key_id="k", current_version="v1", sequence=1,
                   versions=[_kv("v1")])
    log_case("state-persist-failure")
