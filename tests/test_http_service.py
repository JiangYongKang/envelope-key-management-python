"""HTTP 入口与直接调用 SDK 的结论一致性。"""

from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from app.config import build_settings
from app.service import app, configure


@pytest.fixture
def client(tmp_path):
    configure(
        build_settings(
            key_file=str(tmp_path / "k.json"),
            audit_file=str(tmp_path / "a.jsonl"),
            bootstrap=True,
        )
    )
    return TestClient(app)


def _encrypt(client, text, ctx, version=None):
    body = {"plaintext": text, "context": ctx}
    if version is not None:
        body["key_version"] = version
    r = client.post("/encrypt", json=body)
    assert r.status_code == 200, r.text
    return r.json()["envelope"]


def test_http_encrypt_decrypt_roundtrip(client):
    envelope = _encrypt(client, "hello", {"t": "a"})
    r = client.post("/decrypt", json={"envelope": envelope, "context": {"t": "a"}})
    assert r.status_code == 200
    assert r.json()["plaintext"] == "hello"


@pytest.mark.parametrize(
    "tamper,expected_code,http_status",
    [
        (lambda e: {**e, "tag": "X" + e["tag"][1:]}, "CIPHERTEXT_INVALID", 422),
        (lambda e: {**e, "encrypted_dek": "X" + e["encrypted_dek"][1:]},
         "CIPHERTEXT_INVALID", 422),
    ],
)
def test_http_tamper_classification(client, tamper, expected_code, http_status):
    envelope = _encrypt(client, "hello", {"t": "a"})
    r = client.post(
        "/decrypt", json={"envelope": tamper(envelope), "context": {"t": "a"}}
    )
    assert r.status_code == http_status
    assert r.json()["error"]["code"] == expected_code


def test_http_context_mismatch(client):
    envelope = _encrypt(client, "hello", {"t": "a"})
    r = client.post(
        "/decrypt", json={"envelope": envelope, "context": {"t": "other"}}
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "CONTEXT_MISMATCH"


def test_http_version_not_found(client):
    r = client.post("/encrypt", json={"plaintext": "x", "context": {}, "key_version": 42})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "KEY_VERSION_NOT_FOUND"


def test_http_rotate_disable_revoke_flow(client):
    envelope = _encrypt(client, "v1", {"t": "a"})

    r = client.post("/rotate")
    assert r.status_code == 200 and r.json()["key_version"] == 2

    # 历史密文仍可解密
    r = client.post("/decrypt", json={"envelope": envelope, "context": {"t": "a"}})
    assert r.status_code == 200 and r.json()["plaintext"] == "v1"

    r = client.post("/keys/status", json={"version": 1, "status": "disabled"})
    assert r.status_code == 200
    r = client.post("/decrypt", json={"envelope": envelope, "context": {"t": "a"}})
    assert r.status_code == 423 and r.json()["error"]["code"] == "KEY_DISABLED"

    r = client.post("/keys/status", json={"version": 1, "status": "revoked"})
    assert r.status_code == 200
    r = client.post("/decrypt", json={"envelope": envelope, "context": {"t": "a"}})
    assert r.status_code == 423 and r.json()["error"]["code"] == "KEY_REVOKED"


def test_http_unknown_status_value(client):
    r = client.post("/keys/status", json={"version": 1, "status": "frozen"})
    assert r.json()["error"]["code"] == "CONFIG_INVALID"
