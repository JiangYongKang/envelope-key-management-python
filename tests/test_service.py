"""HTTP surface: consistent status/code mapping across every entry point."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from app.service import create_app

from .conftest import log_case, retarget_token, tamper_token


@pytest.fixture
def client(manager):
    return TestClient(create_app(lambda: manager))


def test_health_and_versions(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["current_version"] == "v1"
    r = client.get("/keys/versions")
    assert r.json()["versions"][0]["state"] == "ACTIVE"
    log_case("http-health")


def test_http_encrypt_decrypt(client):
    r = client.post("/encrypt", json={"plaintext": "hi", "context": {"t": "a"}})
    assert r.status_code == 200
    token = r.json()["ciphertext"]
    r = client.post("/decrypt", json={"ciphertext": token, "context": {"t": "a"}})
    assert r.status_code == 200 and r.json()["plaintext"] == "hi"
    log_case("http-roundtrip", token=token)


def test_http_error_codes_are_distinguishable(client):
    token = client.post("/encrypt", json={"plaintext": "s", "context": {"t": "a"}}).json()["ciphertext"]

    cases = [
        ({"ciphertext": "garbage", "context": {}}, 400, "CIPHERTEXT_INVALID"),
        ({"ciphertext": token, "context": {"t": "b"}}, 409, "CONTEXT_MISMATCH"),
        ({"ciphertext": tamper_token(token), "context": {"t": "a"}}, 409, "CIPHERTEXT_TAMPERED"),
        ({"ciphertext": retarget_token(token, kid="other"), "context": {"t": "a"}},
         409, "KEY_ID_MISMATCH"),
        ({"ciphertext": retarget_token(token, version="v77"), "context": {"t": "a"}},
         404, "KEY_VERSION_NOT_FOUND"),
    ]
    for body, status, code in cases:
        r = client.post("/decrypt", json=body)
        assert r.status_code == status, (body, r.text)
        assert r.json()["error"]["code"] == code, (code, r.text)
    log_case("http-error-matrix", codes=[c[2] for c in cases])


def test_http_rotate_revoke_flow(client):
    assert client.post("/keys/rotate", json={}).status_code == 201
    assert client.post("/keys/rotate", json={"expected_version": "v1"}).json()["error"]["code"] == "ROTATION_RACE"

    r = client.post("/keys/revoke", json={"version": "v1"})
    assert r.status_code == 200
    r = client.post("/keys/revoke", json={"version": "v2"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_LIFECYCLE_TRANSITION"
    r = client.post("/keys/deactivate", json={"version": "missing"})
    assert r.status_code == 404 and r.json()["error"]["code"] == "KEY_VERSION_NOT_FOUND"
    log_case("http-lifecycle")


def test_http_response_never_leaks_material(client):
    r = client.post("/encrypt", json={"plaintext": "TOPSECRET", "context": {}})
    body = json.dumps(r.json())
    assert "TOPSECRET" not in body
    log_case("http-no-leak")
