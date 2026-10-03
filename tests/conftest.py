"""Shared pytest fixtures, builders and summary-logging helpers.

Each test logs an "input summary + decision basis" line through the
``ekm.summary`` logger, satisfying the requirement that unit-test logs show
input digests and the reason behind every verdict.
"""

from __future__ import annotations

import base64
import json
import logging
import os

import pytest

from app.audit import AuditLogger, NullAuditLogger
from app.key_source import InlineKeySource, generate_local_key
from app.manager import KeyManager
from app.models import b64e, digest_hex

summary_logger = logging.getLogger("ekm.summary")


def make_inline_versions(*states: str) -> list[dict[str, str]]:
    """Build inline key-source entries with explicit lifecycle states."""
    entries = []
    for i, state in enumerate(states, start=1):
        entries.append(
            {
                "version": f"v{i}",
                "key_material": b64e(generate_local_key()),
                "state": state,
            }
        )
    return entries


def tamper_token(token: str) -> str:
    """Flip the first base64url character of the tag field inside a token."""
    pad = "=" * (-len(token) % 4)
    doc = json.loads(base64.urlsafe_b64decode(token + pad))
    tag = doc["tag"]
    doc["tag"] = ("A" if tag[0] != "A" else "B") + tag[1:]
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def retarget_token(token: str, *, version: str | None = None, kid: str | None = None) -> str:
    """Rewrite embedded version / kid WITHOUT updating the AEAD tag."""
    pad = "=" * (-len(token) % 4)
    doc = json.loads(base64.urlsafe_b64decode(token + pad))
    if version is not None:
        doc["ver"] = version
    if kid is not None:
        doc["kid"] = kid
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def caplog_summary(caplog):
    """Capture ekm logs at DEBUG so decision lines are observable/assertable."""
    caplog.set_level(logging.DEBUG, logger="ekm")
    return caplog


@pytest.fixture
def null_audit() -> NullAuditLogger:
    return NullAuditLogger()


@pytest.fixture
def file_audit(tmp_path) -> AuditLogger:
    return AuditLogger(str(tmp_path / "audit.jsonl"))


@pytest.fixture
def manager_factory(null_audit):
    created: list[KeyManager] = []

    def _factory(states=("ACTIVE",), key_id: str = "test-key", audit=None,
                 state_store=None) -> KeyManager:
        source = InlineKeySource(make_inline_versions(*states))
        manager = KeyManager(key_id, source, audit or null_audit, state_store)
        created.append(manager)
        return manager

    _factory.created = created  # type: ignore[attr-defined]
    return _factory


@pytest.fixture
def manager(manager_factory) -> KeyManager:
    return manager_factory(("ACTIVE",))


def log_case(name: str, **inputs) -> None:
    """Emit a deterministic input summary for a unit-test case."""
    summary = {}
    for key, value in inputs.items():
        if isinstance(value, (bytes, bytearray)):
            summary[key] = digest_hex(bytes(value))[:16]
        elif isinstance(value, str) and len(value) > 48:
            summary[key] = f"sha256:{digest_hex(value.encode())[:16]}"
        else:
            summary[key] = value
    summary_logger.info("CASE %s inputs=%s", name, json.dumps(summary, sort_keys=True))
