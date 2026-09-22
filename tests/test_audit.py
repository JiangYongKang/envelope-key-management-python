"""Audit records are durable JSONL and truthfully mirror operation outcomes."""

from __future__ import annotations

import json

import pytest

from app.audit import AuditLogger, NullAuditLogger
from app.errors import AuditWriteFailedError
from app.models import AuditRecord, KeyOperation, OperationResult

from .conftest import log_case


def _rec(result=OperationResult.SUCCESS, code=None) -> AuditRecord:
    return AuditRecord(
        timestamp="2026-09-23T00:00:00Z",
        operation=KeyOperation.DECRYPT,
        result=result,
        key_version="v1",
        context_digest="ctx-digest",
        error_code=code,
        detail="unit test record",
        input_digest="input-digest",
    )


def test_audit_persists_and_reads_back(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLogger(str(path))
    audit.append(_rec())
    audit.append(_rec(OperationResult.FAILURE, "CIPHERTEXT_TAMPERED"))
    rows = AuditLogger(str(path)).read_all()
    assert [r.result for r in rows] == [OperationResult.SUCCESS, OperationResult.FAILURE]
    assert rows[1].error_code == "CIPHERTEXT_TAMPERED"
    log_case("audit-roundtrip", rows=2)


def test_audit_creates_missing_parent_directory(tmp_path):
    path = tmp_path / "nested" / "deep" / "audit.jsonl"
    AuditLogger(str(path)).append(_rec())
    assert path.exists()
    log_case("audit-mkdir", path=str(path))


def test_audit_read_missing_file_is_empty(tmp_path):
    assert AuditLogger(str(tmp_path / "missing.jsonl")).read_all() == []
    log_case("audit-missing-read")


def test_audit_corrupt_line_raises(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("{broken json\n")
    with pytest.raises(AuditWriteFailedError):
        AuditLogger(str(path)).read_all()
    log_case("audit-corrupt")


def test_audit_never_contains_key_material():
    # Sanity: records only carry digests, enforced at the model boundary.
    record = _rec()
    dumped = json.dumps(record.to_dict())
    assert "key_material" not in dumped and "plaintext" not in dumped
    log_case("audit-no-secrets", keys=sorted(record.to_dict().keys()))


def test_null_audit_collector():
    sink = NullAuditLogger()
    sink.append(_rec())
    assert len(sink.read_all()) == 1
    log_case("audit-null-sink")
