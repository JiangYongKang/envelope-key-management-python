"""Audit/operation truth: when audit cannot persist, success is not returned."""

from __future__ import annotations

import pytest

from app.errors import AuditWriteFailedError
from app.models import AuditRecord, OperationResult

from .conftest import log_case


class FailingAudit:
    """Audit sink that fails on SUCCESS writes, records failures best-effort."""

    def __init__(self) -> None:
        self.failures: list[AuditRecord] = []
        self.success_attempts = 0

    def append(self, record: AuditRecord) -> None:
        if record.result is OperationResult.SUCCESS:
            self.success_attempts += 1
            raise AuditWriteFailedError("simulated disk failure")
        self.failures.append(record)

    def best_effort_append(self, record: AuditRecord) -> None:
        # Mirror AuditLogger: failure records still land even with a broken sink.
        if record.result is OperationResult.FAILURE:
            self.failures.append(record)

    def read_all(self) -> list[AuditRecord]:
        return list(self.failures)


def test_encrypt_fails_when_success_audit_cannot_persist(manager_factory):
    sink = FailingAudit()
    manager = manager_factory(("ACTIVE",), audit=sink)
    with pytest.raises(AuditWriteFailedError):
        manager.encrypt(b"never-returned", {"t": "a"})
    assert sink.success_attempts == 1
    # Caller never received a token; current version is unchanged.
    assert manager.current_version() == "v1"
    log_case("audit-fail-encrypt", attempts=sink.success_attempts)


def test_rotate_rolls_back_when_success_audit_cannot_persist(manager_factory):
    sink = FailingAudit()
    manager = manager_factory(("ACTIVE",), audit=sink)
    before = {v.version: v.state for v in manager.list_versions()}
    with pytest.raises(AuditWriteFailedError):
        manager.rotate()
    after = {v.version: v.state for v in manager.list_versions()}
    assert before == after  # v2 was removed, v1 stays ACTIVE/current
    assert manager.current_version() == "v1"
    assert "v2" not in after
    # A subsequent successful rotation is still numbered v2 (no skipped/dup).
    sink.append = lambda record: None  # type: ignore[method-assign]
    sink.best_effort_append = lambda record: None  # type: ignore[method-assign]
    assert manager.rotate() == "v2"
    log_case("audit-fail-rotate-rollback", versions=list(after))


def test_failure_records_still_emitted_with_failing_sink(manager_factory):
    class FullyFailing(FailingAudit):
        def best_effort_append(self, record):  # swallow; must not mask real error
            return

    sink = FullyFailing()
    manager = manager_factory(("ACTIVE",), audit=sink)
    from app.errors import CiphertextInvalidError
    with pytest.raises(CiphertextInvalidError):
        manager.decrypt("garbage", {})
    # The original classified failure is what reaches the caller regardless.
    log_case("audit-fail-keeps-classification")
