"""Audit logging that mirrors actual operation outcomes.

The service treats audit as part of the operation:

* A *successful* crypto/lifecycle operation only returns success after its
  SUCCESS record is durably appended (line + fsync). An audit write error
  turns the call into an AUDIT_WRITE_FAILED failure instead — the caller can
  never see "success" while the audit entry is missing.
* A *failed* operation is audited best-effort (its FAILURE record must not be
  lost merely because another failure is in flight); an audit error there is
  reported through logging but never changes the classified failure reason.

Records are JSON objects, one per line (JSONL). No key material or plaintext
is ever written — only short digests of inputs/contexts.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Protocol

from .models import AuditRecord

logger = logging.getLogger("ekm.audit")


class AuditSink(Protocol):
    def append(self, record: AuditRecord) -> None: ...

    def read_all(self) -> list[AuditRecord]: ...


def _record_from_dict(row: dict[str, object]) -> AuditRecord:
    from .models import KeyOperation, OperationResult

    return AuditRecord(
        timestamp=str(row["timestamp"]),
        operation=KeyOperation(str(row["operation"])),
        result=OperationResult(str(row["result"])),
        key_version=row.get("key_version"),  # type: ignore[arg-type]
        context_digest=row.get("context_digest"),  # type: ignore[arg-type]
        error_code=row.get("error_code"),  # type: ignore[arg-type]
        detail=str(row.get("detail", "")),
        input_digest=row.get("input_digest"),  # type: ignore[arg-type]
    )


class AuditLogger:
    """Append-only audit sink backed by a local JSON-lines file."""

    def __init__(self, path: str) -> None:
        if not isinstance(path, str) or not path:
            from .errors import ConfigurationError

            raise ConfigurationError("audit path must be a non-empty string")
        self._path = path

    def append(self, record: AuditRecord) -> None:
        """Durably append one record (line + flush + fsync).

        Raises :class:`AuditWriteFailedError` if the record cannot be written;
        callers must treat that as the operation having failed.
        """
        from .errors import AuditWriteFailedError

        line = json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False)
        try:
            directory = os.path.dirname(os.path.abspath(self._path))
            os.makedirs(directory, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditWriteFailedError(
                f"cannot persist audit record to '{self._path}': {exc}"
            ) from exc

    def best_effort_append(self, record: AuditRecord) -> None:
        """Append a failure record; log and swallow audit errors."""
        try:
            self.append(record)
        except Exception as exc:  # noqa: BLE001 - audit of failures is best effort
            logger.error("failed to persist failure audit record: %s", exc)

    def read_all(self) -> list[AuditRecord]:
        from .errors import AuditWriteFailedError

        records: list[AuditRecord] = []
        try:
            with open(self._path, encoding="utf-8") as handle:
                for lineno, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                        records.append(_record_from_dict(row))
                    except (KeyError, ValueError, TypeError) as exc:
                        raise AuditWriteFailedError(
                            f"corrupt audit entry at {self._path}:{lineno}: {exc}"
                        ) from exc
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise AuditWriteFailedError(f"cannot read audit log '{self._path}': {exc}") from exc
        return records


class NullAuditLogger:
    """In-memory audit sink (no disk IO); intended for tests."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> None:
        self._records.append(record)

    # Test sink never fails, but keep the same shape as AuditLogger.
    def best_effort_append(self, record: AuditRecord) -> None:
        self.append(record)

    def read_all(self) -> list[AuditRecord]:
        return list(self._records)
