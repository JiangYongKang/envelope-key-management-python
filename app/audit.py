"""审计记录：与实际操作结果严格一致，写入本地 JSON Lines 文件并镜像到日志。

设计约束：
- 审计事件只在操作有了确定结论（成功 / 明确失败）之后落盘一次，因此不会
  出现“记成功却实际失败”或相反情况；
- 审计只记录摘要（明文 SHA-256 短摘要、上下文摘要），不记录明文本身；
- 审计落盘失败向上抛出 :class:`AuditFailureError`，由 Manager 决定该操作
  是否按失败处理（本实现：加解密等操作以审计写入成功为完成条件）。
"""

from __future__ import annotations

import logging
import os
import pathlib
from datetime import datetime, timezone

from app.errors import AuditFailureError
from app.models import AuditEvent


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditSink:
    """审计落盘协议。"""

    def write(self, event: AuditEvent) -> None:
        raise NotImplementedError


class FileAuditSink(AuditSink):
    """JSON Lines 本地文件审计落盘（追加写，每行一条事件）。"""

    def __init__(self, path: str | pathlib.Path | None) -> None:
        self.path = pathlib.Path(path) if path else None

    def write(self, event: AuditEvent) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = event.to_jsonl() + "\n"
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise AuditFailureError(
                f"审计记录写入失败 {self.path}: {exc}",
                key_version=event.key_version,
            ) from exc


class Auditer:
    """构建并落盘审计事件，同时打印摘要日志（含输入摘要与判定依据）。"""

    def __init__(self, sink: AuditSink | None = None,
                 logger: logging.Logger | None = None) -> None:
        self.sink = sink
        self.logger = logger or logging.getLogger("app.audit")

    def record(self, *, operation: str, success: bool,
               key_version: int | None, context_hash: str | None = None,
               plaintext_hash: str | None = None, error_code: str | None = None,
               detail: str = "", extra: dict[str, str] | None = None) -> AuditEvent:
        event = AuditEvent(
            timestamp=_utc_now_iso(),
            operation=operation,
            success=success,
            key_version=key_version,
            context_hash=context_hash,
            plaintext_hash=plaintext_hash,
            error_code=error_code,
            detail=detail,
            extra=dict(extra or {}),
        )
        if self.sink is not None:
            self.sink.write(event)  # 失败抛 AuditFailureError

        verdict = "SUCCESS" if success else f"DENIED({error_code})"
        self.logger.info(
            "op=%-7s verdict=%-24s key_version=%s ctx=%s pt=%s reason=%s",
            operation,
            verdict,
            key_version,
            context_hash,
            plaintext_hash,
            detail,
        )
        return event
