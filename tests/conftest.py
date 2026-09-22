"""测试公共夹具与日志配置。

审计日志会打印每次操作的输入摘要（明文 SHA-256 短摘要、上下文摘要、
目标密钥版本）与判定依据（SUCCESS / DENIED(code) + 原因），满足
“单测日志中需要打印输入摘要与判定依据”的要求。
"""

from __future__ import annotations

import logging
import sys

import pytest

from app.audit import Auditer, FileAuditSink
from app.config import build_settings, build_manager


@pytest.fixture
def tmp_paths(tmp_path):
    return {
        "key_file": str(tmp_path / "keys.json"),
        "audit_file": str(tmp_path / "audit.jsonl"),
    }


@pytest.fixture
def manager(tmp_paths):
    settings = build_settings(
        key_file=tmp_paths["key_file"],
        audit_file=tmp_paths["audit_file"],
        bootstrap=True,
    )
    return build_manager(settings)


@pytest.fixture
def manager_factory(tmp_path):
    def _factory(bootstrap: bool = True):
        settings = build_settings(
            key_file=str(tmp_path / "keys.json"),
            audit_file=str(tmp_path / "audit.jsonl"),
            bootstrap=bootstrap,
        )
        return build_manager(settings)

    return _factory


@pytest.fixture
def audit_records(tmp_paths):
    """直接读取审计 JSONL 文件，按顺序返回事件字典。"""

    import json
    import pathlib

    def _read():
        p = pathlib.Path(tmp_paths["audit_file"])
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text().splitlines() if line]

    return _read


def _configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s | %(message)s")
    )
    logger = logging.getLogger("app.audit")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


_configure_logging()
