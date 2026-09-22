"""本地密钥管理命令行工具。

示例::

    # 首次引导：在空的本地密钥文件中生成 v1（材料来自本地 CSPRNG）
    python -m app.cli init --key-file ./data/keys.json --audit-file ./data/audit.jsonl

    # 轮换：新增一个版本，历史版本保留
    python -m app.cli rotate --key-file ./data/keys.json --audit-file ./data/audit.jsonl

    # 停用 / 撤销 / 启用
    python -m app.cli set-status --version 1 --status disabled ...

    # 查看版本与状态
    python -m app.cli list ...
"""

from __future__ import annotations

import argparse
import sys

from app.config import build_manager, build_settings
from app.errors import KMSError
from app.models import KeyStatus


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key-file", required=True, help="本地密钥 JSON 文件")
    p.add_argument("--audit-file", default=None, help="审计 JSON Lines 文件")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description="本地信封密钥管理")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="在空库中引导首个密钥版本")
    _add_common(p_init)

    p_rot = sub.add_parser("rotate", help="轮换出一个新密钥版本")
    _add_common(p_rot)

    p_status = sub.add_parser("set-status", help="修改版本状态")
    _add_common(p_status)
    p_status.add_argument("--version", type=int, required=True)
    p_status.add_argument(
        "--status", required=True, choices=[s.value for s in KeyStatus]
    )

    p_list = sub.add_parser("list", help="列出全部密钥版本")
    _add_common(p_list)

    args = parser.parse_args(argv)

    settings = build_settings(
        key_file=args.key_file,
        audit_file=args.audit_file,
        bootstrap=(args.cmd == "init"),
    )
    try:
        manager = build_manager(settings)
        if args.cmd == "init":
            kv = manager.bootstrap()
            print(f"已引导密钥版本 v{kv.version}（{kv.status.value}）")
        elif args.cmd == "rotate":
            kv = manager.rotate()
            print(f"已轮换出新密钥版本 v{kv.version}（{kv.status.value}）")
        elif args.cmd == "set-status":
            kv = manager.set_status(args.version, KeyStatus(args.status))
            print(f"v{kv.version} 状态 -> {kv.status.value}")
        elif args.cmd == "list":
            if not manager.versions:
                print("密钥库为空")
            for kv in sorted(manager.versions.values(), key=lambda k: k.version):
                print(f"v{kv.version}\t{kv.status.value}\t{kv.created_at}")
    except KMSError as exc:
        print(f"[{exc.code.value}] {exc.message}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
