"""Local bootstrap CLI: generate a key file without any network dependency.

Usage::

    uv run python -m app.cli --output local-keys.json
    uv run python -m app.cli --output local-keys.json --version v1 --state ACTIVE

The resulting file can be referenced via EKM_KEY_FILE / EKM_CONFIG_FILE.
"""

from __future__ import annotations

import argparse
import json
import os

from .key_source import generate_local_key
from .models import b64e


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a local envelope key file")
    parser.add_argument("--output", "-o", required=True, help="path of the JSON file to write")
    parser.add_argument("--version", default="v1", help="version label (default: v1)")
    parser.add_argument(
        "--state", default="ACTIVE", choices=("ACTIVE", "DEACTIVATED", "REVOKED"),
        help="initial lifecycle state (default: ACTIVE)",
    )
    parser.add_argument(
        "--force", action="store_true", help="overwrite the file if it already exists",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.path.exists(args.output) and not args.force:
        raise SystemExit(f"refusing to overwrite existing file '{args.output}' (use --force)")
    document = {
        "versions": [
            {
                "version": args.version,
                "key_material": b64e(generate_local_key()),
                "state": args.state,
            }
        ]
    }
    directory = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(directory, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(args.output, 0o600)
    print(f"wrote local key file '{args.output}' version={args.version} state={args.state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
