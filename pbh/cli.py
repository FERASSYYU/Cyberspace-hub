"""Command-line entry point. Local modes only; no live-target mode exists."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from pbh.core.controller import run_analysis
from pbh.core.scope import PolicyViolation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pbh")
    parser.add_argument("--mode", default="local_fixture_benchmark",
                        choices=["repository_analysis", "local_fixture_benchmark"])
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        run = run_analysis(args.mode, args.program, args.input, args.output)
    except PolicyViolation as exc:
        logging.error("safety gate refused the run: %s", exc)
        return 2
    print(json.dumps({"files_processed_json": run["files_processed_json"], "status": "ok"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
