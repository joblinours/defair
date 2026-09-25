"""``python -m defair.workers.check`` — the worker image has every tool it needs.

Run by CI on the published image (``--network none``); prints the versions
and exits non-zero when a tool is missing or broken.
"""

from __future__ import annotations

import json
import subprocess
import sys

TOOLS = {
    "log2timeline": ["log2timeline", "--version"],
    "psort": ["psort", "--version"],
    "mmls": ["mmls", "-V"],
    "fls": ["fls", "-V"],
    "blkls": ["blkls", "-V"],
}


def main() -> int:
    report, ok = {}, True
    for name, argv in TOOLS.items():
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
            output = (proc.stdout + proc.stderr).strip().splitlines()
            report[name] = output[-1] if output else f"exit {proc.returncode}"
            ok &= proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as e:
            report[name] = f"missing: {e}"
            ok = False
    from defair.workers import entry  # noqa: F401 — the runner imports cleanly

    print(json.dumps(report, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
