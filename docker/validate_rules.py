"""Build-time checks of the installed rule store (runs in the `rules` stage).

For every pinned source: load it alone with ``raijin-util validate`` and fail
the build if the engine cannot load a single rule from it. Writes
``VALIDATION.txt`` (full per-source output) and ``NOTICE`` (licenses) into the
store.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

from defair.rules.lock import load_lock

store = Path(sys.argv[1])
raijin_util = sys.argv[2]
lock = load_lock()

OK = re.compile(r"(Sigma|YARA): (\d+) rule\(s\) OK")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
report, failures = [], []

for source in lock.sources:
    with tempfile.TemporaryDirectory() as tmp:
        signatures = Path(tmp) / "signatures"
        for engine in ("yara", "sigma"):
            (signatures / engine).mkdir(parents=True)
        (signatures / source.engine / f"00_{source.id}").symlink_to(store / source.engine / source.id)
        out = subprocess.run(
            [raijin_util, "validate", "--signatures", str(signatures)],
            capture_output=True, text=True, check=False,
        )
    text = ANSI.sub("", out.stdout + out.stderr)
    counts = {engine.lower(): int(n) for engine, n in OK.findall(text)}
    loadable = counts.get(source.engine, 0)
    report.append(f"== {source.id} ({source.engine}, {source.ref}) — {loadable} loadable rules")
    report.extend(line for line in text.splitlines() if line.strip().startswith(("[", " ")) and "rule" in line)
    if loadable == 0:
        failures.append(source.id)

(store / "VALIDATION.txt").write_text("\n".join(report) + "\n")

notice = ["DEFAIR embeds the following third-party detection rule sets, unmodified.", ""]
for source in lock.sources:
    notice.append(f"- {source.id}: https://github.com/{source.repo} @ {source.ref} — license: {source.license or 'see repository'}")
(store / "NOTICE").write_text("\n".join(notice) + "\n")

print("\n".join(report))
if failures:
    sys.exit(f"No loadable rule in: {', '.join(failures)}")
