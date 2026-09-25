"""Write /opt/defair/versions.json from the pinned checksums.

EZ Tools are published under unversioned URLs, so their pinned identity is the
archive SHA-256 itself. Other archives are saved as ``<tool>-<version>-….ext``
and carry that explicit version (hayabusa, chainsaw, ripgrep…).

Usage: write_versions.py <checksums> <unused, kept for compatibility> <dotnet version>
"""

import json
import re
import sys
from pathlib import Path

VERSIONED = re.compile(r"^(?P<tool>[A-Za-z0-9_]+)-(?P<version>\d[\w.]*)-")

versions = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    if not line.strip():
        continue
    digest, name = line.split()
    match = VERSIONED.match(name)
    if match:
        tool, version = match.group("tool").lower(), match.group("version")
    else:
        tool, version = name.split("-")[0].removesuffix(".zip").lower(), f"sha256:{digest[:12]}"
    versions[tool] = {"version": version, "sha256": digest, "archive": name}
versions["dotnet"] = {"version": sys.argv[3]}
Path("/opt/defair").mkdir(parents=True, exist_ok=True)
Path("/opt/defair/versions.json").write_text(json.dumps(versions, indent=2, sort_keys=True))
