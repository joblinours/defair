"""Write /opt/defair/versions.json from the pinned checksums.

EZ Tools are published under unversioned URLs, so their pinned identity is the
archive SHA-256 itself; other tools carry an explicit version.
"""

import json
import sys
from pathlib import Path

EXPLICIT = {"hayabusa": sys.argv[2], "dotnet": sys.argv[3]}

versions = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    if not line.strip():
        continue
    digest, name = line.split()
    tool = name.split("-")[0].removesuffix(".zip").lower()
    versions[tool] = {
        "version": EXPLICIT.get(tool, f"sha256:{digest[:12]}"),
        "sha256": digest,
        "archive": name,
    }
versions["dotnet"] = {"version": EXPLICIT["dotnet"]}
Path("/opt/defair").mkdir(parents=True, exist_ok=True)
Path("/opt/defair/versions.json").write_text(json.dumps(versions, indent=2, sort_keys=True))
