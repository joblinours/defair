"""Native WebCache parser (``WebCacheV01.dat``, Internet Explorer / legacy Edge).

The ESE database behind IE 10+, legacy Edge and Explorer keeps, per user:
browsing history (``History``, daily / weekly ``MSHist*`` containers — also
``file:///`` accesses by Explorer), downloads (``iedownload``) and cookies.
It is read with ``dissect.database.ese`` (no esentutl repair needed).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool
from defair.tools.ntfs_parse import filetime

# container name (lowercase prefix) → record kind
CONTAINERS = (("history", "history"), ("mshist", "history"), ("iedownload", "download"),
              ("cookies", "cookie"))
TIME_COLUMNS = ("AccessedTime", "ModifiedTime", "CreationTime", "ExpiryTime", "SyncTime")


class WebCacheNativeTool(NativeTool):
    """Parse WebCacheV01.dat history, downloads and cookies."""

    module = "dissect.database.ese"

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="webcache_native",
            display_name="WebCache (native)",
            allowed_options=[],
            vendor="DEFAIR (dissect.database)",
            description="IE / legacy Edge WebCacheV01.dat: history (incl. file:// accesses), downloads, cookies.",
            category=ToolCategory.BROWSER,
            command="python-native",
            runtime="python",
            timeout=1800,
            capabilities=["webcache", "browser_history", "downloads", "cookies", "file_access"],
            input_types=["WebCacheV01.dat", "Users directory"],
            output_formats=["jsonl"],
            artifact_types=["windows.browser.history", "windows.browser.download", "windows.browser.cookie"],
            sans_categories=["browser_usage", "file_download", "file_folder_opening"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*") if p.is_file() and p.name.lower() == "webcachev01.dat")
        return [path]

    def parse_file(self, path: Path) -> Iterator[dict]:
        from dissect.database.ese import ESE

        with path.open("rb") as fh:
            db = ESE(fh)
            for container in db.table("Containers").records():
                name = (container.get("Name") or "").rstrip("\x00")
                kind = next((k for prefix, k in CONTAINERS if name.lower().startswith(prefix)), None)
                if kind is None:
                    continue
                container_id = container.get("ContainerId")
                try:
                    table = db.table(f"Container_{container_id}")
                    records = table.records()
                    for record in records:
                        yield _record(record, kind, name, container_id)
                except Exception as e:  # a damaged container must not stop the others
                    yield {"_error": f"Container_{container_id} ({name}): {type(e).__name__}: {e}"}


def _value(record, column: str):
    try:
        value = record.get(column)
    except Exception:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return value.hex()
    if isinstance(value, str):
        return value.rstrip("\x00")
    return value


def _record(record, kind: str, container: str, container_id) -> dict:
    url = _value(record, "Url") or ""
    user = None
    if "@" in url and ":" in url.split("@", 1)[0]:
        # "Visited: bob@https://…" / "iedownload:bob@…"
        prefix, url = url.split("@", 1)
        user = prefix.split(":", 1)[1].strip() or None
    row = {
        "kind": kind,
        "container": container,
        "container_id": container_id,
        "entry_id": _value(record, "EntryId"),
        "url": url,
        "user": user,
        "access_count": _value(record, "AccessCount"),
        "filename": _value(record, "Filename"),
        "file_size": _value(record, "FileSize"),
    }
    for column in TIME_COLUMNS:
        raw = _value(record, column)
        row[column] = filetime(raw) if isinstance(raw, int) else None
    if kind == "download":
        row["response_headers"] = _value(record, "ResponseHeaders")
    return row
