"""Native RDP bitmap cache parser (bmc-tools approach, reimplemented).

The Remote Desktop client caches screen tiles of the sessions it opened
(``Users/<user>/AppData/Local/Microsoft/Terminal Server Client/Cache``):
``Cache????.bin`` (RDP 8, Windows 7+) and ``bcache*.bmc`` (older clients).
Rebuilt, the tiles show fragments of what the user saw on the remote host —
windows, command prompts, file names.

Every tile is written as a PNG plus one collage per cache file, in the run's
output directory; each cache file becomes one artifact (tile count, image
paths). Compressed ``.bmc`` tiles are not decoded (counted as skipped).
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool

BIN_MAGIC = b"RDP8bmp\x00"
COLLAGE_COLUMNS = 64
MAX_TILES = 100_000


class RdpCacheNativeTool(NativeTool):
    """Rebuild RDP bitmap cache tiles."""

    module = "zlib"  # pure Python: always available

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="rdpcache_native",
            display_name="RDP bitmap cache (native)",
            allowed_options=[],
            vendor="DEFAIR",
            description="RDP client bitmap cache (Cache????.bin, bcache*.bmc) rebuilt as PNG tiles + collage.",
            category=ToolCategory.NETWORK,
            command="python-native",
            runtime="python",
            timeout=1800,
            capabilities=["rdp", "bitmap_cache", "lateral_movement", "images"],
            input_types=["Cache????.bin", "bcache*.bmc", "Terminal Server Client/Cache"],
            output_formats=["jsonl", "png"],
            artifact_types=["windows.rdp.bitmap_cache"],
            sans_categories=["account_usage", "network_activity"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*") if p.is_file() and _is_cache(p.name))
        return [path]

    def parse_file(self, path: Path) -> Iterator[dict]:
        data = path.read_bytes()
        if data[:8] == BIN_MAGIC:
            tiles, skipped = list(parse_bin(data)), 0
        else:
            tiles, skipped = parse_bmc(data)
        row = {"cache_file": path.name, "format": "bin" if data[:8] == BIN_MAGIC else "bmc",
               "tiles": len(tiles), "tiles_skipped": skipped, "user": _user(path)}
        if tiles and self.output_dir is not None:
            safe = f"{row['user'] or 'unknown'}_{path.name}".replace(" ", "_")
            tile_dir = self.output_dir / "tiles" / safe
            tile_dir.mkdir(parents=True, exist_ok=True)
            for index, (width, height, pixels) in enumerate(tiles):
                (tile_dir / f"{index:05d}.png").write_bytes(png(width, height, pixels))
            collage_path = self.output_dir / f"{safe}_collage.png"
            collage_path.write_bytes(collage(tiles))
            row["tile_dir"] = str(tile_dir)
            row["collage"] = str(collage_path)
        yield row


def _is_cache(name: str) -> bool:
    lower = name.lower()
    return (lower.startswith("cache") and lower.endswith(".bin")) or (
        lower.startswith("bcache") and lower.endswith(".bmc"))


def _user(path: Path) -> str | None:
    parts = [p.lower() for p in path.parts]
    if "users" in parts and parts.index("users") + 1 < len(parts):
        return path.parts[parts.index("users") + 1]
    return None


def parse_bin(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    """``Cache????.bin``: 12-byte header, then (key, width, height, BGRA pixels)."""
    offset = 12
    count = 0
    while offset + 12 <= len(data) and count < MAX_TILES:
        width, height = struct.unpack_from("<HH", data, offset + 8)
        size = width * height * 4
        if not width or not height or width > 256 or height > 256 or offset + 12 + size > len(data):
            break
        yield width, height, bgra_to_rgba(data[offset + 12:offset + 12 + size])
        offset += 12 + size
        count += 1


def parse_bmc(data: bytes) -> tuple[list[tuple[int, int, bytes]], int]:
    """``bcache*.bmc``: 20-byte tile headers; uncompressed 16/24/32 bpp tiles decoded."""
    tiles, skipped, offset = [], 0, 0
    while offset + 20 <= len(data) and len(tiles) < MAX_TILES:
        width, height, length, flags = struct.unpack_from("<HHII", data, offset + 8)
        offset += 20
        if not width or not height or width > 256 or height > 256 or offset + length > len(data):
            break
        body = data[offset:offset + length]
        offset += length
        bpp = length // (width * height) if length and not flags & 0x08 else 0
        if bpp == 4:
            tiles.append((width, height, bgra_to_rgba(body)))
        elif bpp == 3:
            tiles.append((width, height, b"".join(
                bytes((body[i + 2], body[i + 1], body[i], 255)) for i in range(0, len(body), 3))))
        elif bpp == 2:
            tiles.append((width, height, rgb565_to_rgba(body)))
        else:
            skipped += 1  # compressed tile
    return tiles, skipped


def bgra_to_rgba(pixels: bytes) -> bytes:
    out = bytearray(pixels)
    out[0::4], out[2::4] = pixels[2::4], pixels[0::4]
    out[3::4] = b"\xff" * (len(pixels) // 4)  # cache alpha is meaningless
    return bytes(out)


def rgb565_to_rgba(pixels: bytes) -> bytes:
    out = bytearray()
    for (value,) in struct.iter_unpack("<H", pixels[: len(pixels) // 2 * 2]):
        out += bytes((((value >> 11) & 0x1F) << 3, ((value >> 5) & 0x3F) << 2, (value & 0x1F) << 3, 255))
    return bytes(out)


def png(width: int, height: int, rgba: bytes) -> bytes:
    """Minimal RGBA PNG encoder (no image library needed)."""
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    stride = width * 4
    raw = b"".join(b"\x00" + rgba[y * stride:(y + 1) * stride] for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")


def collage(tiles: list[tuple[int, int, bytes]], columns: int = COLLAGE_COLUMNS) -> bytes:
    """All tiles side by side (64 per row, 64×64 cells), in cache order."""
    cell = 64
    rows = (len(tiles) + columns - 1) // columns
    width, height = min(len(tiles), columns) * cell, rows * cell
    canvas = bytearray(width * height * 4)
    for index, (tw, th, pixels) in enumerate(tiles):
        x0, y0 = (index % columns) * cell, (index // columns) * cell
        for y in range(min(th, cell)):
            src = pixels[y * tw * 4:(y * tw + min(tw, cell)) * 4]
            start = ((y0 + y) * width + x0) * 4
            canvas[start:start + len(src)] = src
    return png(width, height, bytes(canvas))
