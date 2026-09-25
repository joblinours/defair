"""File signatures used to identify evidence containers and artifacts."""

from __future__ import annotations

from pathlib import Path

HEAD_SIZE = 4096


def read_head(path: Path, size: int = HEAD_SIZE) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(size)
    except OSError:
        return b""


def read_tail(path: Path, size: int = 512) -> bytes:
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            length = fh.tell()
            fh.seek(max(0, length - size))
            return fh.read(size)
    except OSError:
        return b""


def image_format(path: Path) -> str | None:
    """Disk image container format, or None."""
    head = read_head(path, 1024)
    if head.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
        return "e01"
    if head.startswith(b"EVF2\r\n\x81\x00"):
        return "ex01"
    if head.startswith(b"LVF\x09\x0d\x0a\xff\x00"):
        return "l01"
    if head.startswith((b"KDMV", b"# Disk DescriptorFile")):
        return "vmdk"
    if head.startswith(b"vhdxfile"):
        return "vhdx"
    if head.startswith(b"conectix") or read_tail(path).startswith(b"conectix"):
        return "vhd"
    if head.startswith(b"AFF10\r\n\x00"):
        return "aff"
    if head.startswith(b"QFI\xfb"):
        return "qcow2"
    # MBR / GPT protective MBR, or a bare NTFS / FAT volume boot sector
    boot_sector = len(head) >= 512 and head[510:512] == b"\x55\xaa"
    known_fs = head[3:11] in (b"NTFS    ", b"MSDOS5.0", b"EXFAT   ")
    if boot_sector and (known_fs or head[0x1BE:0x1FE].strip(b"\x00")):
        return "raw"
    return None


def archive_format(path: Path) -> str | None:
    head = read_head(path, 512)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if path.name.lower().endswith(".p7b") and head[:1] == b"\x30":
        return "pkcs7"
    return None


def artifact_kind(path: Path) -> str | None:
    """Windows artifact type from content (files renamed by collectors, e.g. ORC)."""
    head = read_head(path, 16)
    if head.startswith(b"ElfFile\x00"):
        return "evtx"
    if head.startswith(b"regf"):
        return "registry"
    if head[4:8] == b"SCCA" or head.startswith(b"MAM\x04"):
        return "prefetch"
    if head.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if head[4:8] == b"\xef\xcd\xab\x89":
        return "ese"
    if head.startswith((b"FILE0", b"FILE*")):
        return "mft"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"  # e.g. automaticDestinations-ms JumpLists
    return None
