"""Safe extraction of archives and encrypted collections.

- ZIP (plain, ZipCrypto or AES) via pyzipper
- Generaptor collections (CERT-EDF): RSA-OAEP-SHA512 wrapped secret → AES data.zip
- DFIR-ORC archives (ANSSI): PKCS#7 envelope decrypted by orc-decrypt
  (vendored in engines/orc-decrypt) → 7z (nested 7z included) via py7zr

Every extraction guards against path traversal ("zip slip"), absolute paths,
links, and archive bombs (total size / file count limits), and records each
extracted file with its origin and SHA-256.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import structlog

log = structlog.get_logger(component="sources.archives")

DEFAULT_MAX_BYTES = 200 * 1024**3  # 200 GiB
DEFAULT_MAX_FILES = 1_000_000


class ExtractionError(RuntimeError):
    """Extraction refused or failed (bad secret, unsafe archive, limits)."""


@dataclass
class ExtractionLimits:
    max_bytes: int = DEFAULT_MAX_BYTES
    max_files: int = DEFAULT_MAX_FILES


@dataclass
class ExtractionLog:
    """Derived files and where they came from."""

    files: list[dict] = field(default_factory=list)
    total_bytes: int = 0

    def add(self, path: Path, origin: str, dest_root: Path) -> None:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        size = path.stat().st_size
        self.total_bytes += size
        self.files.append({
            "path": path.relative_to(dest_root).as_posix(),
            "origin": origin,
            "size": size,
            "sha256": digest.hexdigest(),
        })


def safe_member_path(dest: Path, name: str) -> Path:
    """Destination of an archive member, refusing traversal and absolute paths."""
    member = PurePosixPath(name.replace("\\", "/"))
    if member.is_absolute() or ".." in member.parts or (member.parts and ":" in member.parts[0]):
        raise ExtractionError(f"Unsafe path in archive: {name!r}")
    target = (dest / Path(*member.parts)).resolve()
    if dest.resolve() not in target.parents and target != dest.resolve():
        raise ExtractionError(f"Unsafe path in archive: {name!r}")
    return target


def _check_limits(count: int, total: int, limits: ExtractionLimits) -> None:
    if count > limits.max_files:
        raise ExtractionError(f"Archive has more than {limits.max_files} files")
    if total > limits.max_bytes:
        raise ExtractionError(f"Archive expands beyond {limits.max_bytes} bytes")


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------


def extract_zip(
    archive: Path,
    dest: Path,
    password: str | None = None,
    limits: ExtractionLimits | None = None,
    record: ExtractionLog | None = None,
    origin_prefix: str = "",
) -> ExtractionLog:
    """Extract a ZIP (plain / ZipCrypto / AES) safely into ``dest``."""
    import pyzipper

    limits = limits or ExtractionLimits()
    record = record or ExtractionLog()
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with pyzipper.AESZipFile(archive) as zf:
            if password:
                zf.setpassword(password.encode())
            members = [i for i in zf.infolist() if not i.is_dir()]
            _check_limits(len(members), sum(i.file_size for i in members), limits)
            for info in members:
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ExtractionError(f"Symlink in archive refused: {info.filename!r}")
                target = safe_member_path(dest, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with zf.open(info) as src, target.open("wb") as out:
                        shutil.copyfileobj(src, out, 1024 * 1024)
                except RuntimeError as e:  # wrong / missing password
                    raise ExtractionError(
                        f"Cannot decrypt {archive.name}: "
                        f"{'wrong password' if password else 'password required'}"
                    ) from e
                record.add(target, f"{origin_prefix}{archive.name}:{info.filename}", dest)
    except zipfile.BadZipFile as e:
        raise ExtractionError(f"Invalid ZIP archive {archive.name}: {e}") from e
    return record


# ---------------------------------------------------------------------------
# Generaptor (CERT-EDF) — format of generaptor/concept/collection.py
# ---------------------------------------------------------------------------


def _load_private_key(key_path: Path, passphrase: str | None):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        return load_pem_private_key(key_path.read_bytes(), passphrase.encode() if passphrase else None)
    except (ValueError, TypeError) as e:
        raise ExtractionError(f"Cannot load private key {key_path.name}: {e}") from e


def generaptor_metadata(archive: Path) -> dict:
    with zipfile.ZipFile(archive) as zf:
        (metadata,) = json.loads(zf.read("metadata.json").decode())
    return metadata


def extract_generaptor(
    archive: Path,
    dest: Path,
    private_key: Path,
    passphrase: str | None = None,
    limits: ExtractionLimits | None = None,
) -> ExtractionLog:
    """Decrypt and extract a Generaptor collection.

    The collection secret is RSA-OAEP(SHA-512) encrypted in ``metadata.json``;
    it is the AES password of the inner ``data.zip``.
    """
    from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
    from cryptography.hazmat.primitives.hashes import SHA512

    metadata = generaptor_metadata(archive)
    fingerprint = metadata.get("fingerprint_hex")
    if fingerprint and not private_key.name.startswith(fingerprint):
        log.warning("generaptor_key_name_mismatch", expected_prefix=fingerprint, key=private_key.name)

    key = _load_private_key(private_key, passphrase)
    try:
        secret = key.decrypt(
            base64.b64decode(metadata["b64_enc_secret"]),
            OAEP(mgf=MGF1(algorithm=SHA512()), algorithm=SHA512(), label=None),
        ).decode()
    except (KeyError, ValueError) as e:
        raise ExtractionError("Private key does not match this Generaptor collection") from e

    staging = dest / ".generaptor"
    staging.mkdir(parents=True, exist_ok=True)
    try:
        inner = ExtractionLog()
        extract_zip(archive, staging, password=secret, limits=limits, record=inner)
        data_zip = staging / "data.zip"
        if not data_zip.exists():
            raise ExtractionError("Generaptor collection has no data.zip")
        record = extract_zip(data_zip, dest, limits=limits,
                             origin_prefix=f"{archive.name}:data.zip/")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return record


# ---------------------------------------------------------------------------
# DFIR-ORC (ANSSI)
# ---------------------------------------------------------------------------


def _unstream_path() -> Path:
    found = shutil.which("unstream")
    if not found:
        raise ExtractionError("DFIR-ORC 'unstream' binary not found (engines/orc-decrypt)")
    return Path(found)


def decrypt_orc(archive: Path, output: Path, private_key: Path, passphrase: str | None = None) -> Path:
    """Decrypt a ``.7z.p7b`` DFIR-ORC archive into a ``.7z`` file."""
    try:
        from orcdecrypt.decrypt import decrypt_archive
    except ImportError as e:
        raise ExtractionError("orc-decrypt is not installed (engines/orc-decrypt)") from e

    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    ok = decrypt_archive(
        archive, [private_key], output, _unstream_path(), method="python", force=True,
        password=passphrase.encode() if passphrase else None,
    )
    if not ok or not output.exists():
        raise ExtractionError(f"Cannot decrypt {archive.name} (wrong key or corrupted archive)")
    return output


def extract_7z(
    archive: Path,
    dest: Path,
    limits: ExtractionLimits | None = None,
    record: ExtractionLog | None = None,
    origin_prefix: str = "",
    depth: int = 0,
    root: Path | None = None,
) -> ExtractionLog:
    """Extract a 7z archive, recursing into nested 7z (ORC's layout)."""
    import py7zr

    limits = limits or ExtractionLimits()
    record = record or ExtractionLog()
    root = root or dest
    dest.mkdir(parents=True, exist_ok=True)
    with py7zr.SevenZipFile(archive) as zf:
        infos = [i for i in zf.list() if not i.is_directory]
        _check_limits(len(infos), sum(i.uncompressed or 0 for i in infos), limits)
        for info in infos:
            safe_member_path(dest, info.filename)
        zf.extractall(path=dest)
    for info in infos:
        target = safe_member_path(dest, info.filename)
        if not target.is_file():
            continue
        origin = f"{origin_prefix}{archive.name}:{info.filename}"
        if target.suffix.lower() == ".7z" and depth < 3:
            nested_dest = target.with_suffix("")
            extract_7z(target, nested_dest, limits, record, f"{origin}/", depth + 1, root)
            target.unlink()
            continue
        record.add(target, origin, root)
    return record
