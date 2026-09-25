"""Tests for evidence sources: detection, extraction, decryption, preparation (v0.4)."""

from __future__ import annotations

import base64
import io
import json
import shutil
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from defair.sources.archives import (
    ExtractionError,
    ExtractionLimits,
    extract_generaptor,
    extract_zip,
    safe_member_path,
)
from defair.sources.detect import detect_source, find_windows_root
from defair.sources.locate import locate_artifacts
from defair.sources.magic import artifact_kind, image_format
from defair.sources.prepare import PreparationError, Secrets, prepare_path

EVTX = b"ElfFile\x00" + b"\x00" * 120
REGF = b"regf" + b"\x00" * 124
PF = b"\x1e\x00\x00\x00SCCA" + b"\x00" * 100
LNK = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 100

ORC_DIR = Path(__file__).resolve().parent.parent / "engines" / "orc-decrypt"


def _write(path: Path, data: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Magic bytes
# ---------------------------------------------------------------------------


class TestMagic:
    @pytest.mark.parametrize("head, fmt", [
        (b"EVF\x09\x0d\x0a\xff\x00", "e01"),
        (b"KDMV", "vmdk"),
        (b"vhdxfile", "vhdx"),
        (b"QFI\xfb", "qcow2"),
    ])
    def test_image_formats(self, tmp_path, head, fmt):
        assert image_format(_write(tmp_path / "img", head + b"\x00" * 600)) == fmt

    def test_raw_ntfs_volume(self, tmp_path):
        boot = bytearray(1024)
        boot[3:11] = b"NTFS    "
        boot[510:512] = b"\x55\xaa"
        assert image_format(_write(tmp_path / "vol.dd", bytes(boot))) == "raw"

    def test_random_file_is_not_an_image(self, tmp_path):
        assert image_format(_write(tmp_path / "x.bin", b"hello" * 200)) is None

    @pytest.mark.parametrize("data, kind", [(EVTX, "evtx"), (REGF, "registry"), (PF, "prefetch"),
                                            (LNK, "lnk"), (b"SQLite format 3\x00", "sqlite")])
    def test_artifact_kinds(self, tmp_path, data, kind):
        assert artifact_kind(_write(tmp_path / "renamed_by_collector", data)) == kind


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestDetect:
    def test_kape(self, tmp_path):
        _write(tmp_path / "2024-05-21T033012_host" / "C" / "Windows" / "Prefetch" / "CMD.EXE-1.pf", PF)
        info = detect_source(tmp_path)
        assert info.kind == "kape" and info.platform == "windows"
        assert info.root.endswith("/C")

    def test_velociraptor(self, tmp_path):
        _write(tmp_path / "uploads" / "auto" / "C%3A" / "Windows" / "System32" / "config" / "SYSTEM", REGF)
        (tmp_path / "results").mkdir()
        _write(tmp_path / "collection_context.json", json.dumps({"hostname": "WS01"}).encode())
        info = detect_source(tmp_path)
        assert info.kind == "velociraptor" and info.hostname == "WS01"
        assert info.details["accessor_path"] == "auto/C:"

    def test_fastir(self, tmp_path):
        _write(tmp_path / "C" / "Windows" / "System32" / "config" / "SAM", REGF)
        _write(tmp_path / "WS01_processes.csv", b"a,b\n")
        assert detect_source(tmp_path).kind == "fastir"

    def test_mount(self, tmp_path):
        _write(tmp_path / "Windows" / "System32" / "config" / "SYSTEM", REGF)
        assert detect_source(tmp_path).kind == "mount"

    def test_logs_folder_by_content(self, tmp_path):
        _write(tmp_path / "a" / "renamed.bin", EVTX)
        info = detect_source(tmp_path)
        assert info.kind == "logs" and info.details["artifact_counts"] == {"evtx": 1}

    def test_uac(self, tmp_path):
        _write(tmp_path / "uac.log", b"")
        (tmp_path / "[root]").mkdir()
        info = detect_source(tmp_path)
        assert info.kind == "uac" and info.platform == "linux"

    def test_zip_plain_and_encrypted(self, tmp_path):
        import pyzipper

        plain = tmp_path / "p.zip"
        with zipfile.ZipFile(plain, "w") as z:
            z.writestr("Logs/Security.evtx", EVTX)
        enc = tmp_path / "e.zip"
        with pyzipper.AESZipFile(enc, "w", encryption=pyzipper.WZ_AES) as z:
            z.setpassword(b"infected")
            z.writestr("x.evtx", EVTX)
        assert detect_source(plain).kind == "zip"
        info = detect_source(enc)
        assert info.kind == "zip_encrypted" and info.needs == ["password"]

    def test_orc_encrypted(self):
        info = detect_source(ORC_DIR / "test_data" / "archive_aes.7z.p7b")
        assert info.kind == "dfir_orc_encrypted" and info.needs == ["private_key"]

    def test_windows_root_search(self, tmp_path):
        _write(tmp_path / "x" / "y" / "Windows" / "System32" / "drivers" / "a.sys")
        assert find_windows_root(tmp_path) == tmp_path / "x" / "y"


# ---------------------------------------------------------------------------
# Locate
# ---------------------------------------------------------------------------


class TestLocate:
    def test_paths_and_magic(self, tmp_path):
        root = tmp_path / "C"
        _write(root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx", EVTX)
        _write(root / "Windows" / "System32" / "config" / "SYSTEM", REGF)
        _write(root / "Windows" / "Prefetch" / "A.pf", PF)
        _write(root / "$MFT", b"FILE0" + b"\x00" * 100)
        _write(tmp_path / "loose" / "dc_security.evtx", EVTX)  # outside the root
        found = locate_artifacts(tmp_path, root)
        assert str(root / "Windows" / "System32" / "winevt" / "Logs") in found["evtx_dir"]
        assert str(tmp_path / "loose") in found["evtx_dir"]
        assert found["system_hive"] == [str(root / "Windows" / "System32" / "config" / "SYSTEM")]
        assert found["prefetch_dir"] == [str(root / "Windows" / "Prefetch")]
        assert found["mft"] == [str(root / "$MFT")]

    def test_case_insensitive(self, tmp_path):
        _write(tmp_path / "windows" / "prefetch" / "A.pf", PF)
        _write(tmp_path / "windows" / "system32" / "x")
        assert locate_artifacts(tmp_path, tmp_path)["prefetch_dir"] == [str(tmp_path / "windows" / "prefetch")]

    def test_single_file(self, tmp_path):
        f = _write(tmp_path / "Security.evtx", EVTX)
        assert locate_artifacts(f) == {"root": [str(f)], "evtx_dir": [str(f)]}


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------


class TestZip:
    def test_zip_slip_refused(self, tmp_path):
        bad = tmp_path / "bad.zip"
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("../../escape.txt", "x")
        with pytest.raises(ExtractionError, match="Unsafe path"):
            extract_zip(bad, tmp_path / "out")
        assert not (tmp_path / "escape.txt").exists()

    @pytest.mark.parametrize("name", ["/etc/passwd", "C:/Windows/x", "a/../../b"])
    def test_unsafe_names(self, tmp_path, name):
        with pytest.raises(ExtractionError):
            safe_member_path(tmp_path, name)

    def test_wrong_and_missing_password(self, tmp_path):
        import pyzipper

        enc = tmp_path / "e.zip"
        with pyzipper.AESZipFile(enc, "w", encryption=pyzipper.WZ_AES) as z:
            z.setpassword(b"right")
            z.writestr("x.evtx", EVTX)
        with pytest.raises(ExtractionError, match="password required"):
            extract_zip(enc, tmp_path / "o1")
        with pytest.raises(ExtractionError, match="wrong password"):
            extract_zip(enc, tmp_path / "o2", password="wrong")
        record = extract_zip(enc, tmp_path / "o3", password="right")
        assert record.files[0]["path"] == "x.evtx" and len(record.files[0]["sha256"]) == 64

    def test_limits(self, tmp_path):
        z = tmp_path / "bomb.zip"
        with zipfile.ZipFile(z, "w") as zf:
            for i in range(5):
                zf.writestr(f"f{i}", "x")
        with pytest.raises(ExtractionError, match="more than 3 files"):
            extract_zip(z, tmp_path / "o", limits=ExtractionLimits(max_files=3))


def _make_generaptor(tmp_path: Path) -> tuple[Path, Path, str]:
    """Collection in CERT-EDF Generaptor's exact format, with a test RSA key."""
    import pyzipper
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
    from cryptography.hazmat.primitives.hashes import SHA512

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    passphrase = "key-pass"
    key_path = tmp_path / "abcd1234_key.pem"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    ))
    secret = "s3cr3t-collection-password"
    enc = key.public_key().encrypt(secret.encode(), OAEP(mgf=MGF1(SHA512()), algorithm=SHA512(), label=None))

    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as z:  # a Velociraptor offline collection
        z.writestr("uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx", EVTX)
        z.writestr("results/Generic.Client.Info.json", "{}")
        z.writestr("collection_context.json", json.dumps({"hostname": "WS42"}))

    archive = tmp_path / "Collection_WS42.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("metadata.json", json.dumps([{
            "device": "WS42", "fingerprint_hex": "abcd1234",
            "b64_enc_secret": base64.b64encode(enc).decode(),
        }]))
    with pyzipper.AESZipFile(archive, "a", encryption=pyzipper.WZ_AES) as z:
        z.setpassword(secret.encode())
        z.writestr("data.zip", data.getvalue())
    return archive, key_path, passphrase


class TestGeneraptor:
    def test_detect(self, tmp_path):
        archive, _, _ = _make_generaptor(tmp_path)
        info = detect_source(archive)
        assert info.kind == "generaptor" and info.hostname == "WS42"
        assert info.details["fingerprint_hex"] == "abcd1234"

    def test_extract(self, tmp_path):
        archive, key, passphrase = _make_generaptor(tmp_path)
        record = extract_generaptor(archive, tmp_path / "out", key, passphrase)
        assert any(f["path"].endswith("Security.evtx") for f in record.files)
        assert detect_source(tmp_path / "out").kind == "velociraptor"

    def test_wrong_passphrase(self, tmp_path):
        archive, key, _ = _make_generaptor(tmp_path)
        with pytest.raises(ExtractionError, match="Cannot load private key"):
            extract_generaptor(archive, tmp_path / "out", key, "nope")

    def test_prepare_end_to_end(self, tmp_path):
        archive, key, passphrase = _make_generaptor(tmp_path)
        with pytest.raises(PreparationError, match="private key is required"):
            prepare_path(archive, tmp_path / "ws")
        prepared = prepare_path(archive, tmp_path / "ws", Secrets(private_key=str(key), passphrase=passphrase))
        assert prepared["source"]["kind"] == "generaptor"
        assert prepared["kind"] == "velociraptor"
        assert prepared["selectors"]["evtx_dir"]
        manifest = json.loads(Path(prepared["manifest"]).read_text())
        assert manifest["secrets_used"] == ["private_key", "passphrase"]
        assert passphrase not in Path(prepared["manifest"]).read_text()


def _orc_key(tmp_path: Path) -> Path:
    src = (ORC_DIR / "tests" / "conftest.py").read_text()
    ns: dict = {}
    exec(compile(src.split("@pytest")[0], "conftest", "exec"), ns)  # noqa: S102 — official test key
    key = tmp_path / "recipient1-key.pem"
    key.write_bytes(ns["recipient1_key"])
    return key


@pytest.mark.skipif(shutil.which("unstream") is None, reason="orc-decrypt (unstream) not installed")
class TestDfirOrc:
    def test_prepare_decrypts_official_test_archive(self, tmp_path):
        archive = ORC_DIR / "test_data" / "archive_aes.7z.p7b"
        prepared = prepare_path(archive, tmp_path / "ws", Secrets(private_key=str(_orc_key(tmp_path))))
        manifest = json.loads(Path(prepared["manifest"]).read_text())
        names = {Path(f["path"]).name for f in manifest["files"]}
        assert {"Config.xml", "Systeminfo.csv"} <= names

    def test_wrong_key(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        other = tmp_path / "other.pem"
        other.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with pytest.raises(Exception, match="(?i)decrypt|key"):
            prepare_path(ORC_DIR / "test_data" / "archive_aes.7z.p7b", tmp_path / "ws",
                         Secrets(private_key=str(other)))


# ---------------------------------------------------------------------------
# Preparation
# ---------------------------------------------------------------------------


class TestPrepare:
    def test_ready_collection_used_in_place(self, tmp_path):
        _write(tmp_path / "ev" / "C" / "Windows" / "Prefetch" / "A.pf", PF)
        prepared = prepare_path(tmp_path / "ev", tmp_path / "ws")
        assert prepared["kind"] == "kape" and prepared["derived"] is False
        assert not (tmp_path / "ws").exists()  # nothing copied

    def test_zip_in_zip(self, tmp_path):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("Logs/Security.evtx", EVTX)
        outer = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("inner.zip", inner.getvalue())
        prepared = prepare_path(outer, tmp_path / "ws")
        assert prepared["kind"] == "logs" and prepared["selectors"]["evtx_dir"]

    def test_disk_image_uses_dissect_extraction(self, tmp_path):
        from defair.sources.archives import ExtractionLog

        img = _write(tmp_path / "disk.vmdk", b"KDMV" + b"\x00" * 600)

        def fake_extract(image, dest, limits=None):
            _write(dest / "C" / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx", EVTX)
            record = ExtractionLog()
            record.add(dest / "C" / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx",
                       "disk.vmdk:sysvol/Windows/System32/winevt/Logs/Security.evtx", dest)
            return record, {"hostname": "DC01", "os": "windows"}

        with patch("defair.sources.image.extract_image", side_effect=fake_extract):
            prepared = prepare_path(img, tmp_path / "ws")
        assert prepared["kind"] == "kape" and prepared["platform"] == "windows"
        assert prepared["host"]["hostname"] == "DC01"
        assert prepared["target"] == str(img)


# ---------------------------------------------------------------------------
# Evidence registration (folders) + DB
# ---------------------------------------------------------------------------


class TestEvidenceFolders:
    @pytest.mark.asyncio
    async def test_register_and_verify_folder(self, db_conn, tmp_path):
        from defair.services import case_service, evidence_service

        case = await case_service.create_case(db_conn, "folders")
        folder = tmp_path / "kape"
        _write(folder / "C" / "Windows" / "Prefetch" / "A.pf", PF)
        ev = await evidence_service.add_evidence(db_conn, case.id, folder)
        assert ev.type == "collection" and ev.source_kind == "kape" and len(ev.sha256) == 64

        assert (await evidence_service.verify_evidence(db_conn, ev.evidence_number))["verified"]
        _write(folder / "C" / "Windows" / "Prefetch" / "B.pf", PF)  # tamper: add a file
        assert (await evidence_service.verify_evidence(db_conn, ev.evidence_number))["status"] == "mismatch"

    @pytest.mark.asyncio
    async def test_prepare_evidence_stores_result(self, db_conn, tmp_path):
        from defair.services import case_service, evidence_service
        from defair.sources.prepare import prepare_evidence

        case = await case_service.create_case(db_conn, "prep")
        f = _write(tmp_path / "Security.evtx", EVTX)
        ev = await evidence_service.add_evidence(db_conn, case.id, f)
        prepared = await prepare_evidence(db_conn, ev.evidence_number, workspace=tmp_path / "ws")
        assert prepared["evidence_number"] == ev.evidence_number
        reloaded = await evidence_service.get_evidence(db_conn, ev.id)
        assert reloaded.prepared["kind"] == "logs"


# ---------------------------------------------------------------------------
# Container keys mount + MCP secrets
# ---------------------------------------------------------------------------


class TestKeysAndSecrets:
    def test_keys_mount_validated(self, tmp_path):
        from unittest.mock import MagicMock

        from defair.config import ContainerConfig
        from defair.services import container_service

        keys = tmp_path / "keys"
        keys.mkdir()
        client = MagicMock()
        client.containers.create.return_value.attrs = {"Mounts": []}
        client.containers.create.return_value.labels = {}
        client.containers.create.return_value.image.tags = ["img"]
        policy = ContainerConfig(key_roots=[tmp_path])
        import asyncio

        with patch.object(container_service, "_get_client", return_value=client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "ws"):
            asyncio.run(container_service.create_container(policy=policy, keys_path=str(keys)))
            volumes = client.containers.create.call_args.kwargs["volumes"]
            assert volumes[str(keys.resolve())] == {"bind": "/keys", "mode": "ro"}
            with pytest.raises(PermissionError):
                asyncio.run(container_service.create_container(
                    policy=ContainerConfig(key_roots=[tmp_path / "elsewhere"]), keys_path=str(keys)))

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_mcp_prepare_passes_secrets_by_env(self, mock_cs):
        from defair.mcp_server.server import mcp

        mock_cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "{}", "stderr": ""})
        await mcp.call_tool("prepare_evidence", {
            "container": "c", "evidence_id": "EVD-001", "password": "infected",
            "private_key": "/keys/orc.pem", "passphrase": "pp",
        })
        args, kwargs = mock_cs.exec_in_container.call_args
        assert "infected" not in " ".join(args[1]) and "pp" not in args[1]
        assert kwargs["env"] == {"DEFAIR_EVIDENCE_PASSWORD": "infected", "DEFAIR_KEY_PASSPHRASE": "pp"}
        assert args[1][-2:] == ["--private-key", "/keys/orc.pem"]

    @pytest.mark.asyncio
    async def test_mcp_prepare_refuses_key_outside_keys(self):
        from defair.mcp_server.server import mcp

        with pytest.raises(Exception, match="under /keys"):
            await mcp.call_tool("prepare_evidence", {
                "container": "c", "evidence_id": "EVD-001", "private_key": "/etc/shadow"})
