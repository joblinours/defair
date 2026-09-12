"""Tests for the normalization layer."""

from __future__ import annotations

from defair.normalizers.eztools import (
    AmcacheNormalizer,
    AppCompatNormalizer,
    EvtxECmdNormalizer,
    LECmdNormalizer,
    MFTECmdNormalizer,
    PECmdNormalizer,
    RBCmdNormalizer,
    RECmdNormalizer,
    SBECmdNormalizer,
    get_normalizer,
)


class TestNormalizerRegistry:
    def test_get_normalizer(self):
        n = get_normalizer("mftecmd")
        assert n is not None
        assert n.tool_name == "mftecmd"

    def test_get_unknown_normalizer(self):
        assert get_normalizer("nonexistent") is None

    def test_all_tools_have_normalizers(self):
        tools = [
            "mftecmd", "evtxecmd", "pecmd", "recmd", "amcacheparser",
            "appcompatcacheparser", "lecmd", "jlecmd", "rbcmd", "sbecmd",
            "wxtcmd", "sqlecmd", "srumecmd",
        ]
        for t in tools:
            assert get_normalizer(t) is not None, f"Missing normalizer for {t}"


class TestMFTECmdNormalizer:
    def test_normalize_row(self):
        n = MFTECmdNormalizer()
        row = {
            "EntryNumber": "12345",
            "SequenceNumber": "1",
            "ParentPath": "\\Users\\victim\\Desktop",
            "FileName": "malware.exe",
            "Extension": ".exe",
            "FileSize": "65536",
            "Created0x10": "2026-01-15 14:30:00",
            "LastModified0x10": "2026-01-15 14:30:00",
            "InUse": "True",
        }
        result = n.normalize_row(row)
        assert result is not None
        assert result["artifact_type"] == "windows.mft.file_entry"
        assert result["source_tool"] == "mftecmd"
        assert result["data"]["filename"] == "malware.exe"
        assert result["data"]["created_si"] == "2026-01-15 14:30:00"


class TestEvtxNormalizer:
    def test_logon_event(self):
        n = EvtxECmdNormalizer()
        row = {
            "EventId": "4624",
            "Channel": "Security",
            "TimeCreated": "2026-01-15 14:30:00",
            "Computer": "VICTIM-PC",
            "UserName": "admin",
            "MapDescription": "Successful logon",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.evtx.logon"
        assert result["category"] == "account_usage"
        assert result["hostname"] == "VICTIM-PC"

    def test_process_creation(self):
        n = EvtxECmdNormalizer()
        row = {"EventId": "4688", "Channel": "Security", "TimeCreated": "2026-01-15 14:30:00"}
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.evtx.process_creation"
        assert result["category"] == "program_execution"

    def test_service_install(self):
        n = EvtxECmdNormalizer()
        row = {"EventId": "7045", "Channel": "System", "TimeCreated": "2026-01-15 14:30:00"}
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.evtx.service_install"
        assert result["category"] == "persistence"


class TestPECmdNormalizer:
    def test_prefetch_entry(self):
        n = PECmdNormalizer()
        row = {
            "ExecutableName": "POWERSHELL.EXE",
            "RunCount": "5",
            "Hash": "ABCD1234",
            "LastRun": "2026-01-15 14:30:00",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.prefetch.execution"
        assert result["category"] == "program_execution"
        assert "POWERSHELL" in result["description"]


class TestRECmdNormalizer:
    def test_userassist_entry(self):
        n = RECmdNormalizer()
        row = {
            "Description": "UserAssist",
            "HivePath": "NTUSER.DAT",
            "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
            "ValueData": "calc.exe",
            "LastWriteTimestamp": "2026-01-15",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.registry.userassist"
        assert result["category"] == "program_execution"

    def test_run_key(self):
        n = RECmdNormalizer()
        row = {"Description": "Run Key", "HivePath": "SOFTWARE", "ValueData": "malware.exe"}
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.registry.run_key"
        assert result["category"] == "persistence"

    def test_usb_device(self):
        n = RECmdNormalizer()
        row = {"Description": "USB Storage", "HivePath": "SYSTEM", "ValueData": "SanDisk"}
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.registry.usb_device"
        assert result["category"] == "external_device"


class TestAmcacheNormalizer:
    def test_program_entry(self):
        n = AmcacheNormalizer()
        row = {
            "ProgramName": "Mimikatz",
            "FullPath": "C:\\Tools\\mimikatz.exe",
            "SHA1": "abc123def456",
            "KeyLastWriteTimestamp": "2026-01-15",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.amcache.program_entry"
        assert result["category"] == "program_execution"
        assert result["data"]["sha1"] == "abc123def456"


class TestAppCompatNormalizer:
    def test_shimcache_entry(self):
        n = AppCompatNormalizer()
        row = {
            "Path": "C:\\Windows\\System32\\cmd.exe",
            "LastModifiedTimeUTC": "2026-01-15",
            "CacheEntryPosition": "5",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.shimcache.cache_entry"
        assert result["category"] == "program_execution"


class TestLECmdNormalizer:
    def test_lnk_entry(self):
        n = LECmdNormalizer()
        row = {
            "SourceFile": "recent.lnk",
            "LocalPath": "C:\\Users\\admin\\Documents\\secret.docx",
            "TargetCreated": "2026-01-15",
            "VolumeSerialNumber": "ABCD-1234",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.lnk.shortcut"
        assert result["category"] == "file_folder_opening"
        assert "secret.docx" in result["description"]


class TestRBCmdNormalizer:
    def test_deleted_item(self):
        n = RBCmdNormalizer()
        row = {
            "FileName": "evidence.xlsx",
            "FileSize": "4096",
            "DeletedOn": "2026-01-15 15:00:00",
            "UserSid": "S-1-5-21-1234",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.recyclebin.deleted_item"
        assert result["category"] == "deleted_file"
        assert "evidence.xlsx" in result["description"]


class TestSBECmdNormalizer:
    def test_shellbag_entry(self):
        n = SBECmdNormalizer()
        row = {
            "AbsolutePath": "C:\\Users\\admin\\Downloads",
            "ShellType": "Directory",
            "LastInteracted": "2026-01-15",
        }
        result = n.normalize_row(row)
        assert result["artifact_type"] == "windows.shellbags.folder_access"
        assert result["category"] == "file_folder_opening"
