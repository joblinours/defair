"""DEFAIR database layer — async SQLite with schema management."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import aiosqlite

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    case_number TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    evidence_number TEXT UNIQUE NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id),
    type TEXT DEFAULT 'other',
    original_path TEXT NOT NULL,
    filename TEXT NOT NULL,
    size_bytes INTEGER,
    sha256 TEXT,
    read_only INTEGER DEFAULT 1,
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY,
    run_number TEXT UNIQUE NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id),
    evidence_id TEXT REFERENCES evidence(id),
    tool_name TEXT NOT NULL,
    tool_version TEXT,
    command TEXT DEFAULT '',
    parameters TEXT DEFAULT '{}',
    status TEXT DEFAULT 'pending',
    exit_code INTEGER,
    stdout TEXT DEFAULT '',
    stderr TEXT DEFAULT '',
    output_path TEXT,
    output_files TEXT DEFAULT '[]',
    output_hash TEXT,
    started_at TEXT,
    completed_at TEXT,
    duration_seconds REAL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    artifact_number TEXT UNIQUE NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id),
    evidence_id TEXT REFERENCES evidence(id),
    run_id TEXT REFERENCES tool_runs(id),
    artifact_type TEXT NOT NULL,
    category TEXT DEFAULT 'other',
    source_tool TEXT DEFAULT '',
    source_file TEXT DEFAULT '',
    timestamp TEXT,
    end_timestamp TEXT,
    hostname TEXT,
    username TEXT,
    description TEXT DEFAULT '',
    data TEXT DEFAULT '{}',
    tags TEXT DEFAULT '[]',
    severity TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    finding_number TEXT UNIQUE NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id),
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    confidence TEXT DEFAULT 'medium',
    status TEXT DEFAULT 'open',
    source TEXT DEFAULT '',
    mitre_tactics TEXT DEFAULT '[]',
    mitre_techniques TEXT DEFAULT '[]',
    artifact_ids TEXT DEFAULT '[]',
    detection_refs TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_number ON evidence(evidence_number);
CREATE INDEX IF NOT EXISTS idx_tool_runs_case_id ON tool_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_evidence_id ON tool_runs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_run_number ON tool_runs(run_number);
CREATE INDEX IF NOT EXISTS idx_artifacts_case_id ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON artifacts(run_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type);
CREATE INDEX IF NOT EXISTS idx_artifacts_category ON artifacts(category);
CREATE INDEX IF NOT EXISTS idx_artifacts_timestamp ON artifacts(timestamp);
CREATE INDEX IF NOT EXISTS idx_artifacts_hostname ON artifacts(hostname);
CREATE INDEX IF NOT EXISTS idx_artifacts_username ON artifacts(username);
CREATE INDEX IF NOT EXISTS idx_artifacts_severity ON artifacts(severity);
CREATE INDEX IF NOT EXISTS idx_artifacts_source_tool ON artifacts(source_tool);
CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_finding_number ON findings(finding_number);
"""


async def get_connection(db_path: str | Path) -> aiosqlite.Connection:
    """Open an async SQLite connection with WAL mode and foreign keys."""
    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    return conn


async def init_db(conn: aiosqlite.Connection) -> None:
    """Create tables and indexes if they don't exist."""
    await conn.executescript(SCHEMA_SQL)
    await conn.commit()


async def get_initialized_connection(db_path: str | Path) -> aiosqlite.Connection:
    """Open a connection and ensure the schema is created."""
    conn = await get_connection(db_path)
    await init_db(conn)
    return conn


def run_sync(coro: Any) -> Any:
    """Run an async coroutine synchronously — for CLI use.

    This creates a new event loop each time. Safe to call from synchronous
    click command handlers.
    """
    return asyncio.run(coro)
