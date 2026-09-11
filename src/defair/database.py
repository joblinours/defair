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

CREATE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_number ON evidence(evidence_number);
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
