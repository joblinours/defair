"""Test fixtures for DEFAIR."""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

from defair.config import DefairConfig
from defair.database import get_initialized_connection
from defair.logging import configure_logging


@pytest.fixture(scope="session", autouse=True)
def _setup_logging():
    """Configure logging for tests (console, DEBUG)."""
    from defair.config import LoggingConfig
    configure_logging(LoggingConfig(level="WARNING", format="console"))


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Provide a temporary database path."""
    return tmp_path / "test.db"


@pytest_asyncio.fixture
async def db_conn(tmp_db_path: Path):
    """Provide an initialized async database connection."""
    conn = await get_initialized_connection(tmp_db_path)
    yield conn
    await conn.close()


@pytest.fixture
def config(tmp_db_path: Path) -> DefairConfig:
    """Provide a test config pointing to a temp database."""
    return DefairConfig(
        storage={"database": tmp_db_path, "evidence": "/tmp/test-evidence", "cases": "/tmp/test-cases"},
        logging={"level": "WARNING", "format": "console"},
    )


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a small sample file for evidence tests."""
    f = tmp_path / "sample.txt"
    f.write_text("This is test evidence content for hashing.")
    return f
