"""
SQLite database setup using SQLAlchemy async engine.

Educational note:
  SQLite is used for simplicity — it stores everything in a single file,
  perfect for a lab environment.  In production you'd swap this for
  PostgreSQL or similar.
"""

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from config import config

# Convert standard sqlite URL to async (aiosqlite driver)
_url = config.database_url.replace("sqlite:///", "sqlite+aiosqlite:///")

engine = create_async_engine(_url, echo=False, future=True)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# Enable WAL mode for better concurrent read performance
@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


async def init_db():
    """Create all tables if they don't exist."""
    from models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    """Dependency-injectable session factory for FastAPI."""
    async with async_session_factory() as session:
        yield session
