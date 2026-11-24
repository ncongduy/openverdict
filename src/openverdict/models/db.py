"""Database engine, sessions and migrations."""

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine as _create_async_engine


def create_engine(url: str) -> AsyncEngine:
    return _create_async_engine(url, pool_pre_ping=True)


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


def run_migrations(database_url: str) -> None:
    """Upgrade the database to the latest schema. Synchronous: call outside a running loop."""
    config = Config()
    config.set_main_option("script_location", "openverdict:migrations")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(config, "head")
