"""SQLAlchemy async engine/session for Neon Postgres."""

from __future__ import annotations

from sqlalchemy.engine.url import make_url
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.config import settings


class Base(DeclarativeBase):
    pass


def build_engine(database_url: str) -> AsyncEngine:
    """Create the async engine, translating Neon-style URL params for asyncpg."""
    url = make_url(database_url)

    # Force the asyncpg driver for plain postgres URLs
    if url.drivername in ("postgresql", "postgres"):
        url = url.set(drivername="postgresql+asyncpg")

    # asyncpg doesn't accept sslmode/channel_binding kwargs — translate them.
    query = dict(url.query)
    connect_args: dict = {}

    sslmode = query.pop("sslmode", None)
    query.pop("channel_binding", None)
    if sslmode in ("require", "verify-ca", "verify-full"):
        connect_args["ssl"] = True
    elif sslmode == "disable":
        connect_args["ssl"] = False

    url = url.set(query=query)

    return create_async_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=280,
        echo=False,
        connect_args=connect_args,
    )


engine = build_engine(settings.DATABASE_URL)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
