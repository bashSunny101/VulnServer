"""
========================================
PostgreSQL Database Connection
========================================
LEARNING: PostgreSQL stores structured attack data
- Attack sessions
- Aggregated statistics
- Attacker profiles
- Alert rules
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from config import settings

# Create async engine
engine = create_async_engine(
    settings.postgres_url.replace("postgresql://", "postgresql+asyncpg://"),
    echo=settings.environment == "development",
    pool_size=20,
    max_overflow=10
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Base class for models
Base = declarative_base()


async def init_postgres():
    """Initialize PostgreSQL connection"""
    async with engine.begin() as conn:
        # Create tables
        await conn.run_sync(Base.metadata.create_all)
    print("✅ PostgreSQL initialized")


async def close_postgres():
    """Close PostgreSQL connection"""
    await engine.dispose()
    print("✅ PostgreSQL connection closed")


async def get_db():
    """
    Dependency for FastAPI routes
    LEARNING: Ensures connection is closed after request
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
