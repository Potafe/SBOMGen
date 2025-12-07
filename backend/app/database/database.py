from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from app.database.models import Base
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql+psycopg://postgres:password@localhost:5432/sbomgen"
)

# Create async engine with psycopg3
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    future=True,
    pool_pre_ping=True,  # Verify connections before using them
    pool_size=5,  # Number of connections to maintain
    max_overflow=10  # Maximum number of connections to create beyond pool_size
)

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def init_db():
    """Initialize database tables"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Initializing database tables...")
        async with engine.begin() as conn:
            # Enable required PostgreSQL extensions
            # pg_trgm: Fast trigram-based similarity for filtering
            # fuzzystrmatch: Provides levenshtein() for accurate distance calculation
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS fuzzystrmatch"))
            logger.info("PostgreSQL extensions enabled (pg_trgm, fuzzystrmatch)")
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            
            # Create GIN indexes for fuzzy search on package name and version
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_packages_name_trgm 
                ON packages USING gin (name gin_trgm_ops)
            """))
            await conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_packages_version_trgm 
                ON packages USING gin (version gin_trgm_ops)
            """))
            logger.info("Database tables and indexes created successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise

async def get_db_session():
    """Get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def close_db():
    """Close database connections"""
    await engine.dispose()