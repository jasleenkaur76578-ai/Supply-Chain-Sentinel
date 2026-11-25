import os
import tempfile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

database_url = settings.DATABASE_URL
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
elif database_url.startswith("sqlite+aiosqlite://"):
    database_url = database_url.replace("sqlite+aiosqlite://", "sqlite://", 1)
elif database_url.startswith("postgresql+asyncpg://"):
    database_url = database_url.replace("postgresql+asyncpg://", "postgresql://", 1)

if os.environ.get("VERCEL") and database_url.startswith("sqlite:///./"):
    database_url = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel.db')}"

connect_args = {"check_same_thread": False} if "sqlite" in database_url else {}

engine = create_engine(
    database_url,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()

def get_db():
    """Dependency that yields an active database session with automated rollback on error."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
