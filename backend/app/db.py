from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import get_settings

s = get_settings()
url = s.DATABASE_URL
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+psycopg://", 1)
elif url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg://", 1)

kwargs = {"pool_pre_ping": True}
if url.startswith("sqlite"):
    kwargs["connect_args"] = {"check_same_thread": False}
else:
    kwargs.update(pool_size=s.DB_POOL_SIZE, max_overflow=s.DB_MAX_OVERFLOW, pool_recycle=1800)

engine = create_engine(url, **kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
