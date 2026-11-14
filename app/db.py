import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./creds.db")

engine =. create_engine (
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(bind=engine, autoFlush=False)

class Base(declarative_base):
    pass


def get_gb():
    db = Sessionlocal()
    try:
        yield db
    finally:
        db.close()