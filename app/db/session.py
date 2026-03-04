from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.models import Base

DB_URL = "sqlite:///./dfir.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

def init_db():
    Base.metadata.create_all(bind=engine)