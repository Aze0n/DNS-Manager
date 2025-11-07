# app/db.py

from typing import Generator
from sqlmodel import Session, SQLModel, create_engine
import os

# sqlite datei name
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

# engine global definieren
engine = create_engine(sqlite_url, echo=False)

def create_db_and_tables():
    """Erstellt DB-Struktur. Optional: DROP & CREATE via ENV (gefährlich)."""
    try:
        if os.getenv("DROP_AND_RECREATE_DB", "").strip().lower() in ("1", "true", "yes", "on"):
            SQLModel.metadata.drop_all(engine)
    except Exception:
        pass
    SQLModel.metadata.create_all(engine)

def get_session() -> Generator[Session, None, None]:
    """stellt db-session bereit"""
    with Session(engine) as session:
        yield session