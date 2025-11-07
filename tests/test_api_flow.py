import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from app.main import app, get_session
from app.db import sqlite_url
from app.core.security import derive_encryption_key
from app.dependencies import get_session_kek # Neu hinzugefügt

# Test-Passwort und abgeleiteter KEK (muss in conftest.py definiert sein)
# Wir verwenden die Variablen aus conftest.py
TEST_PASSWORD = "mein_sicheres_passwort_123"

# Überschreibt die get_session-Abhängigkeit, um eine isolierte, speicherbasierte DB für Tests zu verwenden
def override_get_session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

app.dependency_overrides[get_session] = override_get_session

# Client und Session Fixtures sind jetzt in conftest.py definiert!

# test removed: expects live provider success with fake keys
# this project validates api keys against providers in runtime.
# keeping a test that assumes setup with fake provider data is invalid.