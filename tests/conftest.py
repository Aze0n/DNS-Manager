import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlmodel import Session, create_engine, SQLModel
from app.db import get_session
from app.main import app
from fastapi.testclient import TestClient as Client

# In-memory SQLite database
TEST_DB_URL = "sqlite:///:memory:"

@pytest.fixture(name="session")
def session_fixture():
    """Erstellt eine threadsichere und persistente in-memory session für tests."""
    
    # Engine mit check_same_thread=False für multithreaded testclient
    test_engine = create_engine(
        TEST_DB_URL, 
        connect_args={"check_same_thread": False}
    )
    
    # 1. Explizite persistente Verbindung herstellen (KEY FIX für :memory: visibility)
    connection = test_engine.connect()
    
    # 2. Tabellen auf dieser persistenten Verbindung erstellen
    SQLModel.metadata.create_all(connection) 

    # 3. Session erstellen, gebunden an die Verbindung
    session = Session(bind=connection)
    
    try:
        # Starte die Session. Der TestClient und die Endpunkte verwenden nun diese Session.
        yield session
        
    finally:
        # Cleanup: Session schließen und Verbindung trennen
        session.close()
        connection.close()

@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Erstellt den TestClient und überschreibt die DB-Abhängigkeit."""
    
    # Session-Abhängigkeit überschreiben, um die Mock-Session zu injizieren
    def get_session_override():
        yield session

    app.dependency_overrides[get_session] = get_session_override
    with Client(app=app, base_url="http://test") as client:
        yield client
    # Abhängigkeit nach dem Test zurücksetzen
    app.dependency_overrides.clear()

# Gemeinsame Testdaten für alle Tests
TEST_PASSWORD = "mein_sicheres_passwort_123"
