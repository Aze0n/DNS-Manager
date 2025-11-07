from sqlmodel import create_engine, SQLModel, Session
from app.main import app
from app.db import get_session
from fastapi.testclient import TestClient

TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
conn = engine.connect()
SQLModel.metadata.create_all(conn)
session = Session(bind=conn)

def get_session_override():
    yield session

app.dependency_overrides[get_session] = get_session_override

with TestClient(app=app, base_url='http://test') as client:
    TEST_PASSWORD = 'mein_sicheres_passwort_123'
    setup_data = {'password':TEST_PASSWORD,'api_key':'test_public_key','api_secret':'test_secret_value','provider_name':'porkbun'}
    r = client.post('/api/setup', json=setup_data)
    print('POST /api/setup', r.status_code, r.text)
    r = client.post('/api/login', json={'password':TEST_PASSWORD})
    print('POST /api/login', r.status_code, 'cookies', dict(r.cookies))
    r = client.get('/api/protected_test')
    print('GET /api/protected_test', r.status_code, r.text)
    r = client.get('/api/domains/example.com/records')
    print('GET /api/domains/example.com/records', r.status_code, r.text)

# cleanup
session.close()
conn.close()
