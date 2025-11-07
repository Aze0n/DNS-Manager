from fastapi import APIRouter, Depends, HTTPException
from app.dns_client import get_dns_client
from app.db import SessionLocal

router = APIRouter()

@router.get("/domains/{domain}/records")
def get_records(domain: str):
    session = SessionLocal()
    client = get_dns_client(session=session, kek=b"test_kek")  # mit echtem Session-KEK ersetzen
    # Platzhalter bis Lexicon-Integration
    return {"domain": domain, "records": []}
