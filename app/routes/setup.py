# app/routes/setup.py
from fastapi import APIRouter
from app.core.security import hash_password, encrypt_secret
from app.db import SessionLocal
from app.models import ApiKey
from app.core.config import save_master_password, is_setup_done

router = APIRouter()

@router.get("/setup")
def check_setup():
    return {"needs_setup": not is_setup_done()}

@router.post("/setup")
def perform_setup(data: dict):
    password = data["password"]
    api_key = data["api_key"]
    api_secret = data["api_secret"]
    provider_name = data["provider_name"]

    save_master_password(password)

    kek, salt = hash_password(password)  # Hinweis: hash_password ist meist ein Einweg-Hash; ggf. derive_encryption_key verwenden
    key_enc = encrypt_secret(kek, api_key.encode())
    secret_enc = encrypt_secret(kek, api_secret.encode())

    db = SessionLocal()
    api_entry = ApiKey(
        provider_name=provider_name,
        api_key_encrypted=key_enc,
        api_secret_encrypted=secret_enc
    )
    db.add(api_entry)
    db.commit()
    db.close()

    return {"status": "setup_complete"}
