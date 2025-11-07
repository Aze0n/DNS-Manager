import base64
from typing import Annotated
from fastapi import Depends, HTTPException, status, Request
from sqlmodel import Session
from app.db import get_session
from app.models import User

def get_current_user(request: Request, session: Session = Depends(get_session)) -> User:
    """prüft session user"""
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="nicht authentifiziert")
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user nicht gefunden")
    return user

def get_session_kek(request: Request) -> bytes:
    """Liefert KEK aus serverseitigem Store (nicht im Cookie)."""
    sid = request.session.get("sid")
    if not sid:
        raise HTTPException(status_code=401, detail="session ungültig")
    store = getattr(request.app.state, "kek_sessions", None)
    if not isinstance(store, dict):
        raise HTTPException(status_code=401, detail="keine session gefunden")
    kek = store.get(sid)
    if not kek:
        raise HTTPException(status_code=401, detail="kek nicht verfügbar")
    return kek
