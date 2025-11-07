# app/models.py

from typing import Optional, List
from sqlmodel import Field, SQLModel, Relationship

# --- 1. user-/authentifizierungsmodell ---
class User(SQLModel, table=True):
    # single-user
    id: Optional[int] = Field(default=None, primary_key=True)
    # argon2id-hash
    password_hash: str = Field(index=True)
    # aktiv
    is_active: bool = Field(default=True)

class ApiKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    provider_name: str
    api_key_encrypted: str
    api_secret_encrypted: str
    kek_salt_b64: Optional[str] = None  # salt für KEK
    # optional: für headless dyndns (mit MASTER_KEY)
    api_key_wrapped: Optional[str] = None
    api_secret_wrapped: Optional[str] = None

    # relationen
    domains: List["Domain"] = Relationship(back_populates="api_key")


class Domain(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # FK -> ApiKey
    api_key_id: int = Field(foreign_key="apikey.id")
    domain_encrypted: str
    # optional
    created_at: Optional[str] = None

    # relationen
    api_key: Optional[ApiKey] = Relationship(back_populates="domains")
    records: List["Record"] = Relationship(back_populates="domain")


class Record(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # FK -> Domain
    domain_id: int = Field(foreign_key="domain.id")
    # verschlüsselt
    name_encrypted: str
    type: str
    content_encrypted: str
    # ttl sekunden
    ttl: Optional[int] = None
    # dyndns aktiv
    dyndns: bool = Field(default=False)
    # created_at optional

    # relationen
    domain: Optional[Domain] = Relationship(back_populates="records")
