# app/schemas.py

from pydantic import BaseModel, Field

# daten für das setup-formular
class SetupData(BaseModel):
    # admin passwort
    password: str = Field(min_length=8)
    
    # public api key
    api_key: str
    
    # secret api key
    api_secret: str
    
    # optional provider (zb porkbun)
    provider_name: str = "porkbun"

# daten für das login-formular
class LoginData(BaseModel):
    # admin passwort
    password: str = Field(min_length=8)