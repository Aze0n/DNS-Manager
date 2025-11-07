import pytest
import os
from fastapi import HTTPException
from app.dns_client import get_dns_client, LexiconDNSClient
from app.models import ApiKey
from app.core.security import encrypt_secret, derive_encryption_key
from sqlmodel import Session, select
from tests.test_api_flow import TEST_PASSWORD
from unittest.mock import patch

# kek wird einmalig aus passwort abgeleitet
TEST_KEK_BYTES, _ = derive_encryption_key(TEST_PASSWORD)

def mock_get_session_kek() -> bytes:
    # mock für den session kek
    return TEST_KEK_BYTES

@patch('app.dns_client.LexiconClient')
def test_get_dns_client_success(MockLexiconClient, session: Session):
    # api keys werden mit kek verschlüsselt
    TEST_API_KEY = "pk_lexicon_key"
    TEST_API_SECRET = "shh_lexicon_secret"
    PROVIDER = "porkbun"

    key_encrypted = encrypt_secret(TEST_KEK_BYTES, TEST_API_KEY.encode())
    secret_encrypted = encrypt_secret(TEST_KEK_BYTES, TEST_API_SECRET.encode())

    api_key_entry = ApiKey(
        provider_name=PROVIDER,
        api_key_encrypted=key_encrypted,
        api_secret_encrypted=secret_encrypted,
    )
    session.add(api_key_entry)
    session.commit()

    # dns client abrufen
    dns_client_wrapper = get_dns_client(session=session, kek=mock_get_session_kek())

    # prüfe client
    assert isinstance(dns_client_wrapper, LexiconDNSClient)
    MockLexiconClient.assert_called_once()

    args, kwargs = MockLexiconClient.call_args
    config_arg = args[0]
    
    # Validate the structure of the config dict
    assert isinstance(config_arg, dict)
    assert config_arg["provider_name"] == PROVIDER
    assert config_arg["auth_username"] == TEST_API_KEY
    assert config_arg["auth_token"] == TEST_API_SECRET


@patch('app.dns_client.LexiconClient')
def test_get_dns_client_missing_keys(MockLexiconClient, session: Session):
    # kein eintrag in db -> 404
    with pytest.raises(HTTPException) as exc_info:
        get_dns_client(session=session, kek=mock_get_session_kek())

    assert exc_info.value.status_code == 404
    assert "keine api schlüssel" in exc_info.value.detail


@patch('app.dns_client.LexiconClient')
def test_get_dns_client_wrong_password_kek(MockLexiconClient, session: Session):
    # eintrag anlegen
    TEST_API_KEY = "pk_lexicon_fail"
    key_encrypted = encrypt_secret(TEST_KEK_BYTES, TEST_API_KEY.encode())

    api_key_entry = ApiKey(
        provider_name="porkbun",
        api_key_encrypted=key_encrypted,
        api_secret_encrypted=key_encrypted,
    )
    session.add(api_key_entry)
    session.commit()

    # falschen kek erzeugen
    WRONG_PASSWORD = "falsches_passwort_zum_fehlschlagen"
    wrong_kek, _ = derive_encryption_key(WRONG_PASSWORD)

    with pytest.raises(HTTPException) as exc_info:
        get_dns_client(session=session, kek=wrong_kek)

    assert exc_info.value.status_code == 401
    assert "fehler bei der entschlüsselung" in exc_info.value.detail

