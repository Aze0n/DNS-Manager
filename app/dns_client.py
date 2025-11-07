from fastapi import Depends, HTTPException
from sqlmodel import Session, select
from typing import Annotated
from lexicon.client import Client as LexiconClient
from lexicon._private.discovery import load_provider_module

from app.db import get_session
from app.models import ApiKey
from app.core.security import decrypt_secret
from app.dependencies import get_session_kek
import requests
from contextlib import contextmanager
import os
import logging


class LexiconDNSClient:
    """Kleiner Wrapper um dns-lexicon."""

    def __init__(self, provider_name: str, api_key: str, api_secret: str):
        self.provider_name = provider_name
        self.api_key = api_key
        self.api_secret = api_secret

    def _base_config(self, domain: str, action: str):
        """Basis-Konfiguration für den Lexicon-Client."""
        cfg = {
            "provider_name": self.provider_name,
            "action": action,
            "domain": domain,
            "auth_username": self.api_key,
            "auth_token": self.api_secret,
        }
        try:
            if str(self.provider_name).lower() == "porkbun":
                cfg.update({
                    "api_key": self.api_key,
                    "api_secret": self.api_secret,
                    # Provider-Optionen, die Porkbun erwartet
                    "auth_key": self.api_key,
                    "auth_secret": self.api_secret,
                    # zusätzlich Bindestrich-Varianten (manche Interna suchen danach)
                    "auth-key": self.api_key,
                    "auth-secret": self.api_secret,
                })
        except Exception:
            pass

        return cfg


    def list_records(self, domain: str):
        """DNS-Einträge auflisten."""
        try:
            config = self._base_config(domain, "list")
            try:
                with _trace_requests(enabled=(str(self.provider_name).lower() == "porkbun")):
                    with LexiconClient(config) as client:
                        if hasattr(client, "list_records"):
                            output = client.list_records()
                        elif hasattr(client, "list"):
                            output = client.list()
                        elif hasattr(client, "execute"):
                            output = client.execute()
                        else:
                            output = []
            except TypeError:
                with _trace_requests(enabled=(str(self.provider_name).lower() == "porkbun")):
                    client = LexiconClient(config)
                    if hasattr(client, "list_records"):
                        output = client.list_records()
                    elif hasattr(client, "list"):
                        output = client.list()
                    elif hasattr(client, "execute"):
                        output = client.execute()
                    else:
                        output = []
            try:
                if isinstance(output, (list, tuple)):
                    logging.debug("list_records: %s einträge für %s (provider=%s)", len(output), domain, self.provider_name)
                else:
                    logging.debug("list_records: typ=%s für %s", type(output), domain)
            except Exception:
                pass

            return output or []
        except Exception as e:
            error_type = type(e).__name__
            msg = str(e)
            # keine lauten prints im release; nur knappe Fehlermeldung
            raise HTTPException(status_code=500, detail=f"Fehler beim Abrufen: {error_type}: {msg}")

    def add_record(self, domain: str, record_data: dict):
        """Eintrag anlegen."""
        try:
            config = self._base_config(domain, "create")
            config.update({
                "type": record_data.get("type"),
                "name": record_data.get("name"),
                "content": record_data.get("content"),
            })
            try:
                ttl_val = record_data.get("ttl")
                if ttl_val is not None and str(ttl_val).strip() != "":
                    config["ttl"] = int(ttl_val)
            except Exception:
                pass
            # keine payload-logs mit geheimnissen ausgeben
            result_flag = None
            try:
                with _trace_requests(enabled=(str(self.provider_name).lower() == "porkbun")):
                    with LexiconClient(config) as operations:
                        if hasattr(operations, "create_record"):
                            result_flag = operations.create_record(
                                record_data.get("type"),
                                record_data.get("name"),
                                record_data.get("content"),
                            )
                        elif hasattr(operations, "create"):
                            result_flag = operations.create(
                                type=record_data.get("type"),
                                name=record_data.get("name"),
                                content=record_data.get("content"),
                            )
                        elif hasattr(operations, "execute"):
                            result_flag = operations.execute()
                        else:
                            result_flag = True
            except TypeError:
                with _trace_requests(enabled=(str(self.provider_name).lower() == "porkbun")):
                    client = LexiconClient(config)
                    if hasattr(client, "create_record"):
                        result_flag = client.create_record(
                            record_data.get("type"),
                            record_data.get("name"),
                            record_data.get("content"),
                        )
                    elif hasattr(client, "create"):
                        result_flag = client.create(
                            type=record_data.get("type"),
                            name=record_data.get("name"),
                            content=record_data.get("content"),
                        )
                    elif hasattr(client, "execute"):
                        result_flag = client.execute()
                    else:
                        result_flag = True
            success = True if result_flag in (None, True) else bool(result_flag)
            return {"success": success, "record": record_data}
        except Exception as e:
            error_type = type(e).__name__
            msg = str(e)
            raise HTTPException(status_code=500, detail=f"Fehler beim Hinzufügen: {error_type}: {msg}")

    def delete_record(self, domain: str, record_data: dict):
        """Eintrag löschen (agnostisch)."""
        try:
            config = self._base_config(domain, "delete")
            config.update({
                "type": record_data.get("type"),
                "name": record_data.get("name"),
                "content": record_data.get("content"),
            })
            # keine payload-logs mit geheimnissen ausgeben

            result_flag = None
            provider = str(self.provider_name).lower()
            if provider == "porkbun":
                try:
                    legacy_config = {
                        "provider_name": "porkbun",
                        "auth_key": self.api_key,
                        "auth_secret": self.api_secret,
                        "domain": domain,
                    }
                    provider_module = load_provider_module("porkbun")
                    ProviderClass = getattr(provider_module, "Provider")
                    provider_instance = ProviderClass(legacy_config)

                    with _trace_requests(enabled=True):
                        result_flag = provider_instance.delete_record(
                            rtype=record_data.get("type"),
                            name=record_data.get("name"),
                            content=record_data.get("content"),
                        )
                except Exception:
                    result_flag = None
            if result_flag is None:
                try:
                    with _trace_requests(enabled=(provider == "porkbun")):
                        with LexiconClient(config) as operations:
                            if hasattr(operations, "delete_record"):
                                result_flag = operations.delete_record(
                                    rtype=record_data.get("type"),
                                    name=record_data.get("name"),
                                    content=record_data.get("content"),
                                )
                            elif hasattr(operations, "delete"):
                                result_flag = operations.delete(
                                    type=record_data.get("type"),
                                    name=record_data.get("name"),
                                    content=record_data.get("content"),
                                )
                            elif hasattr(operations, "execute"):
                                result_flag = operations.execute()
                            else:
                                result_flag = True
                except TypeError:
                    with _trace_requests(enabled=(provider == "porkbun")):
                        client = LexiconClient(config)
                        if hasattr(client, "delete_record"):
                            result_flag = client.delete_record(
                                rtype=record_data.get("type"),
                                name=record_data.get("name"),
                                content=record_data.get("content"),
                            )
                        elif hasattr(client, "delete"):
                            result_flag = client.delete(
                                type=record_data.get("type"),
                                name=record_data.get("name"),
                                content=record_data.get("content"),
                            )
                        elif hasattr(client, "execute"):
                            result_flag = client.execute()
                        else:
                            result_flag = True

            success = True if result_flag in (None, True) else bool(result_flag)
            return {"success": success, "record": record_data}
        except Exception as e:
            error_type = type(e).__name__
            msg = str(e)
            raise HTTPException(status_code=500, detail=f"Fehler beim Löschen: {error_type}: {msg}")

    def authenticate(self):
        """API-Schlüssel prüfen."""
        provider = str(self.provider_name).lower()
        if provider == "porkbun":
            try:
                legacy_config = {
                    "provider_name": "porkbun",
                    "auth_key": self.api_key,
                    "auth_secret": self.api_secret,
                    "domain": "",
                }
                provider_module = load_provider_module("porkbun")
                ProviderClass = getattr(provider_module, "Provider")
                provider_instance = ProviderClass(legacy_config)

                with _trace_requests(enabled=True):
                    response = provider_instance._post("/ping")

                if not isinstance(response, dict) or response.get("status") != "SUCCESS":
                    raise HTTPException(status_code=400, detail=f"Porkbun auth failed: {response}")

                return True
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Porkbun auth error: {type(e).__name__}: {e}")

    def get_domains(self):
        """Domains holen."""
        provider = str(self.provider_name).lower()
        if provider == "porkbun":
            try:
                legacy_config = {
                    "provider_name": "porkbun",
                    "auth_key": self.api_key,
                    "auth_secret": self.api_secret,
                    "domain": "",
                }
                provider_module = load_provider_module("porkbun")
                ProviderClass = getattr(provider_module, "Provider")
                provider_instance = ProviderClass(legacy_config)
                response = provider_instance._post("/domain/listAll", data={"start": "0", "includeLabels": "yes"})

                if not isinstance(response, dict) or response.get("status") != "SUCCESS":
                    raise HTTPException(status_code=500, detail=f"Porkbun domain listing failed: {response}")

                domains = []
                for item in response.get("domains", []):
                    if isinstance(item, dict) and "domain" in item:
                        domains.append(item["domain"])
                    elif isinstance(item, str):
                        domains.append(item)

                return list(dict.fromkeys(domains))
            except HTTPException:
                raise
            except Exception as e:
                logging.debug("porkbun provider list failed: %s %s", type(e).__name__, e)
                return []

        return []

    def update_record(self, domain: str, record_data: dict):
        """Record aktualisieren."""
        try:
            config = self._base_config(domain, "update")
            config.update({
                "type": record_data.get("type"),
                "name": record_data.get("name"),
                "content": record_data.get("content"),
            })

            result_flag = None
            try:
                provider = str(self.provider_name).lower()
                if provider == "porkbun":
                    try:
                        legacy_config = {
                            "provider_name": "porkbun",
                            "auth_key": self.api_key,
                            "auth_secret": self.api_secret,
                            "domain": domain,
                        }
                        try:
                            ttl_val = record_data.get("ttl")
                            if ttl_val is not None and str(ttl_val).strip() != "":
                                legacy_config["ttl"] = int(ttl_val)
                        except Exception:
                            pass
                        provider_module = load_provider_module("porkbun")
                        ProviderClass = getattr(provider_module, "Provider")
                        provider_instance = ProviderClass(legacy_config)
                        with _trace_requests(enabled=True):
                            prov_recs = provider_instance.list_records(record_data.get("type"), record_data.get("name")) or []
                        if len(prov_recs) == 1:
                            record_id = prov_recs[0].get("id")
                            with _trace_requests(enabled=True):
                                result_flag = provider_instance.update_record(
                                    identifier=record_id,
                                    rtype=record_data.get("type"),
                                    name=record_data.get("name"),
                                    content=record_data.get("content"),
                                )
                        else:
                            with _trace_requests(enabled=True):
                                with LexiconClient(config) as operations:
                                    if hasattr(operations, "update_record"):
                                        result_flag = operations.update_record(
                                            rtype=record_data.get("type"),
                                            name=record_data.get("name"),
                                            content=record_data.get("content"),
                                        )
                                    elif hasattr(operations, "update"):
                                        result_flag = operations.update(
                                            type=record_data.get("type"),
                                            name=record_data.get("name"),
                                            content=record_data.get("content"),
                                        )
                                    elif hasattr(operations, "execute"):
                                        result_flag = operations.execute()
                                    else:
                                        result_flag = True
                    except Exception:
                        result_flag = None
                else:
                    with _trace_requests(enabled=False):
                        with LexiconClient(config) as operations:
                            if hasattr(operations, "update_record"):
                                result_flag = operations.update_record(
                                    rtype=record_data.get("type"),
                                    name=record_data.get("name"),
                                    content=record_data.get("content"),
                                )
                            elif hasattr(operations, "update"):
                                result_flag = operations.update(
                                    type=record_data.get("type"),
                                    name=record_data.get("name"),
                                    content=record_data.get("content"),
                                )
                            elif hasattr(operations, "execute"):
                                result_flag = operations.execute()
                            else:
                                result_flag = True
            except TypeError:
                with _trace_requests(enabled=(str(self.provider_name).lower() == "porkbun")):
                    client = LexiconClient(config)
                    if hasattr(client, "update_record"):
                        result_flag = client.update_record(
                            rtype=record_data.get("type"),
                            name=record_data.get("name"),
                            content=record_data.get("content"),
                        )
                    elif hasattr(client, "update"):
                        result_flag = client.update(
                            type=record_data.get("type"),
                            name=record_data.get("name"),
                            content=record_data.get("content"),
                        )
                    elif hasattr(client, "execute"):
                        result_flag = client.execute()
                    else:
                        result_flag = True

            success = True if result_flag in (None, True) else bool(result_flag)
            return {"success": success, "record": record_data}
        except Exception as e:
            error_type = type(e).__name__
            msg = str(e)
            raise HTTPException(status_code=500, detail=f"Fehler beim Aktualisieren: {error_type}: {msg}")


def get_dns_client(
    session: Annotated[Session, Depends(get_session)],
    kek: Annotated[bytes, Depends(get_session_kek)],
) -> LexiconDNSClient:
    """entschlüsselt und liefert einen LexiconDNSClient"""
    api_key_entry = session.exec(select(ApiKey)).first()
    if not api_key_entry:
        raise HTTPException(status_code=404, detail="keine api schlüssel gefunden")

    try:
        key = decrypt_secret(kek, api_key_entry.api_key_encrypted)
        secret = decrypt_secret(kek, api_key_entry.api_secret_encrypted)
    except Exception as e:
        detail = f"fehler bei der entschlüsselung: {type(e).__name__}".lower()
        raise HTTPException(status_code=401, detail=detail)

    config = {
        "provider_name": api_key_entry.provider_name,
        "auth_key": key,
        "auth_secret": secret,
        "api_key": key,
        "api_secret": secret,
        "auth_username": key,
        "auth_token": secret,
    }

    try:
        _ = LexiconClient(config)
    except Exception:
        pass

    return LexiconDNSClient(api_key_entry.provider_name, key, secret)


@contextmanager
def _trace_requests(enabled: bool = True):
    """HTTP-Requests (mit Redaction) protokollieren; per ENV schaltbar."""
    # ENV-Schalter hat Vorrang: TRACE_PROVIDER_HTTP=true/1/on
    try:
        env_flag = os.getenv("TRACE_PROVIDER_HTTP", "").strip().lower()
        if env_flag in ("1", "true", "on", "yes"):  # nur dann aktiv
            enabled = True
        elif env_flag in ("0", "false", "off", "no"):
            enabled = False
    except Exception:
        pass

    if not enabled:
        yield
        return

    orig_request = requests.sessions.Session.request

    def _wrapped_request(self, method, url, *args, **kwargs):
        try:
            logging.debug("--- Outgoing HTTP Request (captured) ---")
            logging.debug("METHOD: %s", method)
            logging.debug("URL: %s", url)
            headers = kwargs.get("headers") or (args[1] if len(args) > 1 else None)
            # redact common secret headers
            if isinstance(headers, dict):
                redacted = {}
                for k, v in headers.items():
                    lk = str(k).lower()
                    if lk in ("authorization", "x-api-key", "api-key", "api_key", "api_secret"):
                        redacted[k] = "<redacted>"
                    else:
                        redacted[k] = v
                headers = redacted
            logging.debug("HEADERS: %s", headers)
            data = kwargs.get("data")
            json_body = kwargs.get("json")
            if json_body is not None:
                # redact known fields in json
                try:
                    if isinstance(json_body, dict):
                        red = {}
                        for k, v in json_body.items():
                            lk = str(k).lower()
                            if lk in ("api_key", "api_secret", "auth_key", "auth_secret"):
                                red[k] = "<redacted>"
                            else:
                                red[k] = v
                        logging.debug("JSON BODY: %s", red)
                    else:
                        logging.debug("JSON BODY: %s", json_body)
                except Exception:
                    logging.debug("JSON BODY: %s", json_body)
            elif data is not None:
                logging.debug("DATA BODY: %s", data)
            else:
                logging.debug("BODY: (not captured in 'data' or 'json')")
        except Exception as e:
            logging.debug("Failed to pretty-print outgoing request: %s", e)

        return orig_request(self, method, url, *args, **kwargs)

    requests.sessions.Session.request = _wrapped_request
    try:
        yield
    finally:
        requests.sessions.Session.request = orig_request