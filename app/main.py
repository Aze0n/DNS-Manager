import base64
import os
from dotenv import load_dotenv
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status, Request, APIRouter, Body
from contextlib import asynccontextmanager
from starlette.middleware.sessions import SessionMiddleware
from sqlmodel import Session, select
from fastapi.middleware.cors import CORSMiddleware
from app.dependencies import get_current_user, get_session_kek
from app.schemas import SetupData, LoginData
from app.db import create_db_and_tables, get_session
from app.models import User, ApiKey, Domain, Record
from app.core.security import (
    hash_password,
    verify_password,
    encrypt_secret,
    decrypt_secret,
    derive_encryption_key,
)
from app.dns_client import LexiconDNSClient, get_dns_client, _trace_requests
from lexicon._private.discovery import load_provider_module
import logging
import re
import threading
import time
import requests
from app.db import engine
from starlette.staticfiles import StaticFiles
from sqlmodel import Session as SQLSession
from typing import Optional, List
from pathlib import Path


load_dotenv()
SESSION_SECRET_KEY = os.getenv("SECRET_KEY")
if not SESSION_SECRET_KEY:
    if os.environ.get("PYTEST_CURRENT_TEST"):
        SESSION_SECRET_KEY = "test_secret_key"
    else:
        raise ValueError("SECRET_KEY muss gesetzt sein")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/Shutdown (DB, Stores)."""
    try:
        create_db_and_tables()
    except Exception:
    # in tests/dev ok
        pass
    # KEK-Store (serverseitig)
    if not hasattr(app.state, "kek_sessions") or not isinstance(getattr(app.state, "kek_sessions"), dict):
        app.state.kek_sessions = {}
    yield
    # shutdown optional


app = FastAPI(title="DNS Manager API", lifespan=lifespan)

api_router = APIRouter(prefix="/api")

# CORS per ENV, sonst dev "*"
origins_env = os.getenv("FRONTEND_ORIGIN") or os.getenv("ALLOW_ORIGINS")
allow_origins = [o.strip() for o in (origins_env or "").split(",") if o.strip()] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="session_id",
    same_site="lax",
    https_only=True,
)




def _is_valid_domain(name: str) -> bool:
    """simple domain-check"""
    if not isinstance(name, str) or not name:
        return False
    name = name.strip().lower()
    # basic regex for domain validation
    pattern = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    return bool(pattern.match(name))


def _get_master_key() -> bytes | None:
    """MASTER_KEY: ENV > Datei > None. Datei wird bei Bedarf erzeugt."""
    env_val = os.getenv("MASTER_KEY")
    if env_val:
        try:
            return env_val.encode()
        except Exception:
            return None
    file_path = os.getenv("MASTER_KEY_FILE") or str(Path(__file__).resolve().parent.parent / "secrets" / "master.key")
    try:
        p = Path(file_path)
        if p.exists():
            return p.read_bytes()
        # neu erzeugen
        p.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(32)
        p.write_bytes(key)
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        return key
    except Exception:
        return None

def _get_or_create_domain_entry(kek_bytes: bytes, session: Session, api_entry: ApiKey, domain_name: str) -> Domain:
    """Domain holen/erstellen (entschl. vergleich)."""
    if not _is_valid_domain(domain_name):
        raise HTTPException(status_code=400, detail="Ungültige Domain")
    # alle domains für diesen api_key holen und entschlüsselt vergleichen
    domains = session.exec(select(Domain).where(Domain.api_key_id == api_entry.id)).all()
    for d in domains:
        try:
            dec = decrypt_secret(kek_bytes, d.domain_encrypted)
            if dec == domain_name:
                return d
        except Exception:
            continue
    # neu anlegen
    try:
        enc = encrypt_secret(kek_bytes, domain_name.encode())
        d = Domain(api_key_id=api_entry.id, domain_encrypted=enc)
        session.add(d)
        session.commit()
        session.refresh(d)
        return d
    except Exception as e:
        try:
            session.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Domain konnte nicht gespeichert werden: {e}")


@api_router.get("/setup")
def check_setup(session: Session = Depends(get_session)):
    """prüft setup"""
    user_exists = session.exec(select(User)).first()
    return {"needs_setup": not bool(user_exists)}


@api_router.post("/setup", status_code=status.HTTP_201_CREATED)
def initial_setup(data: SetupData, session: Session = Depends(get_session)):
    """initial setup"""
    if session.exec(select(User)).first():
        raise HTTPException(status_code=403, detail="Setup bereits abgeschlossen")

    # prüfe api-keys
    try:
        dns_wrapper = LexiconDNSClient(data.provider_name.lower(), data.api_key, data.api_secret)
        dns_wrapper.authenticate()
    except HTTPException as e:
        # Gebe die detaillierte Fehlermeldung an den Client weiter
        raise HTTPException(status_code=400, detail=f"API-Schlüssel ungültig: {e.detail}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"API-Schlüssel konnten nicht validiert werden: {type(e).__name__}: {e}")

    user = User(password_hash=hash_password(data.password))
    session.add(user)
    session.commit()
    session.refresh(user)

    kek, salt = derive_encryption_key(data.password)
    api_key_enc = encrypt_secret(kek, data.api_key.encode())
    api_secret_enc = encrypt_secret(kek, data.api_secret.encode())

    api_entry = ApiKey(
        provider_name=data.provider_name,
        api_key_encrypted=api_key_enc,
        api_secret_encrypted=api_secret_enc,
        kek_salt_b64=base64.b64encode(salt).decode(),
    )
    session.add(api_entry)
    session.commit()
    # optional: wrap für headless dyndns
    try:
        master = _get_master_key()
        if master:
            api_entry.api_key_wrapped = encrypt_secret(master, data.api_key.encode())
            api_entry.api_secret_wrapped = encrypt_secret(master, data.api_secret.encode())
            session.add(api_entry)
            session.commit()
    except Exception:
        session.rollback()

    # hole domains und speichere
    try:
        dns_wrapper2 = LexiconDNSClient(data.provider_name.lower(), data.api_key, data.api_secret)
        domains = dns_wrapper2.get_domains()
        if domains:
            for d in domains:
                if not _is_valid_domain(d):
                    logging.warning("Skipping invalid domain while storing: %s", d)
                    continue
                enc = encrypt_secret(kek, d.encode())
                domain_entry = Domain(api_key_id=api_entry.id, domain_encrypted=enc)
                session.add(domain_entry)
            session.commit()
            # Nach dem Speichern der Domains: hole alle Record-Typen und speichere sie
            try:
                _fetch_and_store_records_for_session(kek, session, record_type=None)
            except Exception:
                logging.exception("Records beim Setup konnten nicht geholt/gespeichert werden")
    except Exception as e:
        logging.warning(f"Domains konnten nicht geholt/gespeichert werden: {e}")

    return {"message": "Setup erfolgreich"}


@api_router.post("/login")
def login(request: Request, data: LoginData, session: Session = Depends(get_session)):
    """login"""
    user = session.exec(select(User)).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Falsches Passwort")

    api_entry = session.exec(select(ApiKey)).first()
    if not api_entry or not api_entry.kek_salt_b64:
        raise HTTPException(status_code=500, detail="KEK Salt fehlt")

    salt = base64.b64decode(api_entry.kek_salt_b64)
    kek, _ = derive_encryption_key(data.password, salt)

    request.session.clear()
    # Opaque Session-ID erzeugen und KEK serverseitig speichern
    sid = base64.b16encode(os.urandom(16)).decode().lower()
    # store in app.state
    try:
        store = getattr(app.state, "kek_sessions", None)
        if not isinstance(store, dict):
            app.state.kek_sessions = {}
            store = app.state.kek_sessions
        store[sid] = kek
    except Exception:
        # im Zweifel abbrechen
        raise HTTPException(status_code=500, detail="Session konnte nicht initialisiert werden")
    request.session.update({
        "user_id": user.id,
        "sid": sid,
    })

    # keine domain/record-synchronisierung beim login (nur über setup/refresh)
    logging.debug("login beendet: refresh wird beim login übersprungen")

    # dyndns-worker starten (kek in app.state)
    try:
        if not hasattr(app.state, "dyndns_worker_thread") or app.state.dyndns_worker_thread is None:
            stop_event = threading.Event()
            app.state.dyndns_stop_event = stop_event
            app.state.dyndns_kek = kek

            def _dyndns_worker():
                logging.info("dyndns-worker gestartet")
                # helper: öffentliche ip
                def get_public_ip(v6: bool = False):
                    try:
                        if v6:
                            resp = requests.get("https://api64.ipify.org?format=json", timeout=10)
                        else:
                            resp = requests.get("https://api.ipify.org?format=json", timeout=10)
                        if resp.status_code == 200:
                            data = resp.json()
                            return data.get("ip")
                    except Exception as e:
                        logging.debug("Failed to get public ip: %s", e)
                    return None

                # schleife: alle 60s
                while True:
                    try:
                        kek_bytes = getattr(app.state, "dyndns_kek", None)
                        if not kek_bytes:
                            continue

                        # eigene db-session
                        with SQLSession(engine) as dbs:
                            api_entry = dbs.exec(select(ApiKey)).first()
                            if not api_entry:
                                continue
                            # creds wählen: MASTER_KEY (Datei/ENV) bevorzugt, danach KEK
                            key = None
                            secret = None
                            master = _get_master_key()
                            if master and api_entry.api_key_wrapped and api_entry.api_secret_wrapped:
                                try:
                                    key = decrypt_secret(master, api_entry.api_key_wrapped)
                                    secret = decrypt_secret(master, api_entry.api_secret_wrapped)
                                except Exception:
                                    key = None
                                    secret = None
                            if not key or not secret:
                                try:
                                    key = decrypt_secret(kek_bytes, api_entry.api_key_encrypted)
                                    secret = decrypt_secret(kek_bytes, api_entry.api_secret_encrypted)
                                except Exception:
                                    logging.debug("DynDNS worker: cannot decrypt with KEK")
                                    key = None
                                    secret = None
                            if not key or not secret:
                                continue

                            dns = LexiconDNSClient(api_entry.provider_name.lower(), key, secret)

                            # dyndns-einträge finden (Records für Domains dieses ApiKey)
                            domain_rows = dbs.exec(select(Domain).where(Domain.api_key_id == api_entry.id)).all()
                            domain_ids = [d.id for d in domain_rows if d.id is not None]
                            if not domain_ids:
                                continue
                            records = dbs.exec(select(Record).where(Record.dyndns == True).where(Record.domain_id.in_(domain_ids))).all()
                            for rec in records:
                                try:
                                    # domain über relation
                                    if not rec.domain:
                                        continue
                                    dec_domain = decrypt_secret(kek_bytes, rec.domain.domain_encrypted)
                                    dec_name = decrypt_secret(kek_bytes, rec.name_encrypted)
                                    dec_content = decrypt_secret(kek_bytes, rec.content_encrypted)
                                except Exception:
                                    continue

                                # nur 'auto' bearbeiten
                                if not dec_content or dec_content != "auto":
                                    continue

                                rtype = (rec.type or "").upper()
                                # ip-version wählen
                                ip = None
                                match rtype:
                                    case "A":
                                        ip = get_public_ip(v6=False)
                                    case "AAAA":
                                        ip = get_public_ip(v6=True)
                                    case _:
                                        # nicht unterstützt
                                        continue

                                if not ip:
                                    logging.debug("DynDNS: could not determine public IP for %s %s", dec_domain, dec_name)
                                    continue

                                try:
                                    # porkbun: id ermitteln und update_record mit identifier aufrufen
                                    updated_ok = False
                                    try:
                                        provider_name = (api_entry.provider_name or "").lower()
                                        if provider_name == "porkbun":
                                            try:
                                                legacy_config = {
                                                    "provider_name": "porkbun",
                                                    "auth_key": key,
                                                    "auth_secret": secret,
                                                    "domain": dec_domain,
                                                }
                                                # TTL beim Provider für DynDNS-Updates auf 60 Sekunden setzen
                                                legacy_config["ttl"] = 60
                                                provider_module = load_provider_module("porkbun")
                                                ProviderClass = getattr(provider_module, "Provider")
                                                provider_instance = ProviderClass(legacy_config)
                                                with _trace_requests(enabled=True):
                                                    prov_recs = provider_instance.list_records(rtype, dec_name) or []
                                                if len(prov_recs) == 1:
                                                    record_id = prov_recs[0].get("id")
                                                    with _trace_requests(enabled=True):
                                                        updated_ok = provider_instance.update_record(
                                                            identifier=record_id,
                                                            rtype=rtype,
                                                            name=dec_name,
                                                            content=ip,
                                                        )
                                            except Exception:
                                                updated_ok = False
                                        if not updated_ok:
                                            # fallback: lexicon-wrapper (ttl=60)
                                            dns.update_record(dec_domain, {"type": rtype, "name": dec_name, "content": ip, "ttl": 60})
                                    except Exception:
                                        # allow outer exception handler to log and handle
                                        raise
                                    logging.info("dyndns update %s %s -> %s", dec_domain, dec_name, ip)
                                    try:
                                        # ttl=60 in db behalten
                                        rec.ttl = 60
                                        dbs.add(rec)
                                        dbs.commit()
                                    except Exception:
                                        dbs.rollback()
                                except Exception as e:
                                    # fehlgeschlagen; ggf. fehlenden eintrag aus db löschen
                                    logging.exception("dyndns update fehlgeschlagen für %s %s: %s", dec_domain, dec_name, e)
                                    try:
                                        detail = ''
                                        try:
                                            # fastapi.HTTPException may have .detail
                                            from fastapi import HTTPException as FastAPIHTTPException
                                            if isinstance(e, FastAPIHTTPException):
                                                detail = str(e.detail)
                                            else:
                                                detail = str(e)
                                        except Exception:
                                            detail = str(e)

                                        if any(token in detail.lower() for token in ("400", "bad request", "not found", "no such", "does not exist", "record not found")):
                                            logging.info("provider meldet fehlenden eintrag -> db löschen für %s %s", dec_domain, dec_name)
                                            try:
                                                dbs.delete(rec)
                                                dbs.commit()
                                            except Exception:
                                                logging.exception("Failed to delete DB record after provider reported missing")
                                    except Exception:
                                        # swallow any cleanup errors
                                        pass
                    except Exception:
                        logging.exception("DynDNS worker encountered an error")
                    # 60s warten (oder früher stoppen)
                    if stop_event.wait(60):
                        break
                logging.info("dyndns-worker gestoppt")

            t = threading.Thread(target=_dyndns_worker, daemon=True, name="dyndns-worker")
            app.state.dyndns_worker_thread = t
            t.start()
    except Exception:
        logging.exception("Failed to start DynDNS worker")

    return {"message": "Login erfolgreich"}


@api_router.post("/logout")
def logout(request: Request):
    """logout"""
    # serverseitige KEK-Session entfernen
    try:
        sid = request.session.get("sid")
        store = getattr(app.state, "kek_sessions", None)
        if isinstance(store, dict) and sid in store:
            del store[sid]
    except Exception:
        pass
    request.session.clear()
    # dyndns-worker stoppen und kek löschen
    try:
        if hasattr(app.state, "dyndns_stop_event") and app.state.dyndns_stop_event:
            app.state.dyndns_stop_event.set()
            # worker is daemon; we clear references
            app.state.dyndns_worker_thread = None
            app.state.dyndns_stop_event = None
        if hasattr(app.state, "dyndns_kek"):
            app.state.dyndns_kek = None
    except Exception:
        logging.exception("Error while stopping DynDNS worker on logout")
    return {"message": "Logout erfolgreich"}


@api_router.get("/me")
def whoami(current_user: Annotated[User, Depends(get_current_user)]):
    """whoami"""
    return {"user_id": current_user.id}


    


@api_router.get("/domains/{domain_name}/records")
def list_dns_records(
    domain_name: str,
    dns_client: Annotated[LexiconDNSClient, Depends(get_dns_client)]
):
    """hole dns-einträge"""
    try:
        records = dns_client.list_records(domain_name)
        return {"domain": domain_name, "records": records}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Abrufen der DNS-Einträge: {e}")


@api_router.post("/domains/{domain_name}/records")
def create_dns_record(
    domain_name: str,
    dns_client: LexiconDNSClient = Depends(get_dns_client),
    record: dict = Body(...),
    session: Session = Depends(get_session),
    kek: bytes = Depends(get_session_kek),
):
    """erstelle dns eintrag"""
    # eingaben normalisieren/prüfen
    rtype = (record.get("type") or "").upper()
    name = (record.get("name") or "").strip()
    content = (record.get("content") or "").strip()
    # optionale felder
    ttl = record.get("ttl")
    try:
        ttl = int(ttl) if ttl is not None and str(ttl).strip() != "" else None
    except Exception:
        raise HTTPException(status_code=400, detail="ttl muss eine ganze Zahl sein")
    dyndns = bool(record.get("dyndns"))

    # einfache validierung nach typ
    import ipaddress

    try:
        if dyndns and content == "auto":
            # 'auto' erlauben
            pass
        else:
            if rtype == "A":
                # ipv4 prüfen
                ipaddress.IPv4Address(content)
            elif rtype == "AAAA":
                # ipv6 prüfen
                ipaddress.IPv6Address(content)
            elif rtype == "CNAME":
                # hostname prüfen
                if not content or "." not in content:
                    raise ValueError("CNAME content muss ein gültiger Hostname sein")
            # else: allow other types without strict validation
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        # dyndns + auto: provider-inhalt ermitteln (client kann provider_content mitsenden)
        provider_content = record.get("provider_content") or content
        store_content = content
        if dyndns and (not content or content.lower() == "auto"):
            # öff. ip je nach typ
            if provider_content and str(provider_content).strip() != "":
                store_content = "auto"
            else:
                def _get_public_ip(v6: bool = False):
                    try:
                        if v6:
                            resp = requests.get("https://api64.ipify.org?format=json", timeout=10)
                        else:
                            resp = requests.get("https://api.ipify.org?format=json", timeout=10)
                        if resp.status_code == 200:
                            j = resp.json()
                            return j.get("ip")
                    except Exception as e:
                        logging.debug("Public IP discovery failed: %s", e)
                    return None

                ip = None
                if rtype == "A":
                    ip = _get_public_ip(v6=False)
                elif rtype == "AAAA":
                    ip = _get_public_ip(v6=True)
                else:
                    raise HTTPException(status_code=400, detail="DynDNS is only supported for A and AAAA records")

                if not ip:
                    raise HTTPException(status_code=500, detail="Konnte öffentliche IP nicht ermitteln für DynDNS")

                provider_content = ip
                store_content = "auto"

        # dyndns: ttl=60
        if dyndns:
            ttl = 60
        result = dns_client.add_record(domain_name, {"type": rtype, "name": name, "content": provider_content, "ttl": ttl})
        if not result or not result.get("success"):
            raise HTTPException(status_code=500, detail="Fehler beim Erstellen des Eintrags")
        # in db speichern (verschlüsselt)
        try:
            # domain sicherstellen
            api_entry = session.exec(select(ApiKey)).first()
            if not api_entry:
                raise HTTPException(status_code=404, detail="API entry not found")
            domain_row = _get_or_create_domain_entry(kek, session, api_entry, domain_name)
            # name/content mit kek verschlüsseln
            name_enc = encrypt_secret(kek, name or "")
            content_enc = encrypt_secret(kek, (store_content or "").encode())
            rec = Record(domain_id=domain_row.id, name_encrypted=name_enc, type=rtype, content_encrypted=content_enc, ttl=ttl, dyndns=dyndns)
            session.add(rec)
            session.commit()
        except Exception:
            # db-fehler dürfen flow nicht brechen
            try:
                session.rollback()
            except Exception:
                pass

        return {"message": "Eintrag erfolgreich erstellt", "result": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Hinzufügen des Eintrags: {e}")


@api_router.patch("/records")
def patch_dns_record(
    record: dict = Body(...),
    session: Session = Depends(get_session),
    kek: bytes = Depends(get_session_kek),
    dns_client: LexiconDNSClient = Depends(get_dns_client),
):
    """aktualisiert record-felder (dyndns/ttl/content)"""
    domain = (record.get("domain") or "").strip()
    name = (record.get("name") or "").strip()
    rtype = (record.get("type") or "").upper()
    if not domain or not name or not rtype:
        raise HTTPException(status_code=400, detail="Fehlende Felder: domain, name und type sind erforderlich")

    new_dyndns = record.get("dyndns")
    new_ttl = record.get("ttl")
    new_content = record.get("content")

    # ttl prüfen (falls gesetzt)
    if new_ttl is not None:
        try:
            new_ttl = int(new_ttl)
        except Exception:
            raise HTTPException(status_code=400, detail="ttl muss eine ganze Zahl sein")

    api_entry = session.exec(select(ApiKey)).first()
    if not api_entry:
        raise HTTPException(status_code=404, detail="API entry not found")

    updated = 0
    try:
        # Domain-Zeile für Klartext-Domain suchen
        domain_row = _get_or_create_domain_entry(kek, session, api_entry, domain)
        # alle records für diese domain holen
        records = session.exec(select(Record).where(Record.domain_id == domain_row.id)).all()
        for rec in records:
            try:
                dec_name = decrypt_secret(kek, rec.name_encrypted)
            except Exception:
                continue
            if dec_name == name and (rec.type or "").upper() == rtype:
                # vorhandenen content prüfen
                try:
                    existing_content = decrypt_secret(kek, rec.content_encrypted)
                except Exception:
                    existing_content = None

                if new_dyndns is not None:
                    # dyndns ausschalten: providerwert holen, wenn wir 'auto' haben
                    if not bool(new_dyndns) and (existing_content or "") == "auto":
                        try:
                            # provider-werte holen
                            prov_recs = dns_client.list_records(domain) or []
                            provider_value = None
                            def _norm(name: str) -> str:
                                if not name:
                                    return ""
                                n = name.strip().lower()
                                if n.endswith('.'):
                                    n = n[:-1]
                                return n

                            dec_name_norm = _norm(dec_name)
                            domain_norm = _norm(domain)
                            # apex/leer berücksichtigen
                            dec_name_candidates = set()
                            if dec_name_norm in ("", "@"):
                                dec_name_candidates.add(domain_norm)
                                dec_name_candidates.add("@")
                            else:
                                dec_name_candidates.add(dec_name_norm)
                                dec_name_candidates.add(f"{dec_name_norm}.{domain_norm}")

                            for pr in prov_recs:
                                pr_name = pr.get("name") or pr.get("record_name") or ""
                                pr_type = (pr.get("type") or pr.get("record_type") or "").upper()
                                pr_content = pr.get("content") or pr.get("data") or pr.get("value") or ""
                                pr_name_norm = _norm(pr_name)
                                # apex kann domain oder '@' sein
                                if pr_name_norm in dec_name_candidates and pr_type == rtype:
                                    provider_value = pr_content
                                    break
                            if provider_value is not None:
                                try:
                                    rec.content_encrypted = encrypt_secret(kek, provider_value.encode())
                                except Exception:
                                    pass
                        except Exception:
                            # ignore provider errors; we'll still disable dyndns below
                            pass
                    rec.dyndns = bool(new_dyndns)
                if new_ttl is not None:
                    rec.ttl = new_ttl
                # content-änderung oder dyndns neu aktiv -> provider updaten und 'auto' speichern
                if new_content is not None:
                    # dyndns + auto: öff. ip verwenden
                    store_content = new_content
                    provider_content = new_content
                    if rec.dyndns and (not new_content or str(new_content).lower() == 'auto'):
                        def _get_public_ip(v6: bool = False):
                            try:
                                if v6:
                                    resp = requests.get("https://api64.ipify.org?format=json", timeout=10)
                                else:
                                    resp = requests.get("https://api.ipify.org?format=json", timeout=10)
                                if resp.status_code == 200:
                                    j = resp.json()
                                    return j.get("ip")
                            except Exception:
                                return None
                            return None

                        ip = None
                        if (rec.type or "").upper() == "A":
                            ip = _get_public_ip(v6=False)
                        elif (rec.type or "").upper() == "AAAA":
                            ip = _get_public_ip(v6=True)
                        if ip:
                            provider_content = ip
                            store_content = "auto"
                        else:
                            provider_content = None
                            store_content = "auto"
                    # provider updaten wenn ip vorhanden
                    if provider_content:
                        try:
                            # ttl=60 für dyndns
                            dns_client.update_record(domain, {"type": rec.type, "name": dec_name, "content": provider_content, "ttl": 60})
                        except Exception:
                            # ignore provider errors
                            pass
                    try:
                        rec.content_encrypted = encrypt_secret(kek, (store_content or "").encode())
                    except Exception:
                        pass
                elif new_dyndns is True:
                    # dyndns aktiv ohne content -> 'auto' setzen und provider updaten
                    def _get_public_ip(v6: bool = False):
                        try:
                            if v6:
                                resp = requests.get("https://api64.ipify.org?format=json", timeout=10)
                            else:
                                resp = requests.get("https://api.ipify.org?format=json", timeout=10)
                            if resp.status_code == 200:
                                j = resp.json()
                                return j.get("ip")
                        except Exception:
                            return None
                        return None

                    ip = None
                    if (rec.type or "").upper() == "A":
                        ip = _get_public_ip(v6=False)
                    elif (rec.type or "").upper() == "AAAA":
                        ip = _get_public_ip(v6=True)

                    if ip:
                        try:
                            dns_client.update_record(domain, {"type": rec.type, "name": dec_name, "content": ip, "ttl": 60})
                        except Exception:
                            pass
                    # 'auto' immer in db speichern
                    try:
                        rec.content_encrypted = encrypt_secret(kek, ("auto").encode())
                    except Exception:
                        pass
                    # ttl=60 in db
                    rec.ttl = 60
            updated += 1
        if updated:
            session.commit()
    except Exception:
        session.rollback()
        raise HTTPException(status_code=500, detail="Fehler beim Aktualisieren der Records")

    return {"updated": updated}





@api_router.delete("/records")
def delete_dns_record(
    record: dict = Body(...),
    session: Session = Depends(get_session),
    kek: bytes = Depends(get_session_kek),
    dns_client: LexiconDNSClient = Depends(get_dns_client),
):
    """Löscht einen DNS-Eintrag beim Provider und entfernt passende Einträge aus der DB.

    Erwartet im Body: { domain, name, type, content }
    """
    domain = (record.get("domain") or "").strip()
    name = (record.get("name") or "").strip()
    rtype = (record.get("type") or "").upper()
    content = (record.get("content") or "").strip()

    if not domain or not name or not rtype:
        raise HTTPException(status_code=400, detail="Fehlende Felder: domain, name und type sind erforderlich")

    # rufe Provider an
    try:
        provider_result = dns_client.delete_record(domain, {"type": rtype, "name": name, "content": content})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen beim Provider: {e}")

    # Falls Provider-Löschen erfolgreich, entferne passende DB-Einträge (entschlüsseln und vergleichen)
    api_entry = session.exec(select(ApiKey)).first()
    deleted_count = 0
    try:
        if api_entry:
            # Domain-Zeile ermitteln
            domain_row = _get_or_create_domain_entry(kek, session, api_entry, domain)
            # Records für Domain laden und matchen
            records = session.exec(select(Record).where(Record.domain_id == domain_row.id)).all()
            for rec in records:
                try:
                    dec_name = decrypt_secret(kek, rec.name_encrypted)
                    dec_content = decrypt_secret(kek, rec.content_encrypted)
                except Exception:
                    continue
                if dec_name == name and (rec.type == rtype) and (not content or dec_content == content):
                    session.delete(rec)
                    deleted_count += 1
            if deleted_count:
                session.commit()
    except Exception:
        # DB cleanup darf fehlschlagen ohne Provider-Fehler
        session.rollback()

    return {"provider_result": provider_result, "deleted_from_db": deleted_count}


def _fetch_and_store_domains_for_session(kek_bytes: bytes, session: Session):
    """hole und speichere domains"""
    api_entry = session.exec(select(ApiKey)).first()
    if not api_entry:
        return []

    # entschlüsseln
    key = decrypt_secret(kek_bytes, api_entry.api_key_encrypted)
    secret = decrypt_secret(kek_bytes, api_entry.api_secret_encrypted)
    dns = LexiconDNSClient(api_entry.provider_name.lower(), key, secret)
    domains = dns.get_domains()
    if not domains:
        return []

    # Avoid duplicate Domain entries: only add domains not already present (decrypted compare)
    existing = session.exec(select(Domain).where(Domain.api_key_id == api_entry.id)).all()
    existing_decrypted = set()
    for en in existing:
        try:
            existing_decrypted.add(decrypt_secret(kek_bytes, en.domain_encrypted))
        except Exception:
            continue

    for d in domains:
        if not _is_valid_domain(d):
            logging.warning("Skipping invalid domain while refresh-store: %s", d)
            continue
        if d in existing_decrypted:
            continue
        try:
            enc = encrypt_secret(kek_bytes, d.encode())
        except Exception:
            continue
    session.add(Domain(api_key_id=api_entry.id, domain_encrypted=enc))
    session.commit()
    return domains


def _fetch_and_store_records_for_session(kek_bytes: bytes, session: Session, record_type: str | None = None):
    """records holen und speichern (optional nach typ)"""
    api_entry = session.exec(select(ApiKey)).first()
    if not api_entry:
        return []

    # entschlüsseln
    key = decrypt_secret(kek_bytes, api_entry.api_key_encrypted)
    secret = decrypt_secret(kek_bytes, api_entry.api_secret_encrypted)
    dns = LexiconDNSClient(api_entry.provider_name.lower(), key, secret)

    # lade domains aus DB
    domain_entries = session.exec(select(Domain).where(Domain.api_key_id == api_entry.id)).all()
    domains = []
    domain_id_by_name = {}
    for en in domain_entries:
        try:
            d = decrypt_secret(kek_bytes, en.domain_encrypted)
            domains.append(d)
            if en.id is not None:
                domain_id_by_name[d] = en.id
        except Exception:
            continue

    # Build a mapping of existing records so we can avoid overwriting 'auto' sentinels.
    # alle records für die Domains (by domain_id)
    domain_ids = [en.id for en in domain_entries if en.id is not None]
    existing_records = session.exec(select(Record).where(Record.domain_id.in_(domain_ids))).all() if domain_ids else []
    existing_map: dict = {}
    for rec in existing_records:
        try:
            # Domain aus Relation entschlüsseln
            if not rec.domain:
                continue
            dec_domain = decrypt_secret(kek_bytes, rec.domain.domain_encrypted)
            dec_name = decrypt_secret(kek_bytes, rec.name_encrypted)
            dec_content = decrypt_secret(kek_bytes, rec.content_encrypted)
            key = (dec_domain, dec_name, (rec.type or "").upper())
            existing_map[key] = (rec, dec_content)
        except Exception:
            continue

    stored = []

    # pro domain parallel holen (netzwerk), db-schritte im haupt-thread
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _fetch_domain_records(domain_name: str):
            try:
                # eigener client je thread
                thread_dns = LexiconDNSClient(api_entry.provider_name.lower(), key, secret)
                recs = thread_dns.list_records(domain_name) or []
                return (domain_name, recs)
            except Exception:
                return (domain_name, [])

        max_workers = min(10, max(2, len(domains)))
        futures = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for d in domains:
                futures.append(ex.submit(_fetch_domain_records, d))

            for f in as_completed(futures):
                try:
                    d, records = f.result()
                except Exception:
                    continue

                # records für diese domain im db-thread verarbeiten
                for r in records:
                    try:
                        rtype = (r.get("type") or r.get("record_type") or "").upper()
                        if record_type and rtype != (record_type or "").upper():
                            continue
                        name_raw = r.get("name") or r.get("record_name") or ""
                        content_raw = r.get("content") or r.get("data") or r.get("value") or ""
                        # ttl extrahieren (falls vorhanden)
                        ttl_raw = None
                        for ttl_key in ("ttl", "ttl_seconds", "ttl_sec", "time_to_live"):
                            if ttl_key in r:
                                ttl_raw = r.get(ttl_key)
                                break
                        ttl_val = None
                        try:
                            if ttl_raw is not None and str(ttl_raw).strip() != "":
                                ttl_val = int(ttl_raw)
                        except Exception:
                            ttl_val = None

                        # 'auto' in db bleibt unangetastet
                        key_lookup = (d, name_raw or "", (rtype or "").upper())
                        existing = existing_map.get(key_lookup)
                        if existing and isinstance(existing, tuple) and (existing[1] or "") == "auto":
                            continue

                        # name/content verschlüsseln
                        try:
                            name_enc = encrypt_secret(kek_bytes, name_raw or "")
                            content_enc = encrypt_secret(kek_bytes, content_raw or "")
                        except Exception:
                            continue

                        if existing:
                            rec_obj = existing[0]
                            try:
                                rec_obj.content_encrypted = content_enc
                                rec_obj.ttl = ttl_val
                                session.add(rec_obj)
                            except Exception:
                                continue
                        else:
                            # domain_id lookup
                            dom_id = domain_id_by_name.get(d)
                            if not dom_id:
                                # Domain existiert nicht (sollte selten passieren) -> anlegen
                                dom_row = _get_or_create_domain_entry(kek_bytes, session, api_entry, d)
                                dom_id = dom_row.id
                                domain_id_by_name[d] = dom_id
                            rec = Record(domain_id=dom_id, name_encrypted=name_enc, type=rtype, content_encrypted=content_enc, ttl=ttl_val)
                            session.add(rec)
                            stored.append(rec)
                    except Exception:
                        continue

    except Exception:
        # fallback: sequentiell
        for d in domains:
            try:
                records = dns.list_records(d) or []
            except Exception:
                continue
            for r in records:
                try:
                    rtype = (r.get("type") or r.get("record_type") or "").upper()
                    if record_type and rtype != (record_type or "").upper():
                        continue
                    name_raw = r.get("name") or r.get("record_name") or ""
                    content_raw = r.get("content") or r.get("data") or r.get("value") or ""
                    ttl_raw = None
                    for ttl_key in ("ttl", "ttl_seconds", "ttl_sec", "time_to_live"):
                        if ttl_key in r:
                            ttl_raw = r.get(ttl_key)
                            break
                    ttl_val = None
                    try:
                        if ttl_raw is not None and str(ttl_raw).strip() != "":
                            ttl_val = int(ttl_raw)
                    except Exception:
                        ttl_val = None

                    key_lookup = (d, name_raw or "", (rtype or "").upper())
                    existing = existing_map.get(key_lookup)
                    if existing and isinstance(existing, tuple) and (existing[1] or "") == "auto":
                        continue
                    try:
                        name_enc = encrypt_secret(kek_bytes, name_raw or "")
                        content_enc = encrypt_secret(kek_bytes, content_raw or "")
                    except Exception:
                        continue
                    if existing:
                        rec_obj = existing[0]
                        try:
                            rec_obj.content_encrypted = content_enc
                            rec_obj.ttl = ttl_val
                            session.add(rec_obj)
                        except Exception:
                            continue
                    else:
                        dom_id = domain_id_by_name.get(d)
                        if not dom_id:
                            dom_row = _get_or_create_domain_entry(kek_bytes, session, api_entry, d)
                            dom_id = dom_row.id
                            domain_id_by_name[d] = dom_id
                        rec = Record(domain_id=dom_id, name_encrypted=name_enc, type=rtype, content_encrypted=content_enc, ttl=ttl_val)
                        session.add(rec)
                        stored.append(rec)
                except Exception:
                    continue

    session.commit()
    return stored


@api_router.post("/domains/refresh")
def refresh_domains(session: Session = Depends(get_session), kek: bytes = Depends(get_session_kek)):
    """domains aktualisieren"""
    try:
        domains = _fetch_and_store_domains_for_session(kek, session)
        return {"domains": domains}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Aktualisieren der Domains: {e}")


@api_router.post("/records/refresh")
def refresh_records(record_type: str | None = None, session: Session = Depends(get_session), kek: bytes = Depends(get_session_kek)):
    """dns-einträge aktualisieren (optional nach typ)"""
    try:
        rt = (record_type or None)
        if isinstance(rt, str):
            rt = rt.upper()
        stored = _fetch_and_store_records_for_session(kek, session, record_type=rt)
        return {"stored": len(stored), "type": rt}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Aktualisieren der Records: {e}")


@api_router.get("/records")
def get_records(record_type: str | None = None, domain: str | None = None, session: Session = Depends(get_session), kek: bytes = Depends(get_session_kek)):
    """records aus db liefern (optional nach typ/domain)"""
    try:
        q = select(Record)
        if record_type:
            q = q.where(Record.type == record_type.upper())
        entries = session.exec(q).all()
        out = []
        for e in entries:
            # domain via relation
            decrypted_domain = ""
            try:
                if e.domain:
                    decrypted_domain = decrypt_secret(kek, e.domain.domain_encrypted)
            except Exception:
                decrypted_domain = ""
            # if a domain filter was provided, skip non-matching decrypted domains
            if domain and decrypted_domain != domain:
                continue
            try:
                name = decrypt_secret(kek, e.name_encrypted)
            except Exception:
                name = ""
            try:
                content = decrypt_secret(kek, e.content_encrypted)
            except Exception:
                content = ""
            out.append({
                "domain": decrypted_domain,
                "name": name,
                "type": e.type,
                "content": content,
                "ttl": e.ttl,
                "dyndns": bool(e.dyndns),
            })
        return {"records": out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Lesen der Records: {e}")


@api_router.get("/domains")
def get_domains(session: Session = Depends(get_session), kek: bytes = Depends(get_session_kek)):
    """gibt domains zurück"""
    kek_bytes = kek
    api_entry = session.exec(select(ApiKey)).first()
    q = select(Domain)
    if api_entry:
        q = q.where(Domain.api_key_id == api_entry.id)
    entries = session.exec(q).all()
    out = []
    for en in entries:
        try:
            d = decrypt_secret(kek_bytes, en.domain_encrypted)
            out.append(d)
        except Exception:
            # Einträge überspringen, die sich nicht entschlüsseln lassen
            continue
    return {"domains": out}


app.include_router(api_router)

# Optional: SPA aus frontend/dist ausliefern, wenn vorhanden
try:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dist_dir = os.path.join(project_root, "frontend", "dist")
    if os.path.isdir(dist_dir):
        app.mount("/", StaticFiles(directory=dist_dir, html=True), name="frontend")
except Exception:
    pass