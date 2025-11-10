dns-manager

kurz
- backend: fastapi + sqlite + dyndns-worker
- frontend: react spa via nginx (https 443) -> proxy /api an backend
- tls: self-signed default; STRICT_TLS=1 erzwingt echte certs
- secure mode: SECURE_MODE=1 erzwingt vorhandene secrets (kein auto-fallback)

start (einfach)
```
docker compose up --build -d
```
-> https://localhost (spa + api) (auto self-signed, falls keine certs)

services
- backend: port 8000 intern
- web: 443 (ssl), 80 (redirect)

parameter (env)
- STRICT_TLS=0/1 (1 = keine self-signed erlauben)
- SECURE_MODE=0/1 (1 = keine auto-generation von SECRET_KEY / MASTER_KEY)
- SECRET_KEY / SECRET_KEY_FILE / docker secret (pflicht bei SECURE_MODE=1)
- MASTER_KEY / MASTER_KEY_FILE / docker secret (empfohlen bei SECURE_MODE=1)
- BACKEND_HOST / BACKEND_PORT (frontend -> api, default service-name)
- CERT_PEM_B64 / KEY_PEM_B64 (tls direkt per env base64)
- CERT_CN (cn für self-signed generierung, default localhost)
- FRONTEND_ORIGIN / ALLOW_ORIGINS (cors, leer = *)
- DROP_AND_RECREATE_DB=0/1 (vorsicht: datenverlust)
- TRACE_PROVIDER_HTTP=0/1 (kurz aktivieren für debug)
- SESSION_COOKIE_NAME (default session_id)

certs
- ordner `certs/` mount auf /certs (cert.pem + key.pem)
- alternativ base64 env: CERT_PEM_B64 + KEY_PEM_B64
- STRICT_TLS=1: container bricht ab falls fehlend

secure defaults ohne parameter
- SECRET_KEY wird random erzeugt und persistent gespeichert
- MASTER_KEY wird random erzeugt (dev) falls nicht gesetzt
- self-signed cert falls keines vorhanden

produktion (empfohlen)
1. certs bereitstellen (volume oder base64 env, STRICT_TLS=1)
2. SECRET_KEY als docker secret oder file / env setzen
3. MASTER_KEY als docker secret oder file / env setzen
4. SECURE_MODE=1 setzen
5. compose starten
 6. BACKEND_HOST/BACKEND_PORT nur verändern falls getrennte systeme

setup flow
1. compose start
2. GET /api/setup -> needs_setup true
3. POST /api/setup (passwort + provider creds)
4. POST /api/login -> session + worker

dyndns
- records mit dyndns=true + content "auto" ~60s aktualisiert

getrennte systeme
```
# backend (system A)
docker run -d -p 8000:8000 --name backend -e SECRET_KEY=xxx dns-manager-backend

# frontend (system B)
docker run -d -p 443:443 -p 80:80 -e BACKEND_HOST=192.168.1.100 -e BACKEND_PORT=8000 dns-manager-frontend
```

tls varianten
- volume `./certs` -> /certs
- env base64 CERT_PEM_B64 / KEY_PEM_B64
- self-signed auto (nur STRICT_TLS=0)
 - vorhandene public cert chain + key einfach rein mounten oder per env b64

secrets handling
- priorität: env > /run/secrets/* > *_FILE > persistent generiert (nur SECURE_MODE=0)
- generierte keys in /app/secrets

tests
```
pytest -q
```

lokale entwicklung
```
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
frontend dev
```
cd frontend
npm ci
npm run dev
```

self-signed cert manuell
```
mkdir certs
openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=localhost" -keyout certs/key.pem -out certs/cert.pem
```

separate builds
```
docker build -t dns-manager-backend .
docker build -f Dockerfile.frontend -t dns-manager-frontend .
```

run einzeln
```
docker run -d --name backend -v ./secrets:/app/secrets dns-manager-backend
docker run -d --name frontend -p 443:443 -p 80:80 -v ./certs:/certs --link backend dns-manager-frontend
```

hinweis
- SECURE_MODE=1 + STRICT_TLS=1 für produktiv
- docker secrets statt plain env für keys bevorzugen
- HSTS aktiv (max-age 31536000 preload). Für rein internes Testen kann Header im nginx.conf entfernt werden.

ohne compose (direkte docker run beispiele)
```
# backend (prod, mit docker secrets)
printf "$(openssl rand -base64 32)" | docker secret create dns_secret_key -
printf "$(openssl rand -base64 32)" | docker secret create dns_master_key -
docker run -d --name dns-backend \
	--secret dns_secret_key \
	--secret dns_master_key \
	-e SECURE_MODE=1 -e STRICT_TLS=1 \
	-p 8000:8000 \
	dns-manager-backend:release

# frontend (mit bereitgestelltem cert-volume)
docker run -d --name dns-frontend \
	-e STRICT_TLS=1 -e BACKEND_HOST=dns-backend -e BACKEND_PORT=8000 \
	-v $(pwd)/certs:/certs:ro \
	-p 443:443 -p 80:80 \
	dns-manager-frontend:release
```

cert per base64 env (falls kein volume)
```
export CERT_PEM_B64=$(base64 -w0 certs/cert.pem)
export KEY_PEM_B64=$(base64 -w0 certs/key.pem)
docker run -d --name dns-frontend \
	-e CERT_PEM_B64 -e KEY_PEM_B64 -e STRICT_TLS=1 \
	-e BACKEND_HOST=192.168.1.10 -e BACKEND_PORT=8000 \
	-p 443:443 -p 80:80 dns-manager-frontend:release
```

split host (frontend extern, backend intern)
```
# backend server
docker run -d --name dns-backend -e SECURE_MODE=1 -e SECRET_KEY=... -e MASTER_KEY=... -p 8000:8000 dns-manager-backend:release

# firewall: nur frontend-host darf 8000 erreichen

# frontend server
docker run -d --name dns-frontend -e BACKEND_HOST=<backend-ip> -e BACKEND_PORT=8000 -e STRICT_TLS=1 -v /opt/certs:/certs:ro -p 443:443 -p 80:80 dns-manager-frontend:release
```

update images (neue version bauen)
```
docker build -t dns-manager-backend:release .
docker build -f Dockerfile.frontend -t dns-manager-frontend:release .
```

rotierende secrets
- backend neu starten nachdem docker secret rotiert wurde
- session cookies invalidieren sich bei SECRET_KEY wechsel

hardening tipps
- setze CORS auf spezifische domain (FRONTEND_ORIGIN=https://dns.example.com)
- verwende reverse proxy davor (optional rate limiting)
- reguliere zugriff auf 8000/tcp ausschließlich intern
- aktiviere strikte firewall regeln (nur 443 offen)
