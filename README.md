dns-manager

kurz
- backend: fastapi + sqlite + dyndns-worker
- frontend: react spa via nginx (https 443) -> proxy /api an backend
- tls: self-signed default; STRICT_TLS=1 erzwingt echte certs

prod docker
```
docker compose up --build -d
```
-> https://localhost (spa + api)

services
- backend: port 8000 intern
- web: 443 (ssl), 80 (redirect)

certs
- ordner `certs/` mount auf /certs
- dateien: cert.pem + key.pem
- fehlen sie: wird self-signed erzeugt (wenn STRICT_TLS=0)

wichtige env (.env)
- SECRET_KEY (pflicht, random)
- DROP_AND_RECREATE_DB=0/1 (vorsicht: datenverlust)
- ALLOW_ORIGINS / FRONTEND_ORIGIN (cors, leer = *)
- MASTER_KEY / MASTER_KEY_FILE (optional für headless dyndns)
- TRACE_PROVIDER_HTTP=0/1 (nur kurz aktivieren)

setup flow
1. start compose
2. GET /api/setup -> needs_setup true
3. POST /api/setup (passwort + provider creds)
4. POST /api/login -> session + worker

dyndns
- records mit dyndns=true + content "auto" werden alle ~60s aktualisiert

strikt tls
- setze STRICT_TLS=1 im web-service -> container startet nicht ohne echte certs

lokale entwicklung (optional)
```
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
frontend dev separat
```
cd frontend
npm ci
npm run dev
```

tests
```
pytest -q
```

self-signed cert erzeugen
```
mkdir certs
openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=localhost" -keyout certs/key.pem -out certs/cert.pem
```
separate docker images

backend
```
docker build -t dns-manager-backend .
docker run -d --name backend -v ./secrets:/app/secrets dns-manager-backend
```

frontend  
```
docker build -f Dockerfile.frontend -t dns-manager-frontend .
docker run -d --name frontend -p 443:443 -p 80:80 -v ./certs:/certs --link backend dns-manager-frontend
```

verteilte systeme
```
# backend auf system A
docker run -d -p 8000:8000 --name backend dns-manager-backend

# frontend auf system B  
docker run -d -p 443:443 -p 80:80 -e BACKEND_HOST=192.168.1.100 -e BACKEND_PORT=8000 dns-manager-frontend
```

tls parameter
- mount ./certs mit cert.pem + key.pem
- oder base64 env vars: CERT_PEM_B64, KEY_PEM_B64
- STRICT_TLS=1 erzwingt echte certs

secrets handling
- priorität: env > /run/secrets/SECRET_KEY > SECRET_KEY_FILE > generiert/persistent
- generierte keys werden in /app/secrets/secret.key gespeichert
- für produktion: docker secrets oder gemountete dateien verwenden
