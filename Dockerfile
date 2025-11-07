## backend-image (fastapi + uvicorn)
## prod: kein frontend-build hierin; nginx dient als tls-terminator/static

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/90-handle-env.sh /docker-entrypoint.d/90-handle-env.sh
RUN chmod +x /entrypoint.sh /docker-entrypoint.d/90-handle-env.sh && \
    mkdir -p /docker-entrypoint.d

EXPOSE 8000
CMD ["/entrypoint.sh"]
