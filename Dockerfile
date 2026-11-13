FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production \
    ENABLE_API_DOCS=false \
    TRUST_PROXY_HEADERS=true \
    PORT=8000

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api_security.py backend_core.py threat_filter_core.py ./

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend_core:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=\"${FORWARDED_ALLOW_IPS:-127.0.0.1}\" --workers 1 --log-level info"]
