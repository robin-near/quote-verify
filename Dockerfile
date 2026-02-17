FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir \
    "cryptography>=46.0.5" \
    "httpx>=0.28.1"

COPY verify_tdx_quote.py web_ui.py ./
COPY web ./web
COPY examples ./examples

EXPOSE 8080

CMD ["python", "web_ui.py", "--host", "0.0.0.0", "--port", "8080"]
