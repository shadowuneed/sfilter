FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /ms-playwright && python -m playwright install --with-deps chromium

COPY . .

RUN groupadd --system argus \
    && useradd --system --gid argus --create-home --home-dir /home/argus argus \
    && mkdir -p /var/data \
    && chown -R argus:argus /app /ms-playwright /var/data

USER argus

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
