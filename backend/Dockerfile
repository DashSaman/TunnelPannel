FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc libpq-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -r -u 10001 netauto && \
    mkdir -p /app/data /app/logs && \
    chown -R netauto:netauto /app

USER netauto

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
