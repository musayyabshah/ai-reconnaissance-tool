FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY ai_recon ./ai_recon
RUN pip install --no-cache-dir .
RUN mkdir -p /app/data /app/reports
EXPOSE 8000
CMD ["uvicorn", "ai_recon.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
