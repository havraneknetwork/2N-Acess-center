FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Instalace závislostí
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Zkopírování aplikace
COPY . .

# Vytvoření a přepnutí na neprivilegovaného uživatele
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Spuštění produkčního WSGI serveru gunicorn s přímým logováním do stdout/stderr
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "15", "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "--enable-stdio-inheritance", "app:app"]
