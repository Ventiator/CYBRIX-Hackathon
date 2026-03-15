FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# .env is NOT copied — mount it at runtime or pass via environment variables
# This is safer for credentials

EXPOSE 5000

# Use python directly (not gunicorn) to preserve background threads
CMD ["python", "app.py"]