# --- Build stage ---
FROM python:3.11-slim AS base

# Don't write .pyc files and enable unbuffered output (important for log visibility)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (layer is cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app/ ./app/

# Create the audit log directory inside the container
RUN mkdir -p /app/audit_logs

# Expose the FastAPI port
EXPOSE 8000

# Default: run the API server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
