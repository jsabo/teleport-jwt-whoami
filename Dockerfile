FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY templates ./templates

# Numeric, so runAsNonRoot can be verified without a runAsUser in a manifest.
RUN useradd --system --uid 65532 --no-create-home app
USER 65532:65532
EXPOSE 8080
ENV PORT=8080
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers 2 --access-logfile - app:app"]
