# Built and smoke-tested in CI (.github/workflows/docker.yml). Not hardened: see docs/KNOWN-LIMITS.md before using it with anything real.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONUTF8=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY omnios ./omnios
COPY sdk ./sdk
# /data holds every customer's database, signing key and secrets: mount a volume and back it up.
VOLUME /data
EXPOSE 8000
CMD ["python", "-m", "omnios", "serve", "--root", "/data", "--host", "0.0.0.0", "--port", "8000"]
