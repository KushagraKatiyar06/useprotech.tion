FROM python:3.11-slim

WORKDIR /app

# System deps: gcc/libmagic for cryptography/python-magic, plus the native
# tools sandbox/analyze.py shells out to (exiftool, binwalk, yara, mono-utils).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    binutils \
    libimage-exiftool-perl \
    binwalk \
    yara \
    mono-utils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
