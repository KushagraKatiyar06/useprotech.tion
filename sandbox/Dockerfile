FROM node:18-slim

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && pip3 install jsbeautifier python-dotenv "e2b==2.19.0" --break-system-packages

WORKDIR /analysis
COPY analyze.py .
COPY .env .

ENTRYPOINT ["python3", "analyze.py"]