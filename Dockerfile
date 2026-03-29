FROM node:18-slim

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-magic \
    && pip3 install jsbeautifier --break-system-packages

WORKDIR /analysis
COPY analyze.py .

CMD ["python3", "analyze.py"]