FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc build-essential make automake libtool pkg-config \
      python3-dev libssl-dev libffi-dev libjansson-dev libmagic-dev \
      yara \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get purge -y --auto-remove gcc build-essential make automake libtool pkg-config python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

CMD ["python3", "app.py"]