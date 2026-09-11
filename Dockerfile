FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY app /app
COPY worker /app/worker
COPY agents /app/agents
COPY ops /app/ops
COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

VOLUME ["/data"]

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "main:app", "--no-control-socket", "--access-logfile", "-", "--error-logfile", "-"]
