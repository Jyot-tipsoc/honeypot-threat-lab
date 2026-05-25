FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests

COPY parser.py .

RUN mkdir -p /app/db /cowrie_logs

CMD ["python", "-u", "parser.py"]
