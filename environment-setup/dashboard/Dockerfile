FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask requests

COPY app.py .
COPY templates/ templates/

RUN mkdir -p /app/db

EXPOSE 5000

CMD ["python", "-u", "app.py"]
