FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py /app/app.py

RUN mkdir -p /app/logs

EXPOSE 8081

CMD ["python", "/app/app.py"]
