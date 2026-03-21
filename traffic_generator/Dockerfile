FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY http_generator.py /app/http_generator.py
COPY ssh_log_generator.py /app/ssh_log_generator.py

CMD ["python", "/app/http_generator.py"]
