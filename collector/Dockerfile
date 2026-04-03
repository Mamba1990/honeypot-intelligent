FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir numpy joblib scikit-learn --pre
COPY collector.py /app/collector.py
CMD ["python", "-u", "/app/collector.py"]
