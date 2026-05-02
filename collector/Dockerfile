FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir numpy joblib scikit-learn==1.7.2
COPY collector.py /app/collector.py
COPY feature_extraction.py /app/feature_extraction.py
CMD ["python", "-u", "/app/collector.py"]
