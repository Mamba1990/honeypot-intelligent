FROM python:3.11-slim

WORKDIR /app

# Installer les mêmes versions que lors du training
RUN pip install --no-cache-dir numpy joblib scikit-learn==1.7.2

COPY collector.py /app/collector.py

#CMD ["python", "/app/collector.py"]
CMD ["python", "-u", "/app/collector.py"]
