FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY worker.py .
RUN useradd -r -u 10003 netauto && mkdir -p /app/data /app/logs && chown -R netauto:netauto /app
USER netauto
CMD ["python", "worker.py"]
