FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bot.py translations.py ./
RUN useradd -r -u 10002 netauto && chown -R netauto:netauto /app
USER netauto
CMD ["python", "bot.py"]
