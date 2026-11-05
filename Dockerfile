FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py migrations.py .
COPY index.html app.js i18n.js style.css tona-logo.png ./
COPY install.html install.css install.js sw.js manifest.webmanifest icon-180.png icon-192.png icon-512.png ./pwa/
ENV TONA_DATA_DIR=/data
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
