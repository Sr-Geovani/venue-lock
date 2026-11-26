FROM python:3.12-slim
RUN pip install --no-cache-dir 'aiohttp>=3.9,<4'
WORKDIR /app
COPY venuelock.py pwa.html ./
ENV VENUELOCK_DB=/data/venuelock.db PYTHONUNBUFFERED=1
USER 1000:1000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=4)"
CMD ["python", "venuelock.py", "serve", "--host", "0.0.0.0", "--port", "8080"]
