FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY reconstruction/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && useradd -u 10001 -m aegis && mkdir /data && chown 10001:10001 /data
COPY common /app/common
COPY reconstruction /app/reconstruction
COPY frontend /app/frontend
USER 10001:10001
EXPOSE 8002
CMD ["uvicorn","reconstruction.main:app","--host","0.0.0.0","--port","8002","--no-access-log","--no-proxy-headers"]
