FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY anchor/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && useradd -u 10001 -m aegis && mkdir /anchor_data && chown 10001:10001 /anchor_data
COPY common /app/common
COPY anchor /app/anchor
USER 10001:10001
EXPOSE 8003
CMD ["uvicorn","anchor.main:app","--host","0.0.0.0","--port","8003","--no-access-log","--no-proxy-headers"]
