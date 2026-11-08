FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY agent/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && useradd -u 10001 -m aegis
COPY common /app/common
COPY agent /app/agent
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn","agent.main:app","--host","0.0.0.0","--port","8000","--workers","1","--no-access-log","--no-proxy-headers"]
