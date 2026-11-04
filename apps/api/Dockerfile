FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY migrations ./migrations
USER 10001:10001
EXPOSE 8000
# X-Forwarded-For는 web 컨테이너(고정 IP)가 보낸 것만 신뢰
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", \
     "--proxy-headers", "--forwarded-allow-ips", "172.30.0.10"]
