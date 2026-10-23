FROM python:3.12-slim
WORKDIR /srv
COPY pyproject.toml .
COPY secure ./secure
RUN pip install --no-cache-dir .
COPY templates ./templates
COPY static ./static
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "secure.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
