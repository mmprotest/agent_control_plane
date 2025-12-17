FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential libpq-dev && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY alembic ./alembic
COPY policies ./policies
RUN pip install --upgrade pip && pip install -e .[dev]

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV APP_ENV=production

EXPOSE 8000

CMD ["uvicorn", "acp_backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
