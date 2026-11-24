# syntax=docker/dockerfile:1
FROM python:3.14-slim AS build
RUN pip install --no-cache-dir uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.14-slim
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin openverdict
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 8000 9100
ENTRYPOINT ["openverdict"]
CMD ["api"]
