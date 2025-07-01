# Use the official Python image as the base image
FROM python:3.10-slim-buster

# Install uv.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV COMPOSE_BAKE=true

# Copy the application into the container.
COPY . /app

# Set the working directory
WORKDIR /app
RUN uv lock

RUN --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Reset the entrypoint, don't invoke `uv`
ENTRYPOINT []

# Command to run the FastAPI application
CMD ["uvicorn", "app.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"]