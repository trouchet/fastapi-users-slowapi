# justfile

# Task to build the Docker image
build:
  docker compose build

# Task to run the FastAPI app in a Docker container
up:
  docker compose up -d

# Task to build and run the Docker container
deploy:
  just build
  just up

# Task to down the FastAPI app from a Docker container
down:
  docker compose down

# Task to build and run the Docker container (for quick start)
restart:
  just down
  just build
  just up

# Task to run tests inside a Docker container
test:
  pytest

# Task to run tests with coverage inside a Docker container
cov:
  pytest --cov=app --cov-report=term-missing

watch:
  ptw --quiet --spool 200 --clear --nobeep --ext=.py

# Task to clean temporary files in Docker (e.g., remove containers, volumes, and images)
clean:
  docker system prune -f
  docker volume prune -f
  docker image prune

