# fastapi-users-slowapi

A FastAPI project demonstrating user authentication, JWT token management, dynamic rate limiting with SlowAPI, and user plans, using Redis for state and token revocation.

## Features
- **User authentication** with JWT tokens
- **Dynamic rate limiting** per user plan (SlowAPI)
- **User plans**: free, premium, admin (with different rate limits)
- **Token revocation** and logout
- **Redis** for token and rate limit storage
- **Scheduler** for periodic cleanup
- **Comprehensive API** with endpoints for login, refresh, logout, plan-limited access, and more
- **Testing** with pytest
- **Dockerized** for easy setup

## Requirements
- Python 3.10+
- Docker & Docker Compose (for containerized setup)

## Quick Start (Docker)

```sh
docker compose up --build
```

- The API will be available at [http://localhost:8000](http://localhost:8000)
- Redis will be available at port 6379
- Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## Local Development

1. Install [uv](https://github.com/astral-sh/uv):
   ```sh
   pip install uv
   ```
2. Install dependencies:
   ```sh
   uv sync
   ```
3. Start Redis locally (or use Docker):
   ```sh
   docker run -p 6379:6379 redis:latest
   ```
4. Run the app:
   ```sh
   uvicorn app.main:app --reload
   ```

## User Database & Plans

This project uses a **fake in-memory user database** for demonstration:

- `john_doe` / `password123` (plan: premium)
- `jane_doe` / `password456` (plan: free)

**Plans and rate limits:**
- `free`: 2 requests/minute
- `premium`: 10 requests/minute
- `admin`: 9999 requests/minute

## API Endpoints

| Method | Path                     | Description                                 |
|--------|--------------------------|---------------------------------------------|
| POST   | `/token`                 | Login, get JWT access token                 |
| POST   | `/refresh`               | Refresh JWT token                           |
| POST   | `/logout`                | Logout (revoke token)                       |
| POST   | `/revoke`                | Revoke a token manually                     |
| GET    | `/is_token_revoked`      | Check if a token is revoked                 |
| GET    | `/plan-limited-endpoint` | Rate-limited endpoint (plan-based)          |
| GET    | `/premium-only-endpoint` | Premium/admin-only endpoint                 |
| GET    | `/users/me`              | Get current user info                       |
| GET    | `/rate-limit-status`     | Check rate limit status                     |
| GET    | `/health`                | Health check                                |

### Example: Login
```sh
curl -X POST http://localhost:8000/token \
  -H 'Content-Type: application/json' \
  -d '{"username": "john_doe", "password": "password123"}'
```

### Example: Access a protected endpoint
```sh
curl -H "Authorization: Bearer <access_token>" http://localhost:8000/users/me
```

## Rate Limiting
- Uses [SlowAPI](https://github.com/laurentS/slowapi) for per-plan rate limits
- Limits are enforced per endpoint and user plan
- Exceeding the limit returns HTTP 429 with a retry time

## Testing

Run tests with:
```sh
just test
```
Or directly:
```sh
pytest
```

## Development Commands

- `just build`   — Build Docker image
- `just up`      — Start services
- `just down`    — Stop services
- `just restart` — Rebuild and restart
- `just test`    — Run tests
- `just cov`     — Run tests with coverage
- `just clean`   — Clean Docker resources

## Environment Variables
- Configure via `.env` file (see `Settings` in `app/main.py` for options)
- Example variables: `SECRET_KEY`, `REDIS_URI`, etc.

## Contributing
Pull requests and issues are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

**License:** MIT
