import pytest
from fastapi.testclient import TestClient
from jose import jwt
from datetime import datetime, timedelta, timezone

from unittest.mock import AsyncMock, patch

from app.main import (
    app, 
    settings, 
    fake_users_db, 
    plan_limits, 
    create_access_token,
)
        
@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def mock_redis(mocker):
    mock_redis = mocker.patch("app.main.redis_client")
    mock_redis.get.return_value = None
    mock_redis.setex.return_value = None
    return mock_redis

@pytest.fixture(autouse=True)
def mock_redis_uri(monkeypatch):
    # Mock the REDIS_URI setting to use in-memory storage during tests
    monkeypatch.setattr(settings, "REDIS_URI", "memory://")

@pytest.fixture
def fake_username():
    return 'john_doe'

# Fixtures to mock data for tests
@pytest.fixture
def fake_user(fake_username: str):
    return fake_users_db[fake_username]

@pytest.fixture
def fake_plan(fake_user: dict):
    return plan_limits[fake_user['plan']]

@pytest.fixture
def client():
    # Return the test client for FastAPI
    return TestClient(app)

# Fixture to generate the authentication token
@pytest.fixture
def token(fake_user: dict):
    access_token = create_access_token(data={"sub": fake_user["username"]})
    return f"Bearer {access_token}"

# Fixture to include the token in the Authorization header
@pytest.fixture
def auth_headers(token: str):
    return {"Authorization": token}