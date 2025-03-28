import pytest
from jose import jwt
from datetime import datetime, timedelta, timezone


from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_redis():
    with patch("app.main.redis_client") as mock:
        redis_instance = mock.return_value
        redis_instance.setex = AsyncMock()
        yield redis_instance

# Helper function to create JWT access token
def create_access_token(username: str, expires_delta: timedelta = timedelta(minutes=5)):
    data = {"sub": username}
    expire = datetime.now(timezone.utc) + expires_delta
    data.update({"exp": expire.timestamp()})
    return jwt.encode(data, "mysecretkey", algorithm="HS256")

@pytest.fixture
def valid_token():
    return create_access_token("john_doe")

@pytest.fixture
def expired_token():
    return create_access_token("john_doe", expires_delta=timedelta(seconds=-1))

@pytest.fixture
def revoked_token(mock_redis, valid_token):
    mock_redis.get.return_value = 1  # Simulate token being revoked
    return valid_token

