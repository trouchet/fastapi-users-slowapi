import pytest
from datetime import timedelta
from fastapi import status 

from app.main import (
    settings, 
    revoke_token, 
    create_access_token,
    decode_access_token,
    is_token_revoked,
    get_username_from_token,
)

def test_create_access_token():
    data = {"sub": "john_doe"}
    token = create_access_token(data)
    assert isinstance(token, str)
    
    payload = decode_access_token(token)
    assert payload["sub"] == "john_doe"

def test_expired_token():
    data = {"sub": "john_doe"}
    expired_token = create_access_token(data, expires_delta=timedelta(seconds=-1))
    
    with pytest.raises(Exception) as exc_info:
        decode_access_token(expired_token)
    
    assert "Token has expired" in str(exc_info.value)

def test_revoke_token(mock_redis):
    token = create_access_token({"sub": "john_doe"})
    mock_redis.setex.return_value = None
    
    revoke_token(token)
    
    mock_redis.setex.assert_called_once_with(f"revoked_token:{token}", settings.TOKEN_TTL, 1)
    
    mock_redis.get.return_value = b"1"
    assert is_token_revoked(token) is True

def test_valid_token_not_revoked(mock_redis):
    token = create_access_token({"sub": "john_doe"})
    mock_redis.get.return_value = None

    assert is_token_revoked(token) is False

def test_get_username_from_valid_token():
    token = create_access_token({"sub": "john_doe"})
    username = get_username_from_token(token)
    assert username == "john_doe"

def test_login_for_access_token(client):
    response = client.post(
        "/token",
        json={"username": "john_doe", "password": "password123"}
    )

    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()

    response = client.post(
        "/token",
        json={"username": "john_doe", "password": "wrongpassword"}
    )
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

