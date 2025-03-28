
from app.main import settings, revoke_token

from unittest.mock import Mock

def test_revoke_token(mocker):
    # Mocka apenas a instância de redis_client
    mock_redis = mocker.patch("app.main.redis_client")
    
    # Define o comportamento do método setex
    mock_redis.setex = Mock()

    # Chama a função que queremos testar
    revoke_token("fake_token")

    # Verifica se o Redis armazenou o token revogado com TTL
    mock_redis.setex.assert_called_once_with("revoked_token:fake_token", settings.TOKEN_TTL, 1)
