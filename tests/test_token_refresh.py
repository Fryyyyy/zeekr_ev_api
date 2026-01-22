import threading
import json
import pytest
from unittest.mock import MagicMock, patch
from zeekr_ev_api.client import ZeekrClient
from zeekr_ev_api.exceptions import AuthException
from zeekr_ev_api import network

@pytest.fixture
def client():
    c = ZeekrClient(
        username="testuser",
        password="testpassword",
        hmac_access_key="key",
        hmac_secret_key="secret",
        password_public_key="pubkey",
        prod_secret="prodsecret",
    )
    c.bearer_token = "old_token"
    # Mock session
    c.session = MagicMock()
    # Mock logger to avoid clutter
    c.logger = MagicMock()
    # Mock constants used in login
    with patch("zeekr_ev_api.const.LOGGED_IN_HEADERS", {"authorization": "old_token"}):
        yield c

def test_token_refresh_refactor_success(client):
    """Test successful token refresh and retry with recursive refactor."""

    expired_response = MagicMock()
    expired_response.json.return_value = {"code": "079012", "msg": "Token expired"}
    expired_response.status_code = 200
    expired_response.text = '{"code": "079012", "msg": "Token expired"}'

    success_response = MagicMock()
    success_response.json.return_value = {"success": True, "data": "success"}
    success_response.status_code = 200
    success_response.text = '{"success": True, "data": "success"}'

    def mock_login(relogin=False):
        client.bearer_token = "new_token"
        pass

    client.login = MagicMock(side_effect=mock_login)

    client.session.send.side_effect = [expired_response, success_response]

    with patch("zeekr_ev_api.zeekr_app_sig.sign_request") as mock_sign:
        mock_sign.return_value = MagicMock()
        mock_sign.return_value.headers = {}

        result = network.appSignedGet(client, "http://test.url")

        assert result["success"] is True
        assert result["data"] == "success"

        # Verify login was called
        client.login.assert_called_once_with(relogin=True)

        # Verify session.send was called twice
        assert client.session.send.call_count == 2

def test_token_refresh_refactor_retry_fails(client):
    """Test recursive retry failure."""

    expired_response = MagicMock()
    expired_response.json.return_value = {"code": "079012", "msg": "Token expired"}
    expired_response.status_code = 200

    client.login = MagicMock(side_effect=lambda relogin: setattr(client, 'bearer_token', 'new_token'))

    # Both calls return expired
    client.session.send.side_effect = [expired_response, expired_response]

    with patch("zeekr_ev_api.zeekr_app_sig.sign_request") as mock_sign:
        mock_sign.return_value = MagicMock()
        mock_sign.return_value.headers = {}

        with pytest.raises(AuthException) as exc:
            network.appSignedGet(client, "http://test.url")

        assert "Token expired (retry failed)" in str(exc.value)
