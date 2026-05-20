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

def test_token_refresh_with_loaded_session(client):
    """Test token refresh logic when a session is loaded from data."""
    from zeekr_ev_api.client import ZeekrClient
    from zeekr_ev_api.network import appSignedGet

    session_data = {
        "username": "test_user",
        "password": "test_password",
        "country_code": "US",
        "bearer_token": "expired_token",
        "auth_token": "auth_token_value"
    }

    # Initialize from session data (which has password)
    new_client = ZeekrClient(session_data=session_data)

    # Set up mocks
    new_client.session = MagicMock()
    new_client.logged_in_headers = {"authorization": "expired_token"}
    new_client._get_urls = MagicMock()
    new_client._check_user = MagicMock()
    new_client._do_login_request = MagicMock()
    new_client._get_user_info = MagicMock()
    new_client._get_protocol = MagicMock()
    new_client._check_inbox = MagicMock()
    new_client._get_tsp_code = MagicMock(return_value=("mock_tsp", ""))
    new_client._update_language = MagicMock()
    new_client._bearer_login = MagicMock()

    def simulate_token_expiration(*args, **kwargs):
        # We need appSignedGet to return "Token expired" the first time,
        # and success the second time.
        if simulate_token_expiration.call_count == 0:
            simulate_token_expiration.call_count += 1
            return {"msg": "Token expired"}
        return {"success": True, "data": "refreshed_data"}

    simulate_token_expiration.call_count = 0

    # Mock zeekr_app_sig.sign_request to just return the prep
    from unittest.mock import patch
    with patch("zeekr_ev_api.network._safe_json", side_effect=simulate_token_expiration), \
         patch("zeekr_ev_api.zeekr_app_sig.sign_request", return_value=MagicMock()):

        # This will trigger appSignedGet -> sees "Token expired" -> calls client.login(relogin=True)
        # Because we have the password in session_data, the login should succeed.
        result = appSignedGet(new_client, "http://mock/url")

        assert result.get("success") is True
        assert result.get("data") == "refreshed_data"
        # Verify that login was actually called (which means _do_login_request was called)
        new_client._do_login_request.assert_called_once()
