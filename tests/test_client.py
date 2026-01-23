
import pytest
from unittest.mock import MagicMock, patch
from zeekr_ev_api.client import ZeekrClient, Vehicle
from zeekr_ev_api.exceptions import ZeekrException, AuthException
from zeekr_ev_api import const

@pytest.fixture
def mock_client():
    client = ZeekrClient(
        username="test@example.com",
        password="password",
        hmac_access_key="key",
        hmac_secret_key="secret",
        password_public_key="pubkey",
        prod_secret="prodsecret",
    )
    # Bypass login logic for most tests
    client.logged_in = True
    client.session = MagicMock()
    client.auth_token = "auth_token"
    client.bearer_token = "bearer_token"
    client.region_login_server = "https://mock.login.server/"

    # Mock constants to avoid external calls
    with patch("zeekr_ev_api.client.const") as mock_const:
        mock_const.LOGGED_IN_HEADERS = {"header": "value"}
        mock_const.REMOTECONTROLSTATE_URL = "remote/state"
        mock_const.VEHICLESTATUS_URL = "vehicle/status"
        mock_const.VEHICLECHARGINGSTATUS_URL = "charging/status"
        mock_const.VEHLIST_URL = "veh/list"
        # Mock encryption to avoid AES errors with empty keys
        with patch("zeekr_ev_api.zeekr_app_sig.aes_encrypt", return_value="encrypted_vin"):
            yield client

def test_client_init():
    client = ZeekrClient(username="u", password="p")
    assert client.username == "u"
    assert client.password == "p"
    assert client.logged_in is False

def test_get_vehicle_list(mock_client):
    mock_response = {
        "success": True,
        "data": [
            {"vin": "VIN123", "name": "Car 1"},
            {"vin": "VIN456", "name": "Car 2"}
        ]
    }

    with patch("zeekr_ev_api.network.appSignedGet", return_value=mock_response) as mock_get:
        vehicles = mock_client.get_vehicle_list()

        assert len(vehicles) == 2
        assert vehicles[0].vin == "VIN123"
        assert vehicles[1].vin == "VIN456"
        assert isinstance(vehicles[0], Vehicle)
        mock_get.assert_called_once()

def test_get_vehicle_status(mock_client):
    mock_response = {"success": True, "data": {"status": "ok"}}

    with patch("zeekr_ev_api.network.appSignedGet", return_value=mock_response) as mock_get:
        status = mock_client.get_vehicle_status("VIN123")
        assert status == {"status": "ok"}
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        # Since we mocked encryption to return 'encrypted_vin', check for that
        assert "encrypted_vin" in str(kwargs.get('headers', {}))

def test_get_vehicle_charging_status(mock_client):
    mock_response = {"success": True, "data": {"charging": True}}

    with patch("zeekr_ev_api.network.appSignedGet", return_value=mock_response) as mock_get:
        status = mock_client.get_vehicle_charging_status("VIN123")
        assert status == {"charging": True}
        mock_get.assert_called_once()

def test_get_remote_control_state_rename(mock_client):
    mock_response = {"success": True, "data": {"remote_state": "active"}}

    with patch("zeekr_ev_api.network.appSignedGet", return_value=mock_response) as mock_get:
        # Call the new method directly
        state = mock_client.get_remote_control_state("VIN123")
        assert state == {"remote_state": "active"}

        # Verify URL called
        args, _ = mock_get.call_args
        # The mock_client uses mocked constants, but here we are checking against the REAL const module
        # imported at the top of the test file.
        # We should check against the value we mocked in the fixture: "remote/state"
        assert "remote/state" in args[1]

def test_get_vehicle_state_deprecated(mock_client):
    mock_response = {"success": True, "data": {"remote_state": "active"}}

    with patch("zeekr_ev_api.network.appSignedGet", return_value=mock_response) as mock_get:
        # Call the deprecated method and check for warning
        with pytest.warns(DeprecationWarning, match="get_vehicle_state is deprecated"):
            state = mock_client.get_vehicle_state("VIN123")

        assert state == {"remote_state": "active"}

        # Verify it still called the underlying logic (via get_remote_control_state)
        mock_get.assert_called_once()

def test_do_remote_control(mock_client):
    mock_response = {"success": True}

    with patch("zeekr_ev_api.network.appSignedPost", return_value=mock_response) as mock_post:
        result = mock_client.do_remote_control("VIN123", "command", "service", {})
        assert result is True
        mock_post.assert_called_once()

def test_vehicle_wrapper_methods(mock_client):
    vehicle_data = {"vin": "VIN123"}
    vehicle = Vehicle(mock_client, "VIN123", vehicle_data)

    # Mock client methods
    mock_client.get_vehicle_status = MagicMock(return_value="status_ok")
    mock_client.get_vehicle_charging_status = MagicMock(return_value="charging_ok")
    mock_client.get_remote_control_state = MagicMock(return_value="remote_ok")
    mock_client.do_remote_control = MagicMock(return_value=True)

    assert vehicle.get_status() == "status_ok"
    assert vehicle.get_charging_status() == "charging_ok"
    assert vehicle.get_remote_control_state() == "remote_ok"
    assert vehicle.do_remote_control("c", "s", {}) is True

    # Verify the vehicle wrapper calls the correct client methods
    mock_client.get_vehicle_status.assert_called_with("VIN123")
    mock_client.get_vehicle_charging_status.assert_called_with("VIN123")
    mock_client.get_remote_control_state.assert_called_with("VIN123")
    mock_client.do_remote_control.assert_called_with("VIN123", "c", "s", {})

def test_not_logged_in(mock_client):
    mock_client.logged_in = False
    with pytest.raises(ZeekrException, match="Not logged in"):
        mock_client.get_vehicle_list()
