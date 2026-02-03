"""
Zeekr EV API Client
"""

import base64
import json
import logging
import time
import threading
import warnings
from typing import Any, Dict, List

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from . import const, network, zeekr_app_sig, zeekr_hmac
from .exceptions import AuthException, ZeekrException


class ZeekrClient:
    """
    A client for the Zeekr EV API.
    """

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        country_code: str = "AU",
        hmac_access_key: str = "",
        hmac_secret_key: str = "",
        password_public_key: str = "",
        prod_secret: str = "",
        vin_key: str = "",
        vin_iv: str = "",
        session_data: dict | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        Initializes the client.
        """
        self.session: requests.Session = requests.Session()
        self.password: str | None = password

        # Logger for this client (allows caller to inject their logger)
        self.logger = logger or logging.getLogger(__name__)

        # Lock for authentication updates
        self.auth_lock = threading.Lock()

        # Cache for encrypted VINs
        self.vin_encryption_cache: Dict[str, str] = {}

        # Store secrets on instance instead of mutating global const
        self.hmac_access_key = hmac_access_key or const.HMAC_ACCESS_KEY
        self.hmac_secret_key = hmac_secret_key or const.HMAC_SECRET_KEY
        self.password_public_key = password_public_key or const.PASSWORD_PUBLIC_KEY
        self.prod_secret = prod_secret or const.PROD_SECRET
        self.vin_key = vin_key or const.VIN_KEY
        self.vin_iv = vin_iv or const.VIN_IV

        self.logged_in_headers = const.LOGGED_IN_HEADERS.copy()

        if session_data:
            self.load_session(session_data)
        else:
            if not username or not password:
                raise ValueError(
                    "Username and password are required for a new session."
                )
            self.username: str = username
            self.country_code: str = country_code
            self.logged_in: bool = False
            self.auth_token: str | None = None
            self.bearer_token: str | None = None
            self.user_info: dict = {}
            self.vin: str | None = None
            self.vehicles: list["Vehicle"] = []

            # These will be populated during login
            self.app_server_host: str = const.APP_SERVER_HOST
            self.usercenter_host: str = const.USERCENTER_HOST
            self.message_host: str = const.MESSAGE_HOST
            self.region_code: str = const.REGION_CODE
            self.region_login_server: str | None = None

    def load_session(self, session_data: dict) -> None:
        """Loads a session from a dictionary."""
        self.username = session_data.get("username", "")
        self.country_code = session_data.get("country_code", "AU")
        self.auth_token = session_data.get("auth_token")
        self.bearer_token = session_data.get("bearer_token")
        self.user_info = session_data.get("user_info", {})
        self.app_server_host = session_data.get("app_server_host", "")
        self.usercenter_host = session_data.get("usercenter_host", "")
        self.message_host = session_data.get("message_host", "")
        self.region_code = session_data.get("region_code", "")
        self.region_login_server = session_data.get("region_login_server")
        self.vehicles: list["Vehicle"] = []

        if self.bearer_token:
            self.logged_in = True
            self.logged_in_headers["authorization"] = self.bearer_token
            if self.auth_token:
                self.session.headers["authorization"] = self.auth_token
        else:
            self.logged_in = False

    def export_session(self) -> dict:
        """Exports the current session to a dictionary."""
        if not self.logged_in:
            return {}

        return {
            "username": self.username,
            "country_code": self.country_code,
            "auth_token": self.auth_token,
            "bearer_token": self.bearer_token,
            "user_info": self.user_info,
            "app_server_host": self.app_server_host,
            "usercenter_host": self.usercenter_host,
            "message_host": self.message_host,
            "region_code": self.region_code,
            "region_login_server": self.region_login_server,
        }

    def _rsa_encrypt_password(self) -> str:
        """
        Encrypts the password using RSA.
        """
        if not self.password:
            raise ValueError("Password is not set for encryption.")

        key_bytes = base64.b64decode(self.password_public_key)
        public_key = RSA.import_key(key_bytes)
        cipher = PKCS1_v1_5.new(public_key)
        password_bytes = self.password.encode("utf-8")
        encrypted_bytes = cipher.encrypt(password_bytes)
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    def _get_encrypted_vin(self, vin: str) -> str:
        """
        Encrypts the VIN using AES, with caching.
        """
        if vin not in self.vin_encryption_cache:
            self.vin_encryption_cache[vin] = zeekr_app_sig.aes_encrypt(
                vin, self.vin_key, self.vin_iv
            )
        return self.vin_encryption_cache[vin]

    def login(self, relogin: bool = False) -> None:
        """
        Logs in to the Zeekr API.
        """
        if self.logged_in and not relogin:
            return
        self._get_urls()
        self._check_user()
        self._do_login_request()
        self._get_user_info()
        self._get_protocol()
        self._check_inbox()
        tsp_code, _ = self._get_tsp_code()
        self._update_language()
        # self._sycn_push(login_id) # Disabled for now
        self._bearer_login(tsp_code)
        self.logged_in = True

    def _get_urls(self) -> None:
        """
        Fetches the regional API URLs.
        """
        urls = network.customGet(self, f"{const.APP_SERVER_HOST}{const.URL_URL}")
        if not urls.get("success", False):
            raise ZeekrException("Unable to fetch URL data")

        url_data = urls.get("data", [])
        found = False
        for url_block in url_data:
            if url_block.get("countryCode", "").lower() == self.country_code.lower():
                self.app_server_host = url_block.get("url", {}).get("appServerUrl", "")
                self.usercenter_host = url_block.get("url", {}).get("userCenterUrl", "")
                self.message_host = url_block.get("url", {}).get("messageCoreUrl", "")
                self.region_code = url_block.get("regionCode", "SEA")
                found = True
                break

        if not found:
            eu_lookup = network.customGet(
                self, f"{const.EU_APP_SERVER_HOST}{const.URL_URL}"
            )
            eu_has_country = False
            if eu_lookup.get("success", False):
                for region in eu_lookup.get("data", []):
                    if region.get("countryCode", "").lower() == self.country_code.lower():
                        eu_has_country = True
                        break

            if eu_has_country:
                self.logger.info(
                    "Country %s found in EU region list; using EU hosts",
                    self.country_code,
                )
                self.app_server_host = const.EU_APP_SERVER_HOST
                self.usercenter_host = const.EU_USERCENTER_HOST
                self.message_host = const.EU_MESSAGE_HOST
                self.region_code = "EU"
            else:
                raise ZeekrException(
                    f"Country code not supported in region lookup: {self.country_code}"
                )

        if (
            not self.app_server_host
            or not self.usercenter_host
            or not self.message_host
        ):
            raise ZeekrException("One or more API URLs are blank after fetching.")

        self.region_login_server = const.REGION_LOGIN_SERVERS.get(self.region_code)
        if not self.region_login_server:
            raise ZeekrException(f"No login server for region: {self.region_code}")

        # Update headers for region-specific project ID
        if self.region_code == "EU":
            self.logged_in_headers["X-PROJECT-ID"] = "ZEEKR_EU"
        else:
            self.logged_in_headers["X-PROJECT-ID"] = "ZEEKR_SEA"

    def _check_user(self) -> None:
        """
        Checks if the user exists.
        """
        user_code = network.customPost(
            self,
            f"{self.usercenter_host}{const.CHECKUSER_URL}",
            {"email": self.username, "checkType": "1"},
        )
        if not user_code.get("success", False):
            raise AuthException("User check failed")

    def _do_login_request(self) -> None:
        """
        Performs the main login request.
        """
        encrypted_password = self._rsa_encrypt_password()
        if not encrypted_password:
            raise AuthException("Password encryption failed")

        request_data = {
            "code": "",
            "codeId": "",
            "email": self.username,
            "password": encrypted_password,
        }

        req = requests.Request(
            "POST",
            f"{self.usercenter_host}{const.LOGIN_URL}",
            headers=const.DEFAULT_HEADERS,
            json=request_data,
        )
        new_req = zeekr_hmac.generateHMAC(
            req, self.hmac_access_key, self.hmac_secret_key
        )
        prepped = self.session.prepare_request(new_req)
        resp = self.session.send(prepped)
        login_data = resp.json()

        if not login_data or not login_data.get("success", False):
            raise AuthException(f"Login failed: {login_data}")

        login_token = login_data.get("data", {})
        if login_token.get("tokenName", "") != "Authorization":
            raise AuthException(f"Unknown login token type: {login_token}")

        self.auth_token = login_token.get("tokenValue")
        if not self.auth_token:
            raise AuthException("No auth token supplied in login response")

        self.session.headers["authorization"] = self.auth_token

    def _get_user_info(self) -> None:
        """
        Fetches user information.
        """
        user_info_resp = network.customPost(
            self, f"{self.usercenter_host}{const.USERINFO_URL}"
        )
        if user_info_resp.get("success", False):
            self.user_info = user_info_resp.get("data", {})

    def _get_protocol(self) -> None:
        """
        Fetches the protocol.
        """
        network.customPost(
            self,
            f"{self.app_server_host}{const.PROTOCOL_URL}",
            {"country": self.country_code},
        )

    def _check_inbox(self) -> None:
        """
        Checks the inbox.
        """
        network.customGet(self, f"{self.app_server_host}{const.INBOX_URL}")

    def _get_tsp_code(self) -> tuple[str, str]:
        """
        Gets the TSP code.
        """
        tsp_code_block = network.customGet(
            self,
            f"{self.usercenter_host}{const.TSPCODE_URL}?tspClientId={const.DEFAULT_HEADERS.get('client-id', '')}",
        )
        if not tsp_code_block.get("success", False):
            raise ZeekrException(f"Unable to fetch TSP Code: {tsp_code_block}")

        tsp_code = tsp_code_block.get("data", {}).get("code")
        login_id = tsp_code_block.get("data", {}).get("loginId")
        if not tsp_code:
            raise ZeekrException(f"No TSP code in response: {tsp_code_block}")

        return tsp_code, login_id

    def _update_language(self, language: str = "en") -> None:
        """
        Updates the language.
        """
        network.customGet(
            self,
            f"{self.usercenter_host}{const.UPDATELANGUAGE_URL}?language={language}",
        )

    def _bearer_login(self, tsp_code: str) -> None:
        """
        Performs the bearer token login.
        """
        bearer_body = {
            "identifier": tsp_code,
            "identityType": 10,
            "loginDeviceId": "google-sdk_gphone64_x86_64-36-16",
            "loginDeviceJgId": "",
            "loginDeviceType": 1,
            "loginPhoneBrand": "google",
            "loginPhoneModel": "sdk_gphone64_x86_64",
            "loginSystem": "Android",
        }

        bearer_login_block = network.appSignedPost(
            self,
            f"{self.region_login_server}{const.BEARERLOGIN_URL}",
            json.dumps(bearer_body, separators=(",", ":")),
        )
        if not bearer_login_block.get("success", False):
            raise AuthException(f"Bearer login failed: {bearer_login_block}")

        bearer_login_data = bearer_login_block.get("data", {})
        self.bearer_token = bearer_login_data.get("accessToken")
        if not self.bearer_token:
            raise AuthException(f"No bearer token in response: {bearer_login_data}")

        self.logged_in_headers["authorization"] = self.bearer_token

    def get_vehicle_list(self) -> list["Vehicle"]:
        """
        Fetches the list of vehicles.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        vehicle_list_block = network.appSignedGet(
            self,
            f"{self.region_login_server}{const.VEHLIST_URL}?needSharedCar=true",
        )
        if not vehicle_list_block.get("success", False):
            raise ZeekrException(f"Failed to get vehicle list: {vehicle_list_block}")

        self.vehicles = [
            Vehicle(self, v.get("vin"), v) for v in vehicle_list_block.get("data", [])
        ]
        return self.vehicles

    def get_vehicle_status(self, vin: str) -> Dict[str, Any]:
        """
        Fetches the status for a specific vehicle.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        vehicle_status_block = network.appSignedGet(
            self,
            f"{self.region_login_server}{const.VEHICLESTATUS_URL}?latest=false&target=new",
            headers=headers,
        )
        if not vehicle_status_block.get("success", False):
            raise ZeekrException(
                f"Failed to get vehicle status: {vehicle_status_block}"
            )

        return vehicle_status_block.get("data", {})

    def get_vehicle_charging_status(self, vin: str) -> Dict[str, Any]:
        """
        Fetches the charging status for a specific vehicle.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        vehicle_charging_status_block = network.appSignedGet(
            self,
            f"{self.region_login_server}{const.VEHICLECHARGINGSTATUS_URL}",
            headers=headers,
        )
        if not vehicle_charging_status_block.get("success", False):
            raise ZeekrException(
                f"Failed to get vehicle charging status: {vehicle_charging_status_block}"
            )

        return vehicle_charging_status_block.get("data", {})

    def get_vehicle_state(self, vin: str) -> dict[str, Any]:
        """
        Deprecated: Use get_remote_control_state instead.
        Fetches the remote control state of a vehicle.
        """
        warnings.warn(
            "get_vehicle_state is deprecated, use get_remote_control_state instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_remote_control_state(vin)

    def get_remote_control_state(self, vin: str) -> dict[str, Any]:
        """
        Fetches the remote control state of a vehicle.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        vehicle_status_block = network.appSignedGet(
            self,
            f"{self.region_login_server}{const.REMOTECONTROLSTATE_URL}",
            headers=headers,
        )
        if not vehicle_status_block.get("success", False):
            raise ZeekrException(
                f"Failed to get vehicle status: {vehicle_status_block}"
            )

        return vehicle_status_block.get("data", {})

    def do_remote_control(
        self, vin: str, command: str, serviceID: str, setting: Dict[str, Any]
    ) -> bool:
        """
        Performs a remote control action on the vehicle.
        The caller must provide the correct command, serviceID, and setting for the desired action.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        extra_header = {"X-VIN": self._get_encrypted_vin(vin)}

        if serviceID == "RCS":
            endpoint = const.CHARGE_CONTROL_URL
        else:
            endpoint = const.REMOTECONTROL_URL

        body = {"command": command, "serviceId": serviceID, "setting": setting}

        remote_control_block = network.appSignedPost(
            self,
            f"{self.region_login_server}{endpoint}",
            json.dumps(body, separators=(",", ":")),
            extra_headers=extra_header,
        )
        return remote_control_block.get("success", False)

    def get_vehicle_charging_limit(self, vin: str) -> Dict[str, Any]:
        """
        Fetches the charging limit (SoC) for a specific vehicle.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        vehicle_charging_limit_block = network.appSignedGet(
            self,
            f"{self.region_login_server}{const.CHARGING_LIMIT_URL}",
            headers=headers,
        )
        if not vehicle_charging_limit_block.get("success", False):
            raise ZeekrException(
                f"Failed to get vehicle charging limit: {vehicle_charging_limit_block}"
            )

        return vehicle_charging_limit_block.get("data", {})

    def get_charge_plan(self, vin: str) -> Dict[str, Any]:
        """
        Fetches the charging plan for a specific vehicle.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        charge_plan_block = network.appSignedGet(
            self,
            f"{self.region_login_server}{const.CHARGING_PLAN_URL}",
            headers=headers,
        )
        if not charge_plan_block.get("success", False):
            self.logger.debug("Failed to get charge plan: %s", charge_plan_block)
            return {}

        return charge_plan_block.get("data", {})

    def set_charge_plan(
        self,
        vin: str,
        start_time: str,
        end_time: str,
        command: str = "start",
        bc_cycle_active: bool = False,
        bc_temp_active: bool = False,
    ) -> bool:
        """
        Sets the charging plan for a specific vehicle.

        Args:
            vin: Vehicle identification number.
            start_time: Start time in HH:MM format (e.g., "01:15").
            end_time: End time in HH:MM format (e.g., "06:45").
            command: "start" to enable, "stop" to disable the plan.
            bc_cycle_active: Battery conditioning cycle active.
            bc_temp_active: Battery conditioning temperature active.

        Returns:
            True if successful, False otherwise.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        body = {
            "bcCycleActive": bc_cycle_active,
            "bcTempActive": bc_temp_active,
            "command": command,
            "endTime": end_time,
            "scheduledTime": "",
            "startTime": start_time,
            "target": "2",
            "timerId": "2",
        }

        charge_plan_block = network.appSignedPost(
            self,
            f"{self.region_login_server}{const.SET_CHARGE_PLAN_URL}",
            json.dumps(body, separators=(",", ":")),
            extra_headers={"X-VIN": self._get_encrypted_vin(vin)},
        )
        return charge_plan_block.get("success", False)

    def get_travel_plan(self, vin: str) -> Dict[str, Any]:
        """
        Fetches the latest travel plan for a specific vehicle.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        travel_plan_block = network.appSignedGet(
            self,
            f"{self.region_login_server}{const.LATEST_TRAVEL_PLAN_URL}",
            headers=headers,
        )
        if not travel_plan_block.get("success", False):
            self.logger.debug("Failed to get travel plan: %s", travel_plan_block)
            return {}

        return travel_plan_block.get("data", {})

    def set_travel_plan(
        self,
        vin: str,
        command: str = "start",
        start_time: str = "",
        scheduled_time: str = "",
        ac_preconditioning: bool = True,
        steering_wheel_heating: bool = False,
        schedule_list: List[Dict[str, str]] | None = None,
        timer_id: str = "4",
    ) -> bool:
        """
        Sets the travel plan for a specific vehicle.

        Args:
            vin: Vehicle identification number.
            command: "start" to enable, "stop" to disable the plan.
            start_time: Start time in HH:MM format (e.g., "08:00").
            scheduled_time: Timestamp in milliseconds as string.
            ac_preconditioning: Enable AC pre-conditioning.
            steering_wheel_heating: Enable steering wheel heating.
            schedule_list: List of schedule dicts for recurring schedules.
            timer_id: Timer ID (default "4" for travel plan).

        Returns:
            True if successful, False otherwise.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        body = {
            "ac": "true" if ac_preconditioning else "false",
            "btActive": False,
            "btTempActive": False,
            "bw": "1" if steering_wheel_heating else "0",
            "bwl": "1",
            "command": command,
            "scheduleList": schedule_list or [],
            "scheduledTime": scheduled_time,
            "timerId": timer_id,
        }

        travel_plan_block = network.appSignedPost(
            self,
            f"{self.region_login_server}{const.SET_TRAVEL_PLAN_URL}",
            json.dumps(body, separators=(",", ":")),
            extra_headers={"X-VIN": self._get_encrypted_vin(vin)},
        )
        return travel_plan_block.get("success", False)

    def get_journey_log(
        self,
        vin: str,
        page_size: int = 10,
        current_page: int = 1,
        last_id: int = -1,
        days_back: int = 30,
    ) -> Dict[str, Any]:
        """
        Fetches the journey log (trip history) for a specific vehicle.

        Args:
            vin: Vehicle identification number.
            page_size: Number of trips per page.
            current_page: Page number (1-indexed).
            last_id: Last trip ID for pagination (-1 for first page).
            days_back: Number of days back to fetch trips.

        Returns:
            Dictionary containing:
            - total: int - Total number of trips matching the query.
            - list: List[dict] - Trip records, each containing:
                - tripId: int - Unique trip identifier.
                - reportTime: int - Report timestamp (ms since epoch).
                - startTime: int - Trip start timestamp (ms since epoch).
                - endTime: int - Trip end timestamp (ms since epoch).
                - startMileage: float - Odometer at trip start (km).
                - endMileage: float - Odometer at trip end (km).
                - distance: float - Trip distance (km).
                - duration: int - Trip duration (seconds).
                - avgSpeed: float - Average speed (km/h).
                - energyConsumption: float - Energy used (kWh).
                - startLongitude/startLatitude: float - Start coordinates.
                - endLongitude/endLatitude: float - End coordinates.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        now_ms = int(time.time() * 1000)
        start_ms = now_ms - (days_back * 24 * 60 * 60 * 1000)

        body = {
            "currentPage": current_page,
            "endTime": now_ms,
            "lastId": last_id,
            "pageSize": page_size,
            "startTime": start_ms,
        }

        journey_log_block = network.appSignedPost(
            self,
            f"{self.region_login_server}{const.JOURNEY_LOG_URL}",
            json.dumps(body, separators=(",", ":")),
            extra_headers=headers,
        )

        if not journey_log_block.get("success", False):
            self.logger.debug("Failed to get journey log: %s", journey_log_block)
            return {}

        return journey_log_block.get("data", {})

    def get_trip_trackpoints(
        self,
        vin: str,
        trip_report_time: int,
        trip_id: int,
    ) -> Dict[str, Any]:
        """
        Fetches detailed GPS trackpoints for a specific trip.
        """
        if not self.logged_in:
            raise ZeekrException("Not logged in")

        headers = self.logged_in_headers.copy()
        headers["X-VIN"] = self._get_encrypted_vin(vin)

        url = (
            f"{self.region_login_server}{const.TRIP_TRACKPOINTS_URL}"
            f"?tripReportTime={trip_report_time}&tripId={trip_id}"
        )

        trackpoints_block = network.appSignedGet(
            self,
            url,
            headers=headers,
        )

        if not trackpoints_block.get("success", False):
            self.logger.debug("Failed to get trip trackpoints: %s", trackpoints_block)
            return {}

        return trackpoints_block.get("data", {})


class Vehicle:
    """
    Represents a Zeekr vehicle.
    """

    def __init__(self, client: "ZeekrClient", vin: str, data: dict) -> None:
        self._client = client
        self.vin = vin
        self.data = data

    def __repr__(self) -> str:
        return f"<Vehicle {self.vin}>"

    def get_status(self) -> Any:
        """
        Fetches the vehicle status.
        """
        return self._client.get_vehicle_status(self.vin)

    def get_charging_status(self) -> Any:
        """
        Fetches the vehicle charging status.
        """
        return self._client.get_vehicle_charging_status(self.vin)

    def get_remote_control_state(self) -> Any:
        """
        Fetches the vehicle remote control state.
        """
        return self._client.get_remote_control_state(self.vin)

    def do_remote_control(
        self, command: str, serviceID: str, setting: Dict[str, Any]
    ) -> bool:
        """
        Performs a remote control action on the vehicle.
        """
        return self._client.do_remote_control(self.vin, command, serviceID, setting)

    def get_charging_limit(self) -> Any:
        """
        Fetches the vehicle charging limit.
        """
        return self._client.get_vehicle_charging_limit(self.vin)

    def get_charge_plan(self) -> Any:
        """
        Fetches the vehicle charging plan.
        """
        return self._client.get_charge_plan(self.vin)

    def set_charge_plan(
        self,
        start_time: str,
        end_time: str,
        command: str = "start",
        bc_cycle_active: bool = False,
        bc_temp_active: bool = False,
    ) -> bool:
        """
        Sets the vehicle charging plan.
        """
        return self._client.set_charge_plan(
            self.vin, start_time, end_time, command, bc_cycle_active, bc_temp_active
        )

    def get_travel_plan(self) -> Any:
        """
        Fetches the vehicle travel plan.
        """
        return self._client.get_travel_plan(self.vin)

    def set_travel_plan(
        self,
        command: str = "start",
        start_time: str = "",
        scheduled_time: str = "",
        ac_preconditioning: bool = True,
        steering_wheel_heating: bool = False,
        schedule_list: List[Dict[str, str]] | None = None,
        timer_id: str = "4",
    ) -> bool:
        """
        Sets the vehicle travel plan.

        Args:
            command: "start" to enable, "stop" to disable the plan.
            start_time: Start time in HH:MM format (e.g., "08:00").
            scheduled_time: Timestamp in milliseconds as string.
            ac_preconditioning: Enable AC pre-conditioning.
            steering_wheel_heating: Enable steering wheel heating.
            schedule_list: List of schedule dicts for recurring schedules.
            timer_id: Timer ID (default "4" for travel plan).

        Returns:
            True if successful, False otherwise.
        """
        return self._client.set_travel_plan(
            self.vin, command, start_time, scheduled_time,
            ac_preconditioning, steering_wheel_heating, schedule_list, timer_id
        )

    def get_journey_log(
        self,
        page_size: int = 10,
        current_page: int = 1,
        last_id: int = -1,
        days_back: int = 30,
    ) -> Dict[str, Any]:
        """
        Fetches the vehicle journey log.
        """
        return self._client.get_journey_log(
            self.vin, page_size, current_page, last_id, days_back
        )

    def get_trip_trackpoints(self, trip_report_time: int, trip_id: int) -> Dict[str, Any]:
        """
        Fetches detailed trackpoints for a specific trip.
        """
        return self._client.get_trip_trackpoints(self.vin, trip_report_time, trip_id)
