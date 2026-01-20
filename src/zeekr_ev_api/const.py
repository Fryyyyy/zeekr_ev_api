import uuid

# Hosts (set to SEA by default)
APP_SERVER_HOST = "https://gateway-pub-hw-em-sg.zeekrlife.com/overseas-app/"
USERCENTER_HOST = "https://gateway-pub-hw-em-sg.zeekrlife.com/zeekr-cuc-idaas-sea/"
MESSAGE_HOST = "https://gateway-pub-hw-em-sg.zeekrlife.com/sea-message-core/"

# EU Hosts
EU_APP_SERVER_HOST = "https://gateway-pub-azure.zeekr.eu/overseas-app/"
EU_USERCENTER_HOST = "https://gateway-pub-azure.zeekr.eu/zeekr-cuc-idaas/"
EU_MESSAGE_HOST = "https://gateway-pub-azure.zeekr.eu/eu-message-core/"

# URLs
LOGIN_URL = "auth/loginByEmailEncrypt"
PROTOCOL_URL = "protocol/service/getProtocol"
SERVICE_URL = "classification/service/type/V2"
URL_URL = "region/url"
CHECKUSER_URL = "auth/checkUserV2"
USERINFO_URL = "user/info"
TSPCODE_URL = "user/tspCode"
BEARERLOGIN_URL = "ms-user-auth/v1.0/auth/login"
VEHLIST_URL = "ms-app-bff/api/v4.0/veh/vehicle-list"
INBOX_URL = "member/inbox/home"
UPDATELANGUAGE_URL = "user/updateLanguage"
SYCN_URL = "open-api/v1/mcs/notice/receiver/equipment/relation/sycn"
VEHICLESTATUS_URL = "ms-vehicle-status/api/v1.0/vehicle/status/latest"
VEHICLECHARGINGSTATUS_URL = "ms-vehicle-status/api/v1.0/vehicle/status/qrvs"
REMOTECONTROLSTATE_URL = "ms-app-bff/api/v1.0/remoteControl/getVehicleState"
REMOTECONTROL_URL = "ms-remote-control/v1.0/remoteControl/control"
CHARGING_LIMIT_URL = "ms-charge-manage/api/v1.0/charge/getLatestSoc"
CHARGE_CONTROL_URL = "ms-charge-manage/api/v1.0/charge/control"
CHARGING_PLAN_URL = "ms-charge-manage/api/v1.0/charge/getChargingPlan"
LATEST_TRAVEL_PLAN_URL = "ms-charge-manage/api/v1.0/charge/getLatestTravelPlan"

COUNTRY_CODE = "AU"
REGION_CODE = "SEA"

REGION_LOGIN_SERVERS = {
    "SEA": "https://sea-snc-tsp-api-gw.zeekrlife.com/",
    "UAE": "https://me-snc-tsp-api-gw.zeekrlife.com/",
    "LA": "https://la-snc-tsp-api-gw.zeekrlife.com/",
    "EU": "https://eu-snc-tsp-api-gw.zeekrlife.com/",
}

# Secrets
HMAC_ACCESS_KEY = ""
HMAC_SECRET_KEY = ""
PASSWORD_PUBLIC_KEY = ""
PROD_SECRET = ""
VIN_KEY = ""
VIN_IV = ""

DEFAULT_HEADERS = {
    "accept-encoding": "gzip",
    "accept-language": "en-AU",
    "app-authorization": "1003",
    "app-code": "32816dbd-ff17-47b7-e250-5dae7d9f8cd4",
    "appcode": "eu-app",
    "appid": "TSP",
    "appsecret": "zeekr_tis",
    "appversion": "1.4.1",
    "call-source": "android",
    "client-id": "1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc",
    "Content-Type": "application/json; charset=UTF-8",
    "country": COUNTRY_CODE,
    "device-name": "sdk_gphone64_x86_64",
    "device-type": "app",
    "language": "en",
    "msgappid": "11002",
    "msgclientid": "1003",
    "registcountry": COUNTRY_CODE,
    "tmp-tenant-code": "3300743799505195008",
    "user-agent": "Device/GoogleAppName/com.zeekr.globalAppVersion/1.4.1Platform/androidOSVersion/16Ditto/true",
}

LOGGED_IN_HEADERS = {
    "Accept-Encoding": "gzip",
    "ACCEPT-LANGUAGE": "en-AU",
    "AppId": "ONEX97FB91F061405",
    "authorization": "",
    "Content-Type": "application/json; charset=UTF-8",
    "user-agent": "okhttp/4.12.0",
    "X-API-SIGNATURE-VERSION": "2.0",
    "X-APP-ID": "ZEEKRCNCH001M0001",
    "x-app-os-version": "",
    "x-device-id": str(uuid.uuid4()),
    "x-p": "Android",
    "X-PLATFORM": "APP",
    "X-PROJECT-ID": "ZEEKR_SEA",
}
