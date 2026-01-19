"""Fusion Solar App API """

from dataclasses import dataclass
from enum import StrEnum
import logging
import threading
import time
import requests
import base64
from json import JSONDecodeError
from typing import Dict, Optional
from urllib.parse import unquote, quote, urlparse, urlencode
from datetime import datetime, timedelta, timezone
from .const import DOMAIN, PUBKEY_URL, LOGIN_HEADERS_1_STEP_REFERER, LOGIN_HEADERS_2_STEP_REFERER, LOGIN_VALIDATE_USER_URL, LOGIN_FORM_URL, DATA_URL, STATION_LIST_URL, KEEP_ALIVE_URL, DATA_REFERER_URL, ENERGY_BALANCE_URL, LOGIN_DEFAULT_REDIRECT_URL, CAPTCHA_URL
from .utils import extract_numeric, encrypt_password, generate_nonce

_LOGGER = logging.getLogger(__name__)


class DeviceType(StrEnum):
    """Device types."""

    SENSOR_KW = "sensor"
    SENSOR_KWH = "sensor_kwh"
    SENSOR_PERCENTAGE = "sensor_percentage"
    SENSOR_TIME = "sensor_time"

class ENERGY_BALANCE_CALL_TYPE(StrEnum):
    """Device types."""

    DAY = "2"
    PREVIOUS_MONTH = "3"
    MONTH = "4"
    YEAR = "5"
    LIFETIME = "6"

DEVICES = [
    {"id": "House Load Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "Panel Production Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Battery Consumption Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Injection Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Grid Consumption Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Injection Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Battery Percentage", "type": DeviceType.SENSOR_PERCENTAGE, "icon": ""},
    {"id": "Battery Capacity", "type": DeviceType.SENSOR_KW, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "Last Authentication Time", "type": DeviceType.SENSOR_TIME, "icon": "mdi:clock-outline"},
]

@dataclass
class Device:
    """FusionSolarAPI device."""

    device_id: str
    device_unique_id: str
    device_type: DeviceType
    name: str
    state: float | int | datetime
    icon: str


class FusionSolarAPI:
    """Class for Fusion Solar App API."""

    _REQUEST_TIMEOUT = 30

    def __init__(self, user: str, pwd: str, login_host: str, captcha_input: str) -> None:
        """Initialise."""
        self.user = user
        self.pwd = pwd
        self.captcha_input = captcha_input
        self.captcha_img = None
        self.station = None
        self.battery_capacity = None
        self.login_host = login_host
        self.data_host = None
        self.dp_session = ""
        self.connected: bool = False
        self.last_session_time: datetime | None = None
        self._session_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.csrf = None
        self.csrf_time = None
        self._session = requests.Session()

    @property
    def controller_name(self) -> str:
        """Return the name of the controller."""
        return DOMAIN


    def login(self) -> bool:
        """Connect to api."""

        # Always start with a clean cookie jar to avoid reusing an expired session.
        self._session.cookies.clear()
        self.dp_session = ""
        self.csrf = None
        self.csrf_time = None
        
        public_key_url = f"https://{self.login_host}{PUBKEY_URL}"
        _LOGGER.debug("Getting Public Key at: %s", public_key_url)
        
        response = self._session.get(public_key_url, timeout=self._REQUEST_TIMEOUT)
        _LOGGER.debug("Pubkey Response Headers: %s\r\nResponse: %s", response.headers, response.text)
        try:
            pubkey_data = response.json()
            _LOGGER.debug("Pubkey Response: %s", pubkey_data)
        except Exception as ex:
            self.connected = False
            _LOGGER.error("Error processing Pubkey response: JSON format invalid!\r\nResponse Headers: %s\r\nResponse: %s", response.headers, response.text)
            raise APIAuthError("Error processing Pubkey response: JSON format invalid!\r\nResponse Headers: %s\r\nResponse: %s", response.headers, response.text)
        
        
        pub_key_pem = pubkey_data['pubKey']
        time_stamp = pubkey_data['timeStamp']
        enable_encrypt = pubkey_data['enableEncrypt']
        version = pubkey_data['version']
        
        nonce = generate_nonce()
        
        encrypted_password = encrypt_password(pub_key_pem, self.pwd) + version

        login_url = f"https://{self.login_host}{LOGIN_VALIDATE_USER_URL}?timeStamp={time_stamp}&nonce={nonce}"
        payload = {
            "organizationName": "",
            "password": encrypted_password,
            "username": self.user
        }
        
        _LOGGER.debug("captcha_input=%s", self.captcha_input)
        if self.captcha_input is not None and self.captcha_input != '':
            payload["verifycode"] = self.captcha_input
        
        headers = {
            "Content-Type": "application/json",
            "accept-encoding": "gzip, deflate, br, zstd",
            "connection": "keep-alive",
            "host": self.login_host,
            "origin": f"https://{self.login_host}",
            "referer": f"https://{self.login_host}{LOGIN_HEADERS_1_STEP_REFERER}",
            "x-requested-with": "XMLHttpRequest"
        }
        
        _LOGGER.debug("Login Request to: %s", login_url)
        response = self._session.post(
            login_url, json=payload, headers=headers, timeout=self._REQUEST_TIMEOUT
        )
        _LOGGER.debug("Login: Request Headers: %s\r\nResponse Headers: %s\r\nResponse: %s", headers, response.headers, response.text)
        if response.status_code == 200:
            try:
                login_response = response.json()
                _LOGGER.debug("Login Response: %s", login_response)
            except Exception as ex:
                self.connected = False
                _LOGGER.error("Error processing Login response: JSON format invalid!\r\nRequest Headers: %s\r\nResponse Headers: %s\r\nResponse: %s", headers, response.headers, response.text)
                raise APIAuthError("Error processing Login response: JSON format invalid!\r\nRequest Headers: %s\r\nResponse Headers: %s\r\nResponse: %s", headers, response.headers, response.text)
            
            redirect_url = None

            if 'respMultiRegionName' in login_response and login_response['respMultiRegionName']:
                redirect_info = login_response['respMultiRegionName'][1]  # Extract redirect URL
                redirect_url = f"https://{self.login_host}{redirect_info}"
            elif 'redirectURL'in login_response and login_response['redirectURL']:
                redirect_info = login_response['redirectURL']  # Extract redirect URL
                redirect_url = f"https://{self.login_host}{redirect_info}"
            else:
                _LOGGER.warning("Login response did not include redirect information.")
                self.connected = False

                if 'errorCode' in login_response and login_response['errorCode'] and login_response['errorCode'] == '411':
                    _LOGGER.warning("Captcha required.")
                    raise APIAuthCaptchaError("Login requires Captcha.")
                else:
                    login_form_url = f"https://{self.login_host}{LOGIN_FORM_URL}"
                    _LOGGER.debug("Redirecting to Login Form: %s", login_form_url)
                    response = self._session.get(
                        login_form_url, timeout=self._REQUEST_TIMEOUT
                    )
                    _LOGGER.debug("Login Form Response: %s", response.text)
                    _LOGGER.debug("Login Form Response headers: %s", response.headers)
                    raise APIAuthError("Login response did not include redirect information.")

            redirect_headers = {
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "accept-encoding": "gzip, deflate, br, zstd",
                "connection": "keep-alive",
                "host": self.login_host,
                "referer": f"https://{self.login_host}{LOGIN_HEADERS_2_STEP_REFERER}"
            }
    
            _LOGGER.debug("Redirect to: %s", redirect_url)
            redirect_response = self._session.get(
                redirect_url,
                headers=redirect_headers,
                allow_redirects=True,
                timeout=self._REQUEST_TIMEOUT,
            )

            # After following redirects, we should land on the data host.
            self.data_host = urlparse(redirect_response.url).netloc
            dp_session = self._session.cookies.get("dp-session")

            if not self.data_host:
                self.connected = False
                raise APIAuthError(
                    f"Login redirect did not resolve data host. Final URL: {redirect_response.url}"
                )

            if not dp_session:
                self.connected = False
                raise APIAuthError(
                    "DP Session not found in cookie jar after login redirect. "
                    f"Final URL: {redirect_response.url}"
                )

            _LOGGER.debug("DP Session Cookie: %s", dp_session)
            self.dp_session = dp_session
            self.connected = True
            self.last_session_time = datetime.now(timezone.utc)
            self.refresh_csrf()
            station_data = self.get_station_list()
            self.station = station_data["data"]["list"][0]["dn"]
            if self.battery_capacity is None or self.battery_capacity == 0.0:
                self.battery_capacity = station_data["data"]["list"][0][
                    "batteryCapacity"
                ]
            self._start_session_monitor()
            return True
        else:
            _LOGGER.warning("Login failed: %s", response.status_code)
            _LOGGER.warning("Response headers: %s", response.headers)
            _LOGGER.warning("Response: %s", response.text)
            self.connected = False
            raise APIAuthError("Login failed.")

    def set_captcha_img(self):
        timestampNow = datetime.now().timestamp() * 1000
        captcha_request_url = f"https://{self.login_host}{CAPTCHA_URL}?timestamp={timestampNow}"
        _LOGGER.debug("Requesting Captcha at: %s", captcha_request_url)
        response = self._session.get(captcha_request_url, timeout=self._REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            self.captcha_img = f"data:image/png;base64,{base64.b64encode(response.content).decode('utf-8')}"
        else:
            self.captcha_img = None

    def _json_or_raise(self, response: requests.Response, *, context: str, auth_on_fail: bool = False) -> dict:
        """Parse JSON response or raise a meaningful integration exception.

        FusionSolar endpoints occasionally return HTML or empty bodies when a session expires.
        In that case we surface an APIAuthError so the coordinator can re-login.
        """

        try:
            return response.json()
        except (JSONDecodeError, ValueError) as ex:
            content_type = response.headers.get("Content-Type", "")
            snippet = (response.text or "").strip()[:500]
            msg = (
                f"{context}: non-JSON response (status={response.status_code}, content-type={content_type}). "
                f"Body starts with: {snippet!r}"
            )
            if auth_on_fail:
                self.connected = False
                raise APIAuthError(msg) from ex
            raise APIDataStructureError(msg) from ex

    def refresh_csrf(self):
        dp_session = self._session.cookies.get("dp-session")
        if dp_session:
            self.dp_session = dp_session

        if not self.data_host or not self.dp_session:
            self.connected = False
            raise APIAuthError("Not authenticated (missing data_host or dp-session).")

        if self.csrf is None or (self.csrf_time and datetime.now() - self.csrf_time > timedelta(minutes=5)):
            roarand_url = f"https://{self.data_host}{KEEP_ALIVE_URL}"
            roarand_headers = {
                "accept": "application/json, text/plain, */*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "Referer": f"https://{self.data_host}{DATA_REFERER_URL}"
            }
            roarand_cookies = {"locale": "en-us"}
            roarand_params = {}
            
            _LOGGER.debug("Getting Roarand at: %s", roarand_url)
            try:
                roarand_response = self._session.get(
                    roarand_url,
                    headers=roarand_headers,
                    cookies=roarand_cookies,
                    params=roarand_params,
                    timeout=self._REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as ex:
                self.connected = False
                raise APIConnectionError(f"CSRF refresh request failed: {ex}") from ex

            roarand_data = self._json_or_raise(roarand_response, context="CSRF refresh", auth_on_fail=True)
            payload = roarand_data.get("payload")
            if not payload:
                self.connected = False
                raise APIAuthError(f"CSRF refresh: missing payload in response: {roarand_data!r}")
            self.csrf = payload
            self.csrf_time = datetime.now()
            _LOGGER.debug("CSRF refreshed: %s", self.csrf)
    
    def get_station_id(self):
        return self.get_station_list()["data"]["list"][0]["dn"]

    def get_station_list(self):
        self.refresh_csrf()

        station_url = f"https://{self.data_host}{STATION_LIST_URL}"
        
        station_headers = {
                "accept": "application/json, text/javascript, /; q=0.01",
                "accept-encoding": "gzip, deflate, br, zstd",
                "Content-Type": "application/json",
                "Origin": f"https://{self.data_host}",
                "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
                "Roarand": f"{self.csrf}",
            }
        
        station_cookies = {"locale": "en-us"}
        
        station_payload = {
                "curPage": 1,
                "pageSize": 10,
                "gridConnectedTime": "",
                "queryTime": 1666044000000,
                "timeZone": 2,
                "sortId": "createTime",
                "sortDir": "DESC",
                "locale": "en_US",
            }
        
        _LOGGER.debug("Getting Station at: %s", station_url)
        try:
            station_response = self._session.post(
                station_url,
                json=station_payload,
                headers=station_headers,
                cookies=station_cookies,
                timeout=self._REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as ex:
            raise APIConnectionError(f"Station list request failed: {ex}") from ex

        json_response = self._json_or_raise(station_response, context="Station list", auth_on_fail=True)
        _LOGGER.debug("Station info: %s", json_response["data"])
        return json_response

    def get_devices(self) -> list[Device]:
        self.refresh_csrf()

        cookies = {"locale": "en-us"}
        
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        
        # Fusion Solar App Station parameter
        params = {"stationDn": unquote(self.station)}
        
        data_access_url = f"https://{self.data_host}{DATA_URL}"
        _LOGGER.debug("Getting Data at: %s", data_access_url)
        try:
            response = self._session.get(
                data_access_url,
                headers=headers,
                cookies=cookies,
                params=params,
                timeout=self._REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as ex:
            raise APIConnectionError(f"Data request failed: {ex}") from ex

        output = {
            "panel_production_power": 0.0,
            "panel_production_today": 0.0,
            "panel_production_week": 0.0,
            "panel_production_month": 0.0,
            "panel_production_year": 0.0,
            "panel_production_lifetime": 0.0,
            "panel_production_consumption_today": 0.0,
            "panel_production_consumption_week": 0.0,
            "panel_production_consumption_month": 0.0,
            "panel_production_consumption_year": 0.0,
            "panel_production_consumption_lifetime": 0.0,
            "house_load_power": 0.0,
            "house_load_today": 0.0,
            "house_load_week": 0.0,
            "house_load_month": 0.0,
            "house_load_year": 0.0,
            "house_load_lifetime": 0.0,
            "grid_consumption_power": 0.0,
            "grid_consumption_today": 0.0,
            "grid_consumption_week": 0.0,
            "grid_consumption_month": 0.0,
            "grid_consumption_year": 0.0,
            "grid_consumption_lifetime": 0.0,
            "grid_injection_power": 0.0,
            "grid_injection_today": 0.0,
            "grid_injection_week": 0.0,
            "grid_injection_month": 0.0,
            "grid_injection_year": 0.0,
            "grid_injection_lifetime": 0.0,
            "battery_injection_power": 0.0,
            "battery_injection_today": 0.0,
            "battery_injection_week": 0.0,
            "battery_injection_month": 0.0,
            "battery_injection_year": 0.0,
            "battery_injection_lifetime": 0.0,
            "battery_consumption_power": 0.0,
            "battery_consumption_today": 0.0,
            "battery_consumption_week": 0.0,
            "battery_consumption_month": 0.0,
            "battery_consumption_year": 0.0,
            "battery_consumption_lifetime": 0.0,
            "battery_percentage": 0.0,
            "battery_capacity": 0.0,
            "exit_code": "SUCCESS",
        }

        if response.status_code == 200:
            data = self._json_or_raise(response, context="Data flow", auth_on_fail=True)
            _LOGGER.debug("Get Data Response: %s", data)

            if "data" not in data or "flow" not in data["data"]:
                _LOGGER.error("Error on data structure!")
                raise APIDataStructureError("Error on data structure!")

            # Process nodes to gather required information
            flow_data_nodes = data["data"]["flow"].get("nodes", [])
            flow_data_links = data["data"]["flow"].get("links", [])
            node_map = {
                "neteco.pvms.energy.flow.buy.power": "grid_consumption_power",
                "neteco.pvms.devTypeLangKey.string": "panel_production_power",
                "neteco.pvms.devTypeLangKey.energy_store": "battery_injection_power",
                "neteco.pvms.KPI.kpiView.electricalLoad": "house_load_power",
            }
        
            for node in flow_data_nodes:
                label = node.get("name", "")
                value = node.get("description", {}).get("value", "")
                
                if label == "neteco.pvms.devTypeLangKey.energy_store":
                    soc = extract_numeric(node.get("deviceTips", {}).get("SOC", ""))
                    if soc is not None:
                        output["battery_percentage"] = soc
                    
                    battery_power = extract_numeric(node.get("deviceTips", {}).get("BATTERY_POWER", ""))
                    if battery_power is None or battery_power <= 0:
                        output["battery_consumption_power"] = extract_numeric(value)
                        output["battery_injection_power"] = 0.0
                    else:
                        output[node_map[label]] = extract_numeric(value)
                        output["battery_consumption_power"] = 0.0
                else:
                    if label in node_map:
                        output[node_map[label]] = extract_numeric(value)
        
            for node in flow_data_links:
                label = node.get("description", {}).get("label", "")
                value = node.get("description", {}).get("value", "")
                if label in node_map:
                    if label == "neteco.pvms.energy.flow.buy.power":
                        grid_consumption_injection = extract_numeric(value)
                        if (output["panel_production_power"] + output["battery_consumption_power"] - output["battery_injection_power"] - output["house_load_power"]) > 0:
                            output["grid_injection_power"] = grid_consumption_injection
                            output["grid_consumption_power"] = 0.0
                        else:
                            output["grid_consumption_power"] = grid_consumption_injection
                            output["grid_injection_power"] = 0.0

            self.update_output_with_battery_capacity(output)
            self.update_output_with_energy_balance(output)

            output["exit_code"] = "SUCCESS"
            _LOGGER.debug("output JSON: %s", output)
        else:
            _LOGGER.error("Error on data structure! %s", response.text)
            raise APIDataStructureError("Error on data structure! %s", response.text)

        """Get devices on api."""
        return [
            Device(
                device_id=device.get("id"),
                device_unique_id=self.get_device_unique_id(
                    device.get("id"), device.get("type")
                ),
                device_type=device.get("type"),
                name=self.get_device_name(device.get("id")),
                state=self.get_device_value(device.get("id"), device.get("type"), output),
                icon=device.get("icon")
            )
            for device in DEVICES
        ]

    def update_output_with_battery_capacity(self, output: Dict[str, Optional[float | str]]):
        if self.battery_capacity is None or self.battery_capacity == 0.0:
            _LOGGER.debug("Getting Battery capacity")
            self.refresh_csrf()
            station_list = self.get_station_list()
            station_data = station_list["data"]["list"][0]
            output["battery_capacity"] = station_data["batteryCapacity"]
            self.battery_capacity = station_data["batteryCapacity"]
        else:
            output["battery_capacity"] = self.battery_capacity
    
    def update_output_with_energy_balance(self, output: Dict[str, Optional[float | str]]):
        self.refresh_csrf()
        
        # Month energy sensors
        _LOGGER.debug("Getting Month's energy data")
        month_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.MONTH)
        output["panel_production_month"] = extract_numeric(month_data["data"]["totalProductPower"])
        output["panel_production_consumption_month"] = extract_numeric(month_data["data"]["totalSelfUsePower"])
        output["grid_injection_month"] = extract_numeric(month_data["data"]["totalOnGridPower"])
        output["grid_consumption_month"] = extract_numeric(month_data["data"]["totalBuyPower"])
        
        month_charge_power_list = month_data["data"]["chargePower"]
        if month_charge_power_list:
            month_total_charge_power = sum(extract_numeric(value) for value in month_charge_power_list if (value != "--" and value != "null"))
            output["battery_injection_month"] = month_total_charge_power
        
        month_discharge_power_list = month_data["data"]["dischargePower"]
        if month_discharge_power_list:
            month_total_discharge_power = sum(extract_numeric(value) for value in month_discharge_power_list if (value != "--" and value != "null"))
            output["battery_consumption_month"] = month_total_discharge_power

        # Today energy sensors
        _LOGGER.debug("Getting Today's energy data")
        week_data = self.get_week_data()
        output["grid_consumption_today"] = extract_numeric(week_data[-1]["data"]["totalBuyPower"])
        output["grid_injection_today"] = extract_numeric(week_data[-1]["data"]["totalOnGridPower"])

        if month_charge_power_list:
            charge_value_today = month_charge_power_list[datetime.now().day - 1]
            charge_value_today = extract_numeric(charge_value_today)
            output["battery_injection_today"] = charge_value_today

        if month_discharge_power_list:
            discharge_value_today = month_discharge_power_list[datetime.now().day - 1]
            discharge_value_today = extract_numeric(discharge_value_today)
            output["battery_consumption_today"] = discharge_value_today
        

        month_self_use_list = month_data["data"]["selfUsePower"]
        if month_self_use_list:
            self_use_value_today = month_self_use_list[datetime.now().day - 1]
            self_use_value_today = extract_numeric(self_use_value_today)
            output["panel_production_consumption_today"] = self_use_value_today
    
        month_house_load_list = month_data["data"]["usePower"]
        if month_house_load_list:
            house_load_value_today = month_house_load_list[datetime.now().day - 1]
            house_load_value_today = extract_numeric(house_load_value_today)
            output["house_load_today"] = house_load_value_today

        month_panel_production_list = month_data["data"]["productPower"]
        if month_panel_production_list:
            panel_production_value_today = month_panel_production_list[datetime.now().day - 1]
            panel_production_value_today = extract_numeric(panel_production_value_today)
            output["panel_production_today"] = panel_production_value_today
        
        # Week energy sensors
        _LOGGER.debug("Getting Week's energy data")
        today = datetime.now()
        start_day_week = today - timedelta(days=today.weekday())

        days_previous_month = []
        days_current_month = []
        
        for i in range(7):
            current_day = start_day_week + timedelta(days=i)
            if current_day.month < today.month:
                days_previous_month.append(current_day.day)
            else: 
                days_current_month.append(current_day.day)

        panel_production_value_week = 0
        panel_production_consumption_value_week = 0
        house_load_value_week = 0
        battery_injection_value_week = 0
        battery_consumption_value_week = 0
        
        if days_previous_month:
            previous_month_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.PREVIOUS_MONTH)
            panel_production_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "productPower")
            panel_production_consumption_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "selfUsePower")
            house_load_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "usePower")
            battery_injection_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "chargePower")
            battery_consumption_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "dischargePower")
        
        if days_current_month:
            panel_production_value_week += self.calculate_week_energy(month_data, days_current_month, "productPower")
            panel_production_consumption_value_week += self.calculate_week_energy(month_data, days_current_month, "selfUsePower")
            house_load_value_week += self.calculate_week_energy(month_data, days_current_month, "usePower")
            battery_injection_value_week += self.calculate_week_energy(month_data, days_current_month, "chargePower")
            battery_consumption_value_week += self.calculate_week_energy(month_data, days_current_month, "dischargePower")

        output["panel_production_week"] = panel_production_value_week
        output["panel_production_consumption_week"] = panel_production_consumption_value_week
        output["house_load_week"] = house_load_value_week
        output["battery_injection_week"] = battery_injection_value_week
        output["battery_consumption_week"] = battery_consumption_value_week
        if week_data:
            output["grid_consumption_week"] = sum(extract_numeric(day["data"]["totalBuyPower"]) for day in week_data if (day["data"]["totalBuyPower"] != "--" and day["data"]["totalBuyPower"] != "null"))
            output["grid_injection_week"] = sum(extract_numeric(day["data"]["totalOnGridPower"]) for day in week_data if (day["data"]["totalOnGridPower"] != "--" and day["data"]["totalOnGridPower"] != "null"))

        # Year energy sensors
        _LOGGER.debug("Getting Years's energy data")
        year_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.YEAR)
        output["panel_production_consumption_year"] = extract_numeric(year_data["data"]["totalSelfUsePower"])
        output["house_load_year"] = extract_numeric(year_data["data"]["totalUsePower"])
        output["panel_production_year"] = extract_numeric(year_data["data"]["totalProductPower"])
        output["grid_consumption_year"] = extract_numeric(year_data["data"]["totalBuyPower"])
        output["grid_injection_year"] = extract_numeric(year_data["data"]["totalOnGridPower"])

        charge_power_list = year_data["data"]["chargePower"]
        if charge_power_list:
            total_charge_power = sum(extract_numeric(value) for value in charge_power_list if (value != "--" and value != "null"))
            output["battery_injection_year"] = total_charge_power
        
        discharge_power_list = year_data["data"]["dischargePower"]
        if discharge_power_list:
            total_discharge_power = sum(extract_numeric(value) for value in discharge_power_list if (value != "--" and value != "null"))
            output["battery_consumption_year"] = total_discharge_power
        
        use_power_list = year_data["data"]["usePower"]
        if use_power_list:
            charge_value_this_month = use_power_list[datetime.now().month - 1]
            charge_value_this_month = extract_numeric(charge_value_this_month)
            output["house_load_month"] = charge_value_this_month
        
        # Lifetime energy sensors
        _LOGGER.debug("Getting Lifetime's energy data")
        lifetime_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.LIFETIME)
        output["panel_production_lifetime"] = extract_numeric(lifetime_data["data"]["totalProductPower"])
        output["panel_production_consumption_lifetime"] = extract_numeric(lifetime_data["data"]["totalSelfUsePower"])
        output["house_load_lifetime"] = extract_numeric(lifetime_data["data"]["totalUsePower"])
        output["grid_consumption_lifetime"] = extract_numeric(lifetime_data["data"]["totalBuyPower"])
        output["grid_injection_lifetime"] = extract_numeric(lifetime_data["data"]["totalOnGridPower"])
        
        lifetime_charge_power_list = lifetime_data["data"]["chargePower"]
        if lifetime_charge_power_list:
            lifetime_total_charge_power = sum(extract_numeric(value) for value in lifetime_charge_power_list if (value != "--" and value != "--"))
            output["battery_injection_lifetime"] = lifetime_total_charge_power
        
        lifetime_discharge_power_list = lifetime_data["data"]["dischargePower"]
        if lifetime_discharge_power_list:
            lifetime_total_discharge_power = sum(extract_numeric(value) for value in lifetime_discharge_power_list if (value != "--" and value != "--"))
            output["battery_consumption_lifetime"] = lifetime_total_discharge_power
        
        
    def call_energy_balance(self, call_type: ENERGY_BALANCE_CALL_TYPE, specific_date: datetime = None):
        currentTime = datetime.now()
        timestampNow = currentTime.timestamp() * 1000
        current_day = currentTime.day
        current_month = currentTime.month
        current_year = currentTime.year
        first_day_of_month = datetime(current_year, current_month, 1)
        if current_month == 1:
            first_day_of_previous_month = datetime(current_year - 1, 12, 1)
        else:
            first_day_of_previous_month = datetime(current_year, current_month - 1, 1)
        first_day_of_year = datetime(current_year, 1, 1)

        if call_type == ENERGY_BALANCE_CALL_TYPE.MONTH:
            timestamp = first_day_of_month.timestamp() * 1000
            dateStr = first_day_of_month.strftime("%Y-%m-%d %H:%M:%S")
        elif call_type == ENERGY_BALANCE_CALL_TYPE.PREVIOUS_MONTH:
            timestamp = first_day_of_previous_month.timestamp() * 1000
            dateStr = first_day_of_previous_month.strftime("%Y-%m-%d %H:%M:%S")
            call_type = ENERGY_BALANCE_CALL_TYPE.MONTH
        elif call_type == ENERGY_BALANCE_CALL_TYPE.YEAR:
            timestamp = first_day_of_year.timestamp() * 1000
            dateStr = first_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        elif call_type == ENERGY_BALANCE_CALL_TYPE.DAY:
            if specific_date is not None:
                specific_year = specific_date.year
                specific_month = specific_date.month
                specific_day = specific_date.day
                current_day_of_year = datetime(specific_year, specific_month, specific_day)
            else:
                current_day_of_year = datetime(current_year, current_month, current_day)
            
            timestamp = current_day_of_year.timestamp() * 1000
            dateStr = current_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp = first_day_of_year.timestamp() * 1000
            dateStr = first_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        
        cookies = {"locale": "en-us"}
        
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "Host": self.data_host,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
            "X-Requested-With": "XMLHttpRequest",
            "Roarand": self.csrf
        }

        params = {
             "stationDn": unquote(self.station),
             "timeDim": call_type,
             "queryTime": int(timestamp),
             "timeZone": "0.0",
             "timeZoneStr": "Europe/London",
             "dateStr": dateStr,
             "_": int(timestampNow)
        }
         
        energy_balance_url = f"https://{self.data_host}{ENERGY_BALANCE_URL}?{urlencode(params)}"
        _LOGGER.debug("Getting Energy Balance at: %s", energy_balance_url)
        try:
            energy_balance_response = self._session.get(
                energy_balance_url,
                headers=headers,
                cookies=cookies,
                timeout=self._REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as ex:
            raise APIConnectionError(f"Energy balance request failed: {ex}") from ex
        _LOGGER.debug("Energy Balance Response: %s", energy_balance_response.text)
        return self._json_or_raise(energy_balance_response, context="Energy balance", auth_on_fail=True)

    def get_week_data(self):
        today = datetime.now()
        start_of_week = today - timedelta(days=today.weekday())  # Segunda-feira da semana corrente
        days_to_process = []
        
        # Determinar dias a processar
        if today.weekday() == 6:  # Se for domingo
            days_to_process = [start_of_week + timedelta(days=i) for i in range(7)]
        else:  # Outros dias da semana
            days_to_process = [start_of_week + timedelta(days=i) for i in range(today.weekday() + 1)]
        
        # Obter dados para cada dia e armazenar no array
        week_data = []
        for day in days_to_process:
            day_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.DAY, specific_date=day)
            week_data.append(day_data)
            time.sleep(1)
        
        return week_data

    def calculate_week_energy(self, data, days, field):
        sum = 0
        if data["data"][field]:
            for day in days:
                value = data["data"][field][day - 1]
                if value != "--" and value != "null":
                    sum += extract_numeric(value)

        return sum

    def logout(self) -> bool:
        """Disconnect from api."""
        self.connected = False
        self._stop_session_monitor()
        return True

    def _renew_session(self) -> None:
        """Simulate session renewal."""
        _LOGGER.info("Renewing session.")
        self.connected = False
        self.dp_session = ""
        self.login()

    def _session_monitor(self) -> None:
        """Monitor session and renew if needed."""
        while not self._stop_event.is_set():
            if self.connected == False:
                self._renew_session()
            time.sleep(60)  # Check every 60 seconds

    def _start_session_monitor(self) -> None:
        """Start the session monitor thread."""
        if self._session_thread is None or not self._session_thread.is_alive():
            self._stop_event.clear()
            self._session_thread = threading.Thread(target=self._session_monitor, daemon=True)
            self._session_thread.start()

    def _stop_session_monitor(self) -> None:
        """Stop the session monitor thread."""
        self._stop_event.set()
        if self._session_thread is not None:
            self._session_thread.join()

    def get_device_unique_id(self, device_id: str, device_type: DeviceType) -> str:
        """Return a unique device id."""
        return f"{self.controller_name}_{device_id.lower().replace(' ', '_')}"

    def get_device_name(self, device_id: str) -> str:
        """Return the device name."""
        return device_id

    def get_device_value(self, device_id: str, device_type: DeviceType, output: Dict[str, Optional[float | str]], default: int = 0) -> float | int | datetime:
        """Get device random value."""
        if device_type == DeviceType.SENSOR_TIME:
            _LOGGER.debug("%s: Value being returned is datetime: %s", device_id, self.last_session_time)
            return self.last_session_time

        if device_id.lower().replace(" ", "_") not in output:
            raise KeyError(f"'{device_id}' not found.")

        value = output[device_id.lower().replace(" ", "_")]
        if value is None or value == 'None':
            return default  # Retorna o valor padrão se for None

        try:
            if device_type == DeviceType.SENSOR_KW or device_type == DeviceType.SENSOR_KWH:
                _LOGGER.debug("%s: Value being returned is float: %s", device_id, value)
                return round(float(value), 4)
            else:
                _LOGGER.debug("%s: Value being returned is int: %i", device_id, value)
                return int(value)
        except ValueError:
            _LOGGER.warning(f"Value '{value}' for '{device_id}' can't be converted.")
            return 0.0

class APIAuthError(Exception):
    """Exception class for auth error."""

class APIAuthCaptchaError(Exception):
    """Exception class for auth captcha error."""

class APIConnectionError(Exception):
    """Exception class for connection error."""

class APIDataStructureError(Exception):
    """Exception class for Data error."""
