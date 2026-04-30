"""Fusion Solar App API """

from dataclasses import dataclass
from enum import StrEnum
import logging
import re
import threading
import time
import requests
import json
import base64
from typing import Any, Dict, Optional
from urllib.parse import unquote, quote, urlparse, urlencode
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
from .const import DOMAIN, PUBKEY_URL, LOGIN_HEADERS_1_STEP_REFERER, LOGIN_HEADERS_2_STEP_REFERER, LOGIN_VALIDATE_USER_URL, LOGIN_VALIDATE_USER_URL_LA5, FINAL_AUTH_URL_LA5, LOGIN_FORM_URL, DATA_URL, STATION_LIST_URL, KEEP_ALIVE_URL, DATA_REFERER_URL, ENERGY_BALANCE_URL, LOGIN_DEFAULT_REDIRECT_URL, CAPTCHA_URL, DEVICE_REALTIME_DATA_URL, DEVICE_REAL_KPI_URL, SOCIAL_CONTRIBUTION_URL
from .utils import extract_numeric, encrypt_password, generate_nonce

_LOGGER = logging.getLogger(__name__)

class DeviceType(StrEnum):
    """Device types."""

    SENSOR_KW = "sensor"
    SENSOR_KWH = "sensor_kwh"
    SENSOR_PERCENTAGE = "sensor_percentage"
    SENSOR_RATIO = "sensor_ratio"
    SENSOR_TIME = "sensor_time"
    SENSOR_VOLTAGE = "sensor_voltage"
    SENSOR_CURRENT = "sensor_current"
    SENSOR_FREQUENCY = "sensor_frequency"
    SENSOR_TEMPERATURE = "sensor_temperature"
    SENSOR_RESISTANCE = "sensor_resistance"
    SENSOR_POWER_FACTOR = "sensor_power_factor"
    SENSOR_TEXT = "sensor_text"
    SENSOR_KG = "sensor_kg"
    SENSOR_COUNT = "sensor_count"

def normalize_fusionsolar_host(host: str) -> str:
    """Normalize a FusionSolar host into the correct login host."""
    if not isinstance(host, str):
        return "eu5.fusionsolar.huawei.com"

    normalized = host.strip().lower()
    normalized = re.sub(r"^https?://", "", normalized)
    normalized = normalized.split("/", 1)[0]
    normalized = normalized.split(":", 1)[0]

    domain_suffix = ".fusionsolar.huawei.com"
    if normalized.endswith(domain_suffix):
        normalized = normalized[: -len(domain_suffix)]

    region_match = re.match(r"^(?:region|uni)\d+(?P<suffix>[a-z]+\d+)$", normalized)
    if region_match:
        normalized = region_match.group("suffix")

    if not normalized:
        normalized = "eu5"

    return f"{normalized}{domain_suffix}"

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
    {"id": "Panel Production Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Self Consumption Ratio Today", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Week", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Month", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Year", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Lifetime", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Today", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Week", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Month", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Year", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Lifetime", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
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
    {"id": "Standard Coal Saved", "type": DeviceType.SENSOR_KG, "icon": "mdi:mine"},
    {"id": "Standard Coal Saved This Year", "type": DeviceType.SENSOR_KG, "icon": "mdi:mine"},
    {"id": "CO2 Avoided", "type": DeviceType.SENSOR_KG, "icon": "mdi:molecule-co2"},
    {"id": "CO2 Avoided This Year", "type": DeviceType.SENSOR_KG, "icon": "mdi:molecule-co2"},
    {"id": "Equivalent Trees Planted", "type": DeviceType.SENSOR_COUNT, "icon": "mdi:tree"},
    {"id": "Equivalent Trees Planted This Year", "type": DeviceType.SENSOR_COUNT, "icon": "mdi:tree"},
    {"id": "Last Authentication Time", "type": DeviceType.SENSOR_TIME, "icon": "mdi:clock-outline"},
]

# Signal ID -> sensor definition for inverter real-time data
BASE_INVERTER_SIGNAL_MAP = {
    10008: {"id": "Inverter Grid Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10011: {"id": "Inverter Phase A Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10012: {"id": "Inverter Phase B Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10013: {"id": "Inverter Phase C Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10014: {"id": "Inverter Grid Current", "type": DeviceType.SENSOR_CURRENT, "icon": "mdi:current-ac"},
    10015: {"id": "Inverter Phase B Current", "type": DeviceType.SENSOR_CURRENT, "icon": "mdi:current-ac"},
    10016: {"id": "Inverter Phase C Current", "type": DeviceType.SENSOR_CURRENT, "icon": "mdi:current-ac"},
    10021: {"id": "Inverter Grid Frequency", "type": DeviceType.SENSOR_FREQUENCY, "icon": "mdi:sine-wave"},
    10023: {"id": "Inverter Internal Temperature", "type": DeviceType.SENSOR_TEMPERATURE, "icon": "mdi:thermometer"},
    10024: {"id": "Inverter Insulation Resistance", "type": DeviceType.SENSOR_RESISTANCE, "icon": "mdi:omega"},
    10020: {"id": "Inverter Power Factor", "type": DeviceType.SENSOR_POWER_FACTOR, "icon": "mdi:angle-acute"},
    10025: {"id": "Inverter Status", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:information-outline"},
    10027: {"id": "Inverter Startup Time", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:clock-outline"},
    10028: {"id": "Inverter Last Shutdown Time", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:clock-outline"},
    21029: {"id": "Inverter Output Mode", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:transmission-tower"},
}


def _build_dynamic_pv_signal_map(max_pv_inputs: int = 20) -> dict[int, dict[str, Any]]:
    """Build PV voltage/current/power signal definitions dynamically."""
    signal_map: dict[int, dict[str, Any]] = {}

    for pv_index in range(1, max_pv_inputs + 1):
        base_signal_id = 11001 + ((pv_index - 1) * 3)
        signal_map[base_signal_id] = {
            "id": f"Inverter PV{pv_index} Voltage",
            "type": DeviceType.SENSOR_VOLTAGE,
            "icon": "mdi:solar-panel",
        }
        signal_map[base_signal_id + 1] = {
            "id": f"Inverter PV{pv_index} Current",
            "type": DeviceType.SENSOR_CURRENT,
            "icon": "mdi:solar-panel",
        }
        signal_map[base_signal_id + 2] = {
            "id": f"Inverter PV{pv_index} Power",
            "type": DeviceType.SENSOR_KW,
            "icon": "mdi:solar-panel",
        }

    return signal_map


def get_inverter_signal_map() -> dict[int, dict[str, Any]]:
    """Return the complete inverter signal definition map."""
    return {**BASE_INVERTER_SIGNAL_MAP, **_build_dynamic_pv_signal_map()}

@dataclass
class Device:
    """FusionSolarAPI device."""

    device_id: str
    device_unique_id: str
    device_type: DeviceType
    name: str
    state: float | int | datetime | str
    icon: str


class FusionSolarAPI:
    """Class for Fusion Solar App API."""

    def __init__(self, user: str, pwd: str, login_host: str, captcha_input: str) -> None:
        """Initialise."""
        self.user = user
        self.pwd = pwd
        self.captcha_input = captcha_input
        self.captcha_img = None
        self.station = None
        self.inverter_dn = None
        self.battery_capacity = None
        self.login_host = normalize_fusionsolar_host(login_host)
        self.data_host = None
        self.dp_session = ""
        self.connected: bool = False
        self.last_session_time: datetime | None = None
        self._session_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.csrf = None
        self.csrf_time = None
        self.request_timeout = 20
        self.session = requests.Session()
        self.session.cookies.set("locale", "en-us")

    @property
    def controller_name(self) -> str:
        """Return the name of the controller."""
        return DOMAIN

    def login(self) -> bool:
        """Connect to api."""
        if any(host in self.login_host for host in ("la5", "intl")):
            _LOGGER.debug("Using LA5 login flow")
            return self._login_la5()
        else:
            _LOGGER.debug("Using EU5 login flow")
            return self._login_eu5()
            
    def _login_eu5(self) -> bool:
        """Connect to API using the EU5 login flow."""
        captcha_input = ""

        if isinstance(self.captcha_input, str):
            captcha_input = self.captcha_input.strip()

        if not captcha_input:
            login_page_url = f"https://{self.login_host}{LOGIN_FORM_URL}"
            _LOGGER.debug("Pre-warming session by visiting login page: %s", login_page_url)

            try:
                self.session.get(login_page_url, timeout=20)
            except Exception as ex:
                _LOGGER.warning("Failed to pre-warm session: %s", ex)

        if captcha_input:
            captcha_is_valid = self._prevalidate_captcha(captcha_input)

            if not captcha_is_valid:
                _LOGGER.warning("Captcha pre-validation failed.")
                self.connected = False
                self.set_captcha_img()
                raise APIAuthCaptchaError("Invalid captcha.")

        public_key_url = f"https://{self.login_host}{PUBKEY_URL}"
        _LOGGER.debug("Getting Public Key at: %s", public_key_url)

        response = self.session.get(public_key_url, timeout=20)
        _LOGGER.debug(
            "Pubkey Response Headers: %s\r\nResponse: %s",
            response.headers,
            response.text,
        )

        try:
            pubkey_data = response.json()
            _LOGGER.debug("Pubkey Response: %s", pubkey_data)
        except Exception as ex:
            self.connected = False
            _LOGGER.error(
                "Error processing Pubkey response: JSON format invalid!\r\nResponse Headers: %s\r\nResponse: %s",
                response.headers,
                response.text,
            )
            raise APIAuthError(
                "Error processing Pubkey response: JSON format invalid!"
            ) from ex

        pub_key_pem = pubkey_data["pubKey"]
        time_stamp = pubkey_data["timeStamp"]
        version = pubkey_data["version"]

        nonce = generate_nonce()
        encrypted_password = encrypt_password(pub_key_pem, self.pwd) + version

        login_url = (
            f"https://{self.login_host}{LOGIN_VALIDATE_USER_URL}"
            f"?timeStamp={time_stamp}&nonce={nonce}"
        )

        payload = {
            "organizationName": "",
            "username": self.user,
            "password": encrypted_password,
            "multiRegionName": "",
        }

        if captcha_input:
            payload["verifycode"] = captcha_input
            _LOGGER.debug("Submitting login with captcha input.")
        else:
            _LOGGER.debug("Submitting login without captcha input.")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "accept-encoding": "gzip, deflate, br, zstd",
            "connection": "keep-alive",
            "host": self.login_host,
            "origin": f"https://{self.login_host}",
            "referer": f"https://{self.login_host}{LOGIN_HEADERS_1_STEP_REFERER}",
            "x-requested-with": "XMLHttpRequest",
        }

        _LOGGER.debug("Login Request to: %s", login_url)

        response = self.session.post(
            login_url,
            json=payload,
            headers=headers,
            timeout=20,
        )

        _LOGGER.debug(
            "Login: Request Headers: %s\r\nResponse Headers: %s\r\nResponse: %s",
            headers,
            response.headers,
            response.text,
        )

        if response.status_code != 200:
            _LOGGER.warning("Login failed: %s", response.status_code)
            _LOGGER.warning("Response headers: %s", response.headers)
            _LOGGER.warning("Response: %s", response.text)
            self.connected = False
            raise APIAuthError("Login failed.")

        try:
            login_response = response.json()
            _LOGGER.debug("Login Response: %s", login_response)
        except Exception as ex:
            self.connected = False
            _LOGGER.error(
                "Error processing Login response: JSON format invalid!\r\nRequest Headers: %s\r\nResponse Headers: %s\r\nResponse: %s",
                headers,
                response.headers,
                response.text,
            )
            raise APIAuthError(
                "Error processing Login response: JSON format invalid!"
            ) from ex

        redirect_url = None

        if login_response.get("respMultiRegionName"):
            redirect_info = login_response["respMultiRegionName"][1]
            redirect_url = f"https://{self.login_host}{redirect_info}"
        elif login_response.get("redirectURL"):
            redirect_info = login_response["redirectURL"]
            redirect_url = f"https://{self.login_host}{redirect_info}"

        if not redirect_url:
            error_code = str(login_response.get("errorCode", ""))
            error_message = str(login_response.get("errorMsg", ""))
            verify_code_create = bool(login_response.get("verifyCodeCreate"))

            _LOGGER.warning(
                "Login response did not include redirect information. errorCode=%s errorMsg=%s verifyCodeCreate=%s",
                error_code,
                error_message,
                verify_code_create,
            )

            self.connected = False

            if error_code == "411" or verify_code_create:
                _LOGGER.warning("Captcha required or captcha challenge still active.")
                self.set_captcha_img()
                raise APIAuthCaptchaError("Login requires Captcha.")

            if error_code == "406":
                raise APIAuthError("Invalid username or password.")

            raise APIAuthError("Login response did not include redirect information.")

        redirect_headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-encoding": "gzip, deflate, br, zstd",
            "connection": "keep-alive",
            "host": self.login_host,
            "referer": f"https://{self.login_host}{LOGIN_HEADERS_2_STEP_REFERER}",
        }

        _LOGGER.debug("Redirect to: %s", redirect_url)

        redirect_response = self.session.get(
            redirect_url,
            headers=redirect_headers,
            allow_redirects=False,
            timeout=20,
        )

        _LOGGER.debug("Redirect Response: %s", redirect_response.text)

        response_headers = redirect_response.headers
        location_header = response_headers.get("Location")
        _LOGGER.debug("Redirect Response headers: %s", response_headers)

        if location_header:
            self.data_host = urlparse(location_header).netloc
        else:
            self.data_host = self.login_host

        if redirect_response.status_code in (200, 302):
            dp_session = redirect_response.cookies.get("dp-session")

            if not dp_session:
                raw_set_cookie = redirect_response.headers.get("Set-Cookie", "")

                for part in raw_set_cookie.split(","):
                    part = part.strip()

                    if part.startswith("dp-session="):
                        dp_session = part.split("=", 1)[1].split(";", 1)[0]
                        break

            if not dp_session:
                dp_session = self.session.cookies.get("dp-session")

            if not dp_session:
                _LOGGER.error("DP Session not found in cookies.")
                self.connected = False
                raise APIAuthError("DP Session not found in cookies.")

            _LOGGER.debug("DP Session Cookie: %s", dp_session)

            self.dp_session = dp_session
            self.connected = True
            self.last_session_time = datetime.now(timezone.utc)
            self.captcha_input = None
            self.captcha_img = None

            self.refresh_csrf()
            station_data = self.get_station_list()

            if not self.station:
                self.station = station_data["data"]["list"][0]["dn"]
            else:
                if not any(s["dn"] == self.station for s in station_data["data"]["list"]):
                    raise APIDataStructureError(f"Station {self.station} not found.")

            if self.battery_capacity is None or self.battery_capacity == 0.0:
                self.battery_capacity = station_data["data"]["list"][0]["batteryCapacity"]

            self._start_session_monitor()
            return True, self.station

        _LOGGER.error("Redirect failed: %s", redirect_response.status_code)
        _LOGGER.error("%s", redirect_response.text)

        self.connected = False
        raise APIAuthError("Redirect failed.")

    def _login_la5(self) -> bool:
        """Login flow for la5 (SSO without pubkey)."""
    
        try:
            # Step 1: pre-warm session (important for cookies)
            base_url = f"https://{self.login_host}"
            self.session.get(f"{base_url}/", timeout=20)
    
            login_url = (
                f"{base_url}{LOGIN_VALIDATE_USER_URL_LA5}"
                "?service=%2Frest%2Fdp%2Fuidm%2Fauth%2Fv1%2Fon-sso-credential-ready"
            )
    
            payload = {
                "username": self.user,
                "password": self.pwd,
                "organizationName": "",
            }
    
            headers = {
                "Content-Type": "application/json;charset=UTF-8",
                "Accept": "application/json, text/plain, */*",
                "Origin": base_url,
                "Referer": base_url,
                "X-Requested-With": "XMLHttpRequest",
            }
    
            _LOGGER.debug("LA5 Login Request to: %s", login_url)
    
            response = self.session.post(
                login_url,
                json=payload,
                headers=headers,
                timeout=20,
            )
    
            _LOGGER.debug(
                "LA5 Login Response Headers: %s\r\nResponse: %s",
                response.headers,
                response.text,
            )
    
            if response.status_code != 200:
                raise APIAuthError(f"LA5 login failed: {response.status_code}")
    
            redirect_url = response.headers.get("redirect_url")
    
            if not redirect_url:
                raise APIAuthError("LA5 login missing redirect_url")
    
            # Step 2: follow SSO redirect (ticket)
            sso_url = f"{base_url}{redirect_url}"
            _LOGGER.debug("LA5 SSO redirect: %s", sso_url)
    
            self.session.get(sso_url, timeout=20, allow_redirects=False)
    
            # Step 3: final redirect (sets dp-session)
            final_url = f"{base_url}{FINAL_AUTH_URL_LA5}"
            _LOGGER.debug("LA5 final redirect: %s", final_url)
    
            final_response = self.session.get(final_url, timeout=20, allow_redirects=False)
    
            _LOGGER.debug(
                "LA5 Final Response Headers: %s",
                final_response.headers,
            )
    
            # Extract dp-session cookie
            dp_session = self.session.cookies.get("dp-session")
    
            if not dp_session:
                _LOGGER.error("LA5 DP Session not found in cookies.")
                raise APIAuthError("LA5 DP Session not found")
    
            self.dp_session = dp_session
            self.connected = True
            self.last_session_time = datetime.now(timezone.utc)
    
            # Detect data_host (important!)
            self.data_host = self.login_host
    
            _LOGGER.debug("LA5 Login successful. DP Session: %s", dp_session)
    
            # Continue normal flow
            self.refresh_csrf()
    
            station_data = self.get_station_list()
    
            if not self.station:
                self.station = station_data["data"]["list"][0]["dn"]
            else:
                if not any(s["dn"] == self.station for s in station_data["data"]["list"]):
                    raise APIDataStructureError(f"Station {self.station} not found.")
    
            if self.battery_capacity is None or self.battery_capacity == 0.0:
                self.battery_capacity = station_data["data"]["list"][0]["batteryCapacity"]
    
            self._start_session_monitor()
    
            return True, self.station
    
        except Exception as ex:
            _LOGGER.error("LA5 login failed: %s", ex)
            self.connected = False
            raise

    def _prevalidate_captcha(self, captcha_input: str) -> bool:
        """Pre-validate the captcha using the same endpoint as the web UI."""
        captcha_value = captcha_input.strip() if isinstance(captcha_input, str) else ""

        if not captcha_value:
            return False

        prevalidate_url = f"https://{self.login_host}/unisso/preValidVerifycode"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"https://{self.login_host}",
            "Referer": f"https://{self.login_host}{LOGIN_HEADERS_1_STEP_REFERER}",
            "X-Requested-With": "XMLHttpRequest",
        }

        payload = {
            "verifycode": captcha_value,
            "index": "0",
        }

        _LOGGER.debug("Pre-validating captcha at: %s", prevalidate_url)

        response = self.session.post(
            prevalidate_url,
            data=payload,
            headers=headers,
            timeout=20,
        )

        response_text = response.text.strip()
        normalized_response = response_text.strip('"').lower()

        _LOGGER.debug(
            "Captcha pre-validation response. Status=%s Response=%s",
            response.status_code,
            response_text,
        )

        if response.status_code != 200:
            return False

        invalid_markers = (
            "false",
            "fail",
            "failed",
            "failure",
            "incorrect",
            "invalid",
            "error",
            "411",
        )

        valid_markers = (
            "true",
            "success",
            "successful",
            "correct",
            "valid",
            "ok",
            "1",
        )

        if any(marker in normalized_response for marker in invalid_markers):
            return False

        if any(marker in normalized_response for marker in valid_markers):
            return True

        return True

    def restore_session(self, dp_session: str, data_host: str) -> None:
        """Restore an authenticated session without requiring login.

        Does NOT make HTTP calls — safe to call from the event loop.
        CSRF is refreshed lazily on the next API call that needs it.
        """
        self.dp_session = dp_session
        self.data_host = data_host
        self.session.cookies.set("dp-session", dp_session)
        self.session.cookies.set("locale", "en-us")
        self.connected = True
        self.last_session_time = datetime.now(timezone.utc)
        self._start_session_monitor()

    def reset_session(self):
        """Reset HTTP session, clearing cookies and volatile auth state."""
        try:
            self.session.close()
        except Exception:
            pass
    
        self.session = requests.Session()
        self.session.cookies.set("locale", "en-us")
        self.connected = False
        self.dp_session = ""
        self.csrf = None
        self.csrf_time = None
        self.captcha_input = None
        self.captcha_img = None
        
    def _response_looks_like_auth_failure(self, response: requests.Response) -> bool:
        """Return True when the response looks like an expired-session login page."""
        location = (response.headers.get("Location") or "").lower()
        content_type = (response.headers.get("Content-Type") or "").lower()
        body_preview = (response.text or "")[:500].lower()
    
        auth_markers = (
            "login",
            "sign in",
            "verifycode",
            "captcha",
            "dpcloud/auth",
            "uniportal",
            "user name",
            "username",
            "password",
        )
    
        return (
            response.status_code in (401, 403)
            or "login" in location
            or (
                "text/html" in content_type
                and any(marker in body_preview for marker in auth_markers)
            )
        )
    
    def _request_json(
        self,
        method: str,
        url: str,
        *,
        context: str,
        timeout: int | None = None,
        **kwargs,
    ) -> tuple[requests.Response, dict]:
        """Perform an HTTP request and return parsed JSON with robust auth/timeout handling."""
        effective_timeout = timeout or self.request_timeout
    
        try:
            response = self.session.request(
                method,
                url,
                timeout=effective_timeout,
                **kwargs,
            )
        except requests.Timeout as err:
            raise APIConnectionError(
                f"{context} timed out after {effective_timeout}s"
            ) from err
        except requests.RequestException as err:
            raise APIConnectionError(f"{context} request failed: {err}") from err
    
        if self._response_looks_like_auth_failure(response):
            _LOGGER.warning(
                "%s appears to have returned an auth page or expired session. "
                "Status=%s Headers=%s Body=%s",
                context,
                response.status_code,
                response.headers,
                response.text[:300],
            )
            self.connected = False
            raise APIAuthError(f"{context} returned an expired or invalid session")
    
        if response.status_code != 200:
            _LOGGER.error(
                "%s failed. Status=%s Headers=%s Body=%s",
                context,
                response.status_code,
                response.headers,
                response.text[:300],
            )
            raise APIConnectionError(
                f"{context} failed with HTTP {response.status_code}"
            )
    
        try:
            payload = response.json()
        except json.JSONDecodeError as err:
            content_type = response.headers.get("Content-Type", "")
            body_preview = response.text[:300]
    
            if (
                "html" in content_type.lower()
                or "<html" in body_preview.lower()
                or "<!doctype" in body_preview.lower()
            ):
                _LOGGER.warning(
                    "%s returned HTML instead of JSON. Treating it as an expired "
                    "session. Status=%s Body=%s",
                    context,
                    response.status_code,
                    body_preview,
                )
                self.connected = False
                raise APIAuthError(f"{context} returned HTML instead of JSON") from err
    
            _LOGGER.error(
                "%s did not return JSON. Content-Type=%s Body=%s",
                context,
                content_type,
                body_preview,
            )
            raise APIConnectionError(f"{context} did not return JSON") from err
    
        return response, payload

    def set_captcha_img(self):
        """Fetch a new captcha image using the current session."""
        self.captcha_input = None

        timestamp_now = int(time.time() * 1000)
        captcha_request_url = (
            f"https://{self.login_host}{CAPTCHA_URL}?timestamp={timestamp_now}"
        )

        headers = {
            "Accept": "*/*",
            "Referer": f"https://{self.login_host}{LOGIN_HEADERS_1_STEP_REFERER}",
        }

        _LOGGER.debug("Requesting Captcha at: %s", captcha_request_url)

        response = self.session.get(
            captcha_request_url,
            headers=headers,
            timeout=20,
        )

        if response.status_code == 200 and response.content:
            self.captcha_img = (
                "data:image/png;base64,"
                f"{base64.b64encode(response.content).decode('utf-8')}"
            )
            _LOGGER.debug("Captcha image refreshed successfully.")
            return

        self.captcha_img = None

        _LOGGER.warning(
            "Failed to fetch captcha image. Status=%s Headers=%s Body=%s",
            response.status_code,
            response.headers,
            response.text[:300],
        )

    def refresh_csrf(self):
        """Refresh the CSRF token when needed."""
        now = datetime.now()
    
        if (
            self.csrf is not None
            and self.csrf_time is not None
            and now - self.csrf_time <= timedelta(minutes=5)
        ):
            return
    
        roarand_url = f"https://{self.data_host}{KEEP_ALIVE_URL}"
        roarand_headers = {
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }
    
        _LOGGER.debug("Getting Roarand at: %s", roarand_url)
        _, roarand_json = self._request_json(
            "GET",
            roarand_url,
            context="FusionSolar keep-alive",
            headers=roarand_headers,
        )
    
        csrf_value = roarand_json.get("payload")
        if not csrf_value:
            _LOGGER.error(
                "Keep-alive JSON did not contain a CSRF payload. Body=%s",
                str(roarand_json)[:300],
            )
            self.connected = False
            raise APIAuthError("Could not refresh CSRF token")
    
        self.csrf = csrf_value
        self.csrf_time = now
        _LOGGER.debug("CSRF refreshed: %s", self.csrf)

    
    def get_station_id(self):
        return self.get_station_list()["data"]["list"][0]["dn"]

    def get_station_list(self):
        """Return the list of stations for the authenticated account."""
        self.refresh_csrf()
    
        station_url = f"https://{self.data_host}{STATION_LIST_URL}"
    
        station_headers = {
            "accept": "application/json, text/javascript, */*; q=0.01",
            "accept-encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "Origin": f"https://{self.data_host}",
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
            "Roarand": f"{self.csrf}",
        }
    
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
        _, json_response = self._request_json(
            "POST",
            station_url,
            context="FusionSolar station list",
            headers=station_headers,
            json=station_payload,
        )
    
        stations = json_response.get("data", {}).get("list")
        if not isinstance(stations, list):
            _LOGGER.error(
                "Station list response did not contain the expected data. Body=%s",
                str(json_response)[:300],
            )
            raise APIDataStructureError("Station list response did not contain data.list")
    
        _LOGGER.debug("Station info: %s", json_response.get("data"))
        return json_response

    def call_social_contribution(self):
        """Call the social contribution endpoint and return parsed JSON."""
        self.refresh_csrf()

        current_time = int(datetime.now().timestamp() * 1000)
        local_offset = datetime.now().astimezone().utcoffset()
        time_zone_hours = int(local_offset.total_seconds() / 3600) if local_offset else 0

        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "Host": self.data_host,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
            "X-Requested-With": "XMLHttpRequest",
            "Roarand": self.csrf,
        }

        params = {
            "dn": unquote(self.station),
            "clientTime": current_time,
            "timeZone": str(time_zone_hours),
            "_": current_time,
        }

        social_contribution_url = (
            f"https://{self.data_host}{SOCIAL_CONTRIBUTION_URL}?{urlencode(params)}"
        )
        _LOGGER.debug("Getting Social Contribution at: %s", social_contribution_url)

        response = self.session.get(
            social_contribution_url,
            headers=headers,
            timeout=20,
        )

        if response.status_code != 200:
            _LOGGER.error(
                "Social contribution request failed. Status=%s Body=%s",
                response.status_code,
                response.text[:300],
            )
            raise APIConnectionError("Social contribution request failed")

        try:
            social_contribution_data = response.json()
        except json.JSONDecodeError as err:
            _LOGGER.error(
                "Social contribution did not return JSON. Status=%s Content-Type=%s Body=%s",
                response.status_code,
                response.headers.get("Content-Type"),
                response.text[:300],
            )
            raise APIAuthError("Social contribution did not return JSON") from err

        if "data" not in social_contribution_data:
            _LOGGER.error(
                "Social contribution response had an unexpected structure: %s",
                str(social_contribution_data)[:500],
            )
            raise APIDataStructureError(
                "Social contribution response did not contain data"
            )

        _LOGGER.debug("Social Contribution Response: %s", social_contribution_data)
        return social_contribution_data
    
    def update_output_with_social_contribution(
        self,
        output: Dict[str, Optional[float | str]],
    ):
        """Populate social contribution values in the output dictionary."""
        _LOGGER.debug("Getting social contribution data")

        social_contribution_data = self.call_social_contribution()
        data = social_contribution_data.get("data", {})

        output["standard_coal_saved"] = extract_numeric(
            data.get("standardCoalSavings", 0)
        )
        output["standard_coal_saved_this_year"] = extract_numeric(
            data.get("standardCoalSavingsByYear", 0)
        )
        output["co2_avoided"] = extract_numeric(
            data.get("co2Reduction", 0)
        )
        output["co2_avoided_this_year"] = extract_numeric(
            data.get("co2ReductionByYear", 0)
        )
        output["equivalent_trees_planted"] = int(
            round(extract_numeric(data.get("equivalentTreePlanting", 0)))
        )
        output["equivalent_trees_planted_this_year"] = int(
            round(extract_numeric(data.get("equivalentTreePlantingByYear", 0)))
        )
    
    def get_inverter_realtime_data(self) -> dict:
        """Fetch real-time inverter data and dynamically expose only visible PV inputs."""
        if not self.inverter_dn:
            return {}
    
        signal_map = get_inverter_signal_map()
    
        self.refresh_csrf()
        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }
        params = {"deviceDn": self.inverter_dn, "displayAccessModel": "true"}
    
        realtime_url = f"https://{self.data_host}{DEVICE_REALTIME_DATA_URL}"
        _LOGGER.debug("Getting inverter realtime data at: %s", realtime_url)
    
        _, realtime_data = self._request_json(
            "GET",
            realtime_url,
            context="FusionSolar inverter realtime data",
            headers=headers,
            params=params,
        )
    
        if not realtime_data.get("success") or not realtime_data.get("data"):
            _LOGGER.warning(
                "Inverter realtime data response indicates failure: %s",
                realtime_data,
            )
            return {}
    
        result: dict[int, Any] = {}
    
        # Collect general inverter signals from the realtime endpoint.
        for entry in realtime_data["data"]:
            if not isinstance(entry, dict) or "signals" not in entry:
                continue
    
            for signal in entry["signals"]:
                signal_id = signal.get("id")
                signal_value = signal.get("value", "")
    
                if signal_id not in signal_map:
                    continue
    
                if signal_value in ("", "--", "null", None):
                    continue
    
                result[signal_id] = signal_value
    
        # Query only PV voltage/current signal IDs from KPI.
        pv_voltage_current_signal_ids: list[int] = []
        for pv_index in range(1, 21):
            voltage_id = 11001 + ((pv_index - 1) * 3)
            current_id = voltage_id + 1
            pv_voltage_current_signal_ids.extend([voltage_id, current_id])
    
        pv_signal_meta: dict[int, dict[str, Any]] = {}
    
        if pv_voltage_current_signal_ids:
            try:
                self.refresh_csrf()
                headers["Roarand"] = self.csrf
                signal_str = "&".join(
                    f"signalIds={signal_id}"
                    for signal_id in pv_voltage_current_signal_ids
                )
                kpi_url = (
                    f"https://{self.data_host}{DEVICE_REAL_KPI_URL}"
                    f"?deviceDn={self.inverter_dn}&{signal_str}"
                )
                _LOGGER.debug("Getting inverter PV KPI data at: %s", kpi_url)
    
                _, kpi_data = self._request_json(
                    "GET",
                    kpi_url,
                    context="FusionSolar inverter PV KPI data",
                    headers=headers,
                )
    
                if kpi_data.get("success") and kpi_data.get("data", {}).get("signals"):
                    for sid_str, val in kpi_data["data"]["signals"].items():
                        sid = int(sid_str)
    
                        if sid not in signal_map:
                            continue
    
                        raw_value = val.get("value", "")
                        if raw_value in ("", "--", "null", None):
                            continue
    
                        pv_signal_meta[sid] = {
                            "value": raw_value,
                            "latestTime": val.get("latestTime"),
                        }
            except Exception as ex:
                _LOGGER.warning("Failed to fetch PV string KPI data: %s", ex)
    
        visible_pv_indexes = self._get_visible_pv_indexes_from_signal_meta(pv_signal_meta)
    
        # Keep only voltage/current values for visible PV inputs.
        for sid, meta in pv_signal_meta.items():
            pv_index = ((sid - 11001) // 3) + 1
            if pv_index not in visible_pv_indexes:
                continue
            result[sid] = meta["value"]
    
        # Calculate PV power locally for visible PV inputs.
        for pv_index in visible_pv_indexes:
            voltage_id = 11001 + ((pv_index - 1) * 3)
            current_id = voltage_id + 1
            power_id = voltage_id + 2
    
            if voltage_id not in result or current_id not in result:
                continue
    
            voltage_value = extract_numeric(result[voltage_id])
            current_value = extract_numeric(result[current_id])
            result[power_id] = round(voltage_value * current_value / 1000, 4)
    
        _LOGGER.debug(
            "Inverter realtime data after PV filtering: visible_pv_indexes=%s result=%s",
            sorted(visible_pv_indexes),
            result,
        )
        return result
    
    def _get_visible_pv_indexes_from_signal_meta(
        self,
        pv_signal_meta: dict[int, dict[str, Any]],
        max_pv_inputs: int = 20,
    ) -> set[int]:
        """Determine which PV inputs should be exposed.
    
        The FusionSolar web UI requests many PV signal IDs, but on some inverters
        the API returns a repeated stale zero-value tail for non-existent inputs.
        This method keeps the contiguous real PV inputs and trims that placeholder tail.
        """
        pv_pairs: list[dict[str, Any]] = []
    
        for pv_index in range(1, max_pv_inputs + 1):
            voltage_id = 11001 + ((pv_index - 1) * 3)
            current_id = voltage_id + 1
    
            voltage_meta = pv_signal_meta.get(voltage_id)
            current_meta = pv_signal_meta.get(current_id)
    
            if voltage_meta is None and current_meta is None:
                continue
    
            voltage_value = (
                extract_numeric(voltage_meta.get("value"))
                if voltage_meta is not None
                else 0.0
            )
            current_value = (
                extract_numeric(current_meta.get("value"))
                if current_meta is not None
                else 0.0
            )
            voltage_time = voltage_meta.get("latestTime") if voltage_meta else None
            current_time = current_meta.get("latestTime") if current_meta else None
    
            pv_pairs.append(
                {
                    "pv_index": pv_index,
                    "voltage_value": voltage_value,
                    "current_value": current_value,
                    "voltage_time": voltage_time,
                    "current_time": current_time,
                    "is_zero_only": voltage_value == 0 and current_value == 0,
                    "time_tuple": (voltage_time, current_time),
                }
            )
    
        if not pv_pairs:
            return set()
    
        cutoff_index: int | None = None
    
        for pos, pair in enumerate(pv_pairs):
            tail = pv_pairs[pos:]
    
            if len(tail) < 2:
                continue
    
            if not pair["is_zero_only"]:
                continue
    
            placeholder_time_tuple = pair["time_tuple"]
    
            if all(
                tail_pair["is_zero_only"]
                and tail_pair["time_tuple"] == placeholder_time_tuple
                for tail_pair in tail
            ):
                cutoff_index = pair["pv_index"] - 1
                break
    
        if cutoff_index is None:
            cutoff_index = pv_pairs[-1]["pv_index"]
    
        visible_indexes = {
            pair["pv_index"]
            for pair in pv_pairs
            if pair["pv_index"] <= cutoff_index
        }
    
        _LOGGER.debug(
            "Visible PV indexes determined from signal metadata: %s (cutoff=%s, pairs=%s)",
            sorted(visible_indexes),
            cutoff_index,
            pv_pairs,
        )
    
        return visible_indexes

    def get_devices(self) -> list[Device]:
        """Fetch device values from the FusionSolar data endpoint."""
        self.refresh_csrf()
    
        if not self.station:
            raise APIDataStructureError("FusionSolar station DN is not configured")
    
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
        }
    
        params = {"stationDn": unquote(self.station)}
    
        data_access_url = f"https://{self.data_host}{DATA_URL}"
        _LOGGER.debug("Getting Data at: %s", data_access_url)
    
        _, data = self._request_json(
            "GET",
            data_access_url,
            context="FusionSolar realtime data",
            headers=headers,
            params=params,
        )
    
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
            "self_consumption_ratio_today": 0.0,
            "self_consumption_ratio_week": 0.0,
            "self_consumption_ratio_month": 0.0,
            "self_consumption_ratio_year": 0.0,
            "self_consumption_ratio_lifetime": 0.0,
            "self_consumption_ratio_by_production_today": 0.0,
            "self_consumption_ratio_by_production_week": 0.0,
            "self_consumption_ratio_by_production_month": 0.0,
            "self_consumption_ratio_by_production_year": 0.0,
            "self_consumption_ratio_by_production_lifetime": 0.0,
            "standard_coal_saved": 0.0,
            "standard_coal_saved_this_year": 0.0,
            "co2_avoided": 0.0,
            "co2_avoided_this_year": 0.0,
            "equivalent_trees_planted": 0,
            "equivalent_trees_planted_this_year": 0,
            "exit_code": "SUCCESS",
        }
    
        if "data" not in data or "flow" not in data["data"]:
            _LOGGER.error(
                "FusionSolar realtime data response had an unexpected structure. "
                "Cookies=%s Headers=%s Body=%s",
                self.session.cookies.get_dict(),
                headers,
                str(data)[:500],
            )
            raise APIDataStructureError("FusionSolar realtime data structure is invalid")
    
        _LOGGER.debug("Get Data Response: %s", data)
    
        flow_data_nodes = data["data"]["flow"].get("nodes", [])
        flow_data_links = data["data"]["flow"].get("links", [])
    
        if not isinstance(flow_data_nodes, list) or not isinstance(flow_data_links, list):
            raise APIDataStructureError("FusionSolar flow nodes/links structure is invalid")
    
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
    
                battery_power = extract_numeric(
                    node.get("deviceTips", {}).get("BATTERY_POWER", "")
                )
                if battery_power is None or battery_power <= 0:
                    output["battery_consumption_power"] = extract_numeric(value)
                    output["battery_injection_power"] = 0.0
                else:
                    output[node_map[label]] = extract_numeric(value)
                    output["battery_consumption_power"] = 0.0
            elif label in node_map:
                output[node_map[label]] = extract_numeric(value)
    
        for node in flow_data_links:
            label = node.get("description", {}).get("label", "")
            value = node.get("description", {}).get("value", "")
            if label in node_map and label == "neteco.pvms.energy.flow.buy.power":
                grid_consumption_injection = extract_numeric(value)
                if (
                    output["panel_production_power"]
                    + output["battery_consumption_power"]
                    - output["battery_injection_power"]
                    - output["house_load_power"]
                ) > 0:
                    output["grid_injection_power"] = grid_consumption_injection
                    output["grid_consumption_power"] = 0.0
                else:
                    output["grid_consumption_power"] = grid_consumption_injection
                    output["grid_injection_power"] = 0.0
    
        if self.inverter_dn is None:
            for node in flow_data_nodes:
                if node.get("name") == "neteco.pvms.devTypeLangKey.inverter":
                    dev_ids = node.get("devIds") or []
                    dn = dev_ids[0] if dev_ids else node.get("devDn")
                    if dn:
                        self.inverter_dn = dn
                        _LOGGER.info("Discovered inverter DN: %s", self.inverter_dn)
                    else:
                        _LOGGER.warning(
                            "Could not determine inverter DN from inverter node. Node: %s",
                            node,
                        )
                    break
    
        self.update_output_with_battery_capacity(output)
        self.update_output_with_energy_balance(output)
        self._update_output_with_self_consumption_ratios(output)
    
        try:
            self.update_output_with_social_contribution(output)
        except Exception as ex:
            _LOGGER.warning("Failed to fetch social contribution data: %s", ex)
    
        output["exit_code"] = "SUCCESS"
        _LOGGER.debug("output JSON: %s", output)
    
        devices = [
            Device(
                device_id=device.get("id"),
                device_unique_id=self.get_device_unique_id(
                    device.get("id"),
                    device.get("type"),
                ),
                device_type=device.get("type"),
                name=self.get_device_name(device.get("id")),
                state=self.get_device_value(
                    device.get("id"),
                    device.get("type"),
                    output,
                ),
                icon=device.get("icon"),
            )
            for device in DEVICES
        ]
    
        try:
            inverter_data = self.get_inverter_realtime_data()
            signal_map = get_inverter_signal_map()
            for signal_id, value in inverter_data.items():
                if signal_id in signal_map:
                    sig = signal_map[signal_id]
                    sig_type = sig["type"]
                    if sig_type == DeviceType.SENSOR_TEXT:
                        state = str(value)
                    else:
                        try:
                            state = float(value)
                        except (ValueError, TypeError):
                            state = 0.0
    
                    devices.append(
                        Device(
                            device_id=sig["id"],
                            device_unique_id=self.get_device_unique_id(
                                sig["id"],
                                sig_type,
                            ),
                            device_type=sig_type,
                            name=sig["id"],
                            state=state,
                            icon=sig["icon"],
                        )
                    )
        except Exception as ex:
            _LOGGER.warning("Failed to fetch inverter realtime data: %s", ex)
    
        return devices

    def _calculate_ratio_percentage(self, numerator: float, denominator: float) -> float:
        """Return a percentage ratio with safe division handling."""
        if denominator <= 0:
            return 0.0
    
        return round((numerator / denominator) * 100, 2)
    
    
    def _update_output_with_self_consumption_ratios(self, output: Dict[str, Optional[float | str]]):
        """Populate self-consumption ratios for all supported periods."""
        periods = ("today", "week", "month", "year", "lifetime")
    
        for period in periods:
            self_use_value = float(output.get(f"panel_production_consumption_{period}", 0.0) or 0.0)
            house_load_value = float(output.get(f"house_load_{period}", 0.0) or 0.0)
            panel_production_value = float(output.get(f"panel_production_{period}", 0.0) or 0.0)
    
            output[f"self_consumption_ratio_{period}"] = self._calculate_ratio_percentage(
                self_use_value,
                house_load_value,
            )
            output[f"self_consumption_ratio_by_production_{period}"] = self._calculate_ratio_percentage(
                self_use_value,
                panel_production_value,
            )
            
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
    
        self._update_output_with_self_consumption_ratios(output)
        
        
    def call_energy_balance(
        self,
        call_type: ENERGY_BALANCE_CALL_TYPE,
        specific_date: datetime = None,
    ):
        """Call the energy balance endpoint and return parsed JSON."""
        self.refresh_csrf()
    
        currentTime = datetime.now()
        timestampNow = currentTime.timestamp() * 1000
        current_day = currentTime.day
        current_month = currentTime.month
        current_year = currentTime.year
        first_day_of_month = datetime(current_year, current_month, 1)
        first_day_of_previous_month = first_day_of_month - relativedelta(months=1)
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
                current_day_of_year = datetime(
                    specific_year,
                    specific_month,
                    specific_day,
                )
            else:
                current_day_of_year = datetime(current_year, current_month, current_day)
    
            timestamp = current_day_of_year.timestamp() * 1000
            dateStr = current_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp = first_day_of_year.timestamp() * 1000
            dateStr = first_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
    
        headers = {
            "application/json": "text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "Host": self.data_host,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
            "X-Requested-With": "XMLHttpRequest",
            "Roarand": self.csrf,
        }
    
        params = {
            "stationDn": unquote(self.station),
            "timeDim": call_type,
            "queryTime": int(timestamp),
            "timeZone": "0.0",
            "timeZoneStr": "Europe/London",
            "dateStr": dateStr,
            "_": int(timestampNow),
        }
    
        energy_balance_url = (
            f"https://{self.data_host}{ENERGY_BALANCE_URL}?{urlencode(params)}"
        )
        _LOGGER.debug("Getting Energy Balance at: %s", energy_balance_url)
    
        _, energy_balance_data = self._request_json(
            "GET",
            energy_balance_url,
            context=f"FusionSolar energy balance ({call_type})",
            headers=headers,
        )
    
        if "data" not in energy_balance_data:
            _LOGGER.error(
                "Energy balance response had an unexpected structure: %s",
                str(energy_balance_data)[:500],
            )
            raise APIDataStructureError("Energy balance response did not contain data")
    
        _LOGGER.debug("Energy Balance Response: %s", energy_balance_data)
        return energy_balance_data

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
        self.reset_session()
        try:
            self.login()
        except APIAuthCaptchaError:
            _LOGGER.error(
                "Session renewal requires CAPTCHA. "
                "Automated renewal is not possible. "
                "Please reconfigure the integration."
            )
            self.connected = False
        except Exception as ex:
            _LOGGER.error("Session renewal failed: %s", ex)
            self.connected = False

    def _session_monitor(self) -> None:
        """Monitor session and renew if needed."""
        while not self._stop_event.is_set():
            if not self.connected:
                self._renew_session()
                if not self.connected:
                    _LOGGER.warning("Session monitor stopping: renewal failed")
                    self._stop_event.set()
                    break
            self._stop_event.wait(60)

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

        station_suffix = ""
        if self.station:
            safe = (
                str(self.station)
                .lower()
                .replace(" ", "_")
                .replace(":", "_")
                .replace("/", "_")
            )
            station_suffix = f"_{safe}"

        return f"{self.controller_name}{station_suffix}_{device_id.lower().replace(' ', '_')}"


    def get_device_name(self, device_id: str) -> str:
        """Return the device name."""
        return device_id

    def get_device_value(
        self,
        device_id: str,
        device_type: DeviceType,
        output: Dict[str, Optional[float | str]],
        default: int = 0,
    ) -> float | int | datetime | str:
        """Return the normalized device value for the requested entity."""
        if device_type == DeviceType.SENSOR_TIME:
            _LOGGER.debug(
                "%s: Value being returned is datetime: %s",
                device_id,
                self.last_session_time,
            )
            return self.last_session_time
    
        output_key = device_id.lower().replace(" ", "_")
        if output_key not in output:
            raise KeyError(f"'{device_id}' not found.")
    
        value = output[output_key]
        if value is None or value == "None":
            return default
    
        if device_type == DeviceType.SENSOR_TEXT:
            return str(value)
    
        if device_type == DeviceType.SENSOR_PERCENTAGE:
            return int(float(value))
    
        if device_type == DeviceType.SENSOR_COUNT:
            return int(round(float(value)))
    
        if device_type in (
            DeviceType.SENSOR_KW,
            DeviceType.SENSOR_KWH,
            DeviceType.SENSOR_RATIO,
            DeviceType.SENSOR_VOLTAGE,
            DeviceType.SENSOR_CURRENT,
            DeviceType.SENSOR_FREQUENCY,
            DeviceType.SENSOR_TEMPERATURE,
            DeviceType.SENSOR_RESISTANCE,
            DeviceType.SENSOR_POWER_FACTOR,
            DeviceType.SENSOR_KG,
        ):
            decimals = 2 if device_type == DeviceType.SENSOR_RATIO else 4
            _LOGGER.debug("%s: Value being returned is float: %s", device_id, value)
            return round(float(value), decimals)
    
        return value

class APIAuthError(Exception):
    """Exception class for auth error."""

class APIAuthCaptchaError(Exception):
    """Exception class for auth captcha error."""

class APIConnectionError(Exception):
    """Exception class for connection error."""

class APIDataStructureError(Exception):
    """Exception class for Data error."""
