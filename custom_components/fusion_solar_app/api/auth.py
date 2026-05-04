import base64
from datetime import datetime, timedelta, timezone
import json
import logging
import re
import time
from urllib.parse import quote, urlparse

import requests

from ..const import (
    CAPTCHA_URL,
    DATA_REFERER_URL,
    FINAL_AUTH_URL_LA5,
    KEEP_ALIVE_URL,
    LOGIN_FORM_URL,
    LOGIN_HEADERS_1_STEP_REFERER,
    LOGIN_HEADERS_2_STEP_REFERER,
    LOGIN_VALIDATE_USER_URL,
    LOGIN_VALIDATE_USER_URL_LA5,
    PUBKEY_URL,
)
from ..utils import encrypt_password, generate_nonce
from .exceptions import APIAuthCaptchaError, APIAuthError, APIConnectionError


_LOGGER = logging.getLogger(__name__)


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


class FusionSolarAuthMixin:
    """Authentication and session helpers for FusionSolar API."""

    def login(self) -> bool:
        """Connect to api."""
        if any(host in self.login_host for host in ("la5", "intl")):
            _LOGGER.debug("Using LA5 login flow")
            return self._login_la5()
        else:
            _LOGGER.debug("Using EU5 login flow")
            return self._login_eu5()

    def _login_eu5(self) -> bool:
        """Connect to API using the EU5 login flow.
    
        The method first tries the modern browser-aligned flow using the nested
        service parameter. If that does not return redirect information, it falls
        back once to the legacy flow to preserve backwards compatibility.
        """
        captcha_input = ""
    
        if isinstance(self.captcha_input, str):
            captcha_input = self.captcha_input.strip()
    
        # Browser-aligned flow first, legacy flow second as fallback.
        login_modes = [True, False]
    
        if not captcha_input:
            login_page_url = self._get_eu5_login_page_url(use_service=True)
            _LOGGER.debug("Pre-warming EU5 session by visiting login page: %s", login_page_url)
    
            try:
                self.session.get(login_page_url, timeout=20)
            except Exception as ex:
                _LOGGER.warning("Failed to pre-warm EU5 session: %s", ex)
    
        if captcha_input:
            captcha_is_valid = self._prevalidate_captcha(captcha_input)
    
            if not captcha_is_valid:
                _LOGGER.warning("Captcha pre-validation failed.")
                self.connected = False
                self.set_captcha_img()
                raise APIAuthCaptchaError("Invalid captcha.")
    
        public_key_url = f"https://{self.login_host}{PUBKEY_URL}"
        pubkey_headers = {
            "Accept": "application/json",
            "Referer": self._get_eu5_login_page_url(use_service=True),
        }
    
        _LOGGER.debug("Getting Public Key at: %s", public_key_url)
    
        response = self.session.get(
            public_key_url,
            headers=pubkey_headers,
            timeout=20,
        )
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
    
        last_error_code = ""
        last_error_message = ""
        last_verify_code_create = False
    
        for use_service in login_modes:
            login_page_url = self._get_eu5_login_page_url(use_service=use_service)
            login_url = self._get_eu5_validate_user_url(
                time_stamp=time_stamp,
                nonce=nonce,
                use_service=use_service,
            )
    
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "accept-encoding": "gzip, deflate, br, zstd",
                "connection": "keep-alive",
                "host": self.login_host,
                "origin": f"https://{self.login_host}",
                "referer": login_page_url,
                "x-requested-with": "XMLHttpRequest",
            }
    
            _LOGGER.debug(
                "EU5 login attempt. use_service=%s login_url=%s referer=%s",
                use_service,
                login_url,
                login_page_url,
            )
    
            response = self.session.post(
                login_url,
                json=payload,
                headers=headers,
                timeout=20,
            )
    
            _LOGGER.debug(
                "Login attempt (use_service=%s): Request Headers: %s\r\nResponse Headers: %s\r\nResponse: %s",
                use_service,
                headers,
                response.headers,
                response.text,
            )
    
            if response.status_code != 200:
                _LOGGER.warning(
                    "EU5 login attempt failed with HTTP %s (use_service=%s)",
                    response.status_code,
                    use_service,
                )
                continue
    
            try:
                login_response = response.json()
                _LOGGER.debug("Login Response (use_service=%s): %s", use_service, login_response)
            except Exception as ex:
                _LOGGER.warning(
                    "EU5 login response was not valid JSON (use_service=%s).",
                    use_service,
                )
                if not use_service:
                    self.connected = False
                    raise APIAuthError(
                        "Error processing Login response: JSON format invalid!"
                    ) from ex
                continue
    
            redirect_url = self._extract_eu5_redirect_url(login_response)
            if redirect_url:
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
                    self._update_station_metadata_from_station_list(station_data)
    
                    self._start_session_monitor()
                    return True, self.station
    
                _LOGGER.error("Redirect failed: %s", redirect_response.status_code)
                _LOGGER.error("%s", redirect_response.text)
                self.connected = False
                raise APIAuthError("Redirect failed.")
    
            last_error_code = str(login_response.get("errorCode", ""))
            last_error_message = str(login_response.get("errorMsg", ""))
            last_verify_code_create = bool(login_response.get("verifyCodeCreate"))
    
            _LOGGER.warning(
                "EU5 login response did not include redirect information. use_service=%s errorCode=%s errorMsg=%s verifyCodeCreate=%s",
                use_service,
                last_error_code,
                last_error_message,
                last_verify_code_create,
            )
    
            if last_error_code == "411" or last_verify_code_create:
                self.connected = False
                _LOGGER.warning("Captcha required or captcha challenge still active.")
                self.set_captcha_img()
                raise APIAuthCaptchaError("Login requires Captcha.")
    
            # Only raise invalid credentials after both modes have been tried.
            if not use_service and last_error_code == "406":
                self.connected = False
                raise APIAuthError("Invalid username or password.")
    
        self.connected = False
        raise APIAuthError(
            "Login response did not include redirect information."
        )

    def _login_la5(self) -> bool:
        """Login flow for la5 (SSO without pubkey)."""
        try:
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

            sso_url = f"{base_url}{redirect_url}"
            _LOGGER.debug("LA5 SSO redirect: %s", sso_url)

            self.session.get(sso_url, timeout=20, allow_redirects=False)

            final_url = f"{base_url}{FINAL_AUTH_URL_LA5}"
            _LOGGER.debug("LA5 final redirect: %s", final_url)

            final_response = self.session.get(final_url, timeout=20, allow_redirects=False)

            _LOGGER.debug(
                "LA5 Final Response Headers: %s",
                final_response.headers,
            )

            dp_session = self.session.cookies.get("dp-session")

            if not dp_session:
                _LOGGER.error("LA5 DP Session not found in cookies.")
                raise APIAuthError("LA5 DP Session not found")

            self.dp_session = dp_session
            self.connected = True
            self.last_session_time = datetime.now(timezone.utc)
            self.data_host = self.login_host

            _LOGGER.debug("LA5 Login successful. DP Session: %s", dp_session)

            self.refresh_csrf()

            station_data = self.get_station_list()
            self._update_station_metadata_from_station_list(station_data)

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
    
    def _get_eu5_service_value(self) -> str:
        """Return the nested service value used by the EU5 web login flow."""
        return "/unisess/v1/auth?service=%2Fnetecowebext%2Fhome%2Findex.html"
        
    def _get_eu5_login_page_url(self, use_service: bool) -> str:
        """Return the EU5 login page URL, optionally including the nested service parameter."""
        base_url = f"https://{self.login_host}{LOGIN_FORM_URL}"
    
        if not use_service:
            return base_url
    
        service_value = self._get_eu5_service_value()
        encoded_service = quote(service_value, safe="")
        return f"{base_url}?service={encoded_service}"
    
    def _get_eu5_validate_user_url(
        self,
        time_stamp: str,
        nonce: str,
        use_service: bool,
    ) -> str:
        """Return the EU5 validate-user URL, optionally including the nested service parameter."""
        base_url = (
            f"https://{self.login_host}{LOGIN_VALIDATE_USER_URL}"
            f"?timeStamp={time_stamp}&nonce={nonce}"
        )
    
        if not use_service:
            return base_url
    
        service_value = self._get_eu5_service_value()
        encoded_service = quote(service_value, safe="")
        return f"{base_url}&service={encoded_service}"
    
    def _extract_eu5_redirect_url(self, login_response: dict) -> str | None:
        """Extract the redirect URL from the EU5 login response."""
        if login_response.get("respMultiRegionName"):
            redirect_info = login_response["respMultiRegionName"][1]
            return f"https://{self.login_host}{redirect_info}"
    
        if login_response.get("redirectURL"):
            redirect_info = login_response["redirectURL"]
            return f"https://{self.login_host}{redirect_info}"
    
        return None
    
    