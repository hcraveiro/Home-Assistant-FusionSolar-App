"""Instance-local, network-incapable runtime backend exercising the real readers."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from urllib.parse import parse_qs, urlsplit

import requests

from .api import FusionSolarAPI
from .mock_profile import READ_ONLY_GET_PATHS, READ_ONLY_POST_PATHS, validate_profile


class UnexpectedMockRequest(AssertionError):
    """A runtime profile did not explicitly describe an operation."""


class OfflineSession(requests.Session):
    """No adapter is ever invoked, including for prepared requests and redirects."""

    def __init__(self, profile, unexpected=None):
        super().__init__()
        self.trust_env = False
        self.adapters.clear()
        self.profile = profile
        self.unexpected = unexpected if unexpected is not None else []
        self.calls = []

    def _reject(self, message):
        self.unexpected.append(message)
        raise UnexpectedMockRequest(message)

    def request(self, method, url, **kwargs):
        # Use requests only to normalize URL/query/form encoding, never its transport.
        request = requests.Request(
            method.upper(), url, params=kwargs.get("params"),
            json=kwargs.get("json"), data=kwargs.get("data"),
            headers=kwargs.get("headers"),
        ).prepare()
        return self.send(request)

    def send(self, request, **kwargs):
        parsed = urlsplit(request.url)
        method = request.method.upper()
        if parsed.scheme != "https" or parsed.netloc != "example.invalid" or parsed.fragment:
            return self._reject("Offline transport forbids this origin")
        if not ((method == "GET" and parsed.path in READ_ONLY_GET_PATHS)
                or (method == "POST" and parsed.path in READ_ONLY_POST_PATHS)):
            return self._reject("Offline transport forbids unknown/read-write operations")
        query = parse_qs(parsed.query, keep_blank_values=True)
        body = request.body
        content_type = request.headers.get("Content-Type", "")
        if body is not None:
            if isinstance(body, bytes):
                body = body.decode("utf-8")
            if "application/json" in content_type:
                body = json.loads(body)
            elif "application/x-www-form-urlencoded" in content_type:
                body = {key: values[0] if len(values) == 1 else values
                        for key, values in parse_qs(body, keep_blank_values=True).items()}
        self.calls.append((method, parsed.path, query, body))
        for route in self.profile["routes"]:
            if method != route["method"] or parsed.path != route["path"]:
                continue
            if not self._query_matches(query, route.get("params", {})):
                continue
            expected_body = route["data"] if "data" in route else route.get("json")
            if body != expected_body:
                continue
            if route.get("exception") == "timeout":
                raise requests.Timeout("Declared synthetic offline timeout", request=request)
            if route.get("exception") == "connection":
                raise requests.ConnectionError("Declared synthetic offline connection failure", request=request)
            response = requests.Response()
            response.status_code = route.get("status", 200)
            response._content = json.dumps(route["body"]).encode("utf-8")
            response.headers["Content-Type"] = "application/json"
            response.url = request.url
            response.request = request
            return response
        return self._reject(f"Unmatched offline request: {method} {parsed.path} query={query!r}")

    @staticmethod
    def _query_matches(actual, expected):
        if actual.keys() != expected.keys():
            return False
        for key, value in expected.items():
            values = actual[key]
            if isinstance(value, str) and value.startswith("$"):
                if len(values) != 1:
                    return False
                raw = values[0]
                try:
                    if value == "$timestamp_ms":
                        if not raw.isdigit() or abs(int(raw) - datetime.now().timestamp() * 1000) > 86400000:
                            return False
                    elif value == "$timezone_hours":
                        offset = datetime.now().astimezone().utcoffset()
                        if raw != str(int(offset.total_seconds() / 3600) if offset else 0):
                            return False
                    elif value == "$date_midnight":
                        date = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
                        if date.time() != datetime.min.time() or not 2000 <= date.year <= 2100:
                            return False
                    elif value == "$date_epoch_ms":
                        date = datetime.strptime(actual["dateStr"][0], "%Y-%m-%d %H:%M:%S")
                        if raw != str(int(date.timestamp() * 1000)):
                            return False
                        now = datetime.now()
                        dim = actual["timeDim"][0]
                        if dim == "2":
                            if not (now.date() - timedelta(days=now.weekday()) <= date.date() <= now.date()):
                                return False
                        elif dim == "4":
                            first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                            previous = (first - timedelta(days=1)).replace(day=1)
                            if date not in (first, previous):
                                return False
                        elif dim in ("5", "6"):
                            if date != datetime(now.year, 1, 1):
                                return False
                        else:
                            return False
                    else:
                        return False
                except (ValueError, KeyError, OverflowError, OSError):
                    return False
            elif values != [str(item) for item in (value if isinstance(value, list) else [value])]:
                return False
        return True


class MockFusionSolarAPI(FusionSolarAPI):
    """Synthetic authentication, real discovery and every production data reader.

    Construct a new instance after close, just like the production API. Profile
    mismatches persist across resets so optional readers cannot swallow omissions.
    """

    def __init__(self, profile: dict):
        self.mock_profile = validate_profile(profile)
        self.frame_index = 0
        self._pending_frame = None
        self.unexpected_requests = []
        super().__init__(f"mock-{profile['id']}", "MOCK_RUNTIME_UNUSED", "example.invalid", None)
        self.session.close()
        self.session = OfflineSession(self.mock_profile, self.unexpected_requests)
        self.login_host = "example.invalid"
        self.data_host = "example.invalid"
        self.station = profile["station"]["dn"]
        self.station_name = profile["station"]["name"]
        self._apply_frame()

    @property
    def frame_id(self):
        frames = self.mock_profile.get("frames", [])
        return frames[self.frame_index]["id"] if frames else None

    def queue_frame(self, operation):
        """Schedule only an allowlisted transition, consumed atomically by next poll."""
        with self._session_lock:
            self._ensure_session_open()
            frames = self.mock_profile.get("frames", [])
            if not frames or operation not in ("advance", "reset"):
                raise ValueError("Not a transition profile or invalid operation")
            if self._pending_frame is not None:
                raise ValueError("A frame transition is already pending")
            target = 0 if operation == "reset" else self.frame_index + 1
            if target >= len(frames):
                raise ValueError("Final frame reached; reset explicitly")
            self._pending_frame = target

    def _apply_frame(self):
        resolved = deepcopy(self.mock_profile)
        frames = resolved.get("frames", [])
        if frames:
            frame = frames[self.frame_index]
            for response in frame.get("responses", []):
                route = resolved["routes"][response["route"]]
                route.update({key: value for key, value in response.items() if key != "route"})
            if frame.get("invalidate_battery_config", False):
                self._battery_config_cache = {}
        self.session.profile = resolved

    def login(self):
        with self._session_lock:
            self._ensure_session_open()
            self.data_host = self.login_host = "example.invalid"
            self.dp_session = "MOCK_RUNTIME_SESSION"
            self.session.cookies.set("dp-session", self.dp_session)
            self.session.cookies.set("locale", "en-us")
            self.connected = True
            self.last_session_time = datetime.now(timezone.utc)
            self.refresh_csrf()
            self._update_station_metadata_from_station_list(self.get_station_list())
            self._assert_matched()
            return True, self.station

    def reset_session(self):
        with self._session_lock:
            self._ensure_session_open()
            self.session.close()
            current = self.session.profile
            self.session = OfflineSession(current, self.unexpected_requests)
            self.connected = False
            self.dp_session = ""
            self.csrf = self.csrf_time = None
            self.captcha_input = self.captcha_img = None
            self.data_host = self.login_host = "example.invalid"

    def restore_session(self, dp_session, data_host):
        if dp_session != "MOCK_RUNTIME_SESSION" or data_host != "example.invalid":
            raise ValueError("Runtime mocks cannot restore real sessions")
        return super().restore_session(dp_session, data_host)

    def _assert_matched(self):
        if self.unexpected_requests:
            raise UnexpectedMockRequest("; ".join(self.unexpected_requests))

    def get_devices(self):
        with self._session_lock:
            if self._pending_frame is not None:
                self.frame_index = self._pending_frame
                self._pending_frame = None
                self._apply_frame()
            try:
                return super().get_devices()
            finally:
                self._assert_matched()
