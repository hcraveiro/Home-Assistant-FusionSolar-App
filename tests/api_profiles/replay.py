"""Strict, ordered HTTP replay using genuine requests.Response objects.

Profiles contain explicit frames; callers must consume a frame before advancing.
Only the explicitly listed read-only optimizer POST endpoints are permitted.
Unexpected calls are retained because optional production readers catch Exception
(including AssertionError). Always call assert_consumed after exercising a frame.
"""

from copy import deepcopy
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import requests

PROFILE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "api_profiles"
READ_ONLY_POSTS = frozenset({
    "/rest/pvms/web/station/v1/layout/device-sampling-data",
    "/rest/pvms/web/station/v1/layout/device-tree-page",
})


def load_profile(name):
    """Load an explicitly synthetic/mixed profile, resolving local body files."""
    path = PROFILE_ROOT / name
    profile = json.loads(path.read_text(encoding="utf-8"))
    assert profile["origin"] in {"synthetic", "mixed"}
    assert profile["source_url"].startswith("https://")
    for frame in profile["frames"]:
        for route in frame["routes"]:
            if "body_file" in route:
                body_path = (PROFILE_ROOT / route["body_file"]).resolve()
                assert body_path.is_relative_to(PROFILE_ROOT.resolve())
                route["body"] = json.loads(body_path.read_text(encoding="utf-8"))
    return profile


def _params(value):
    # Match what requests puts on the wire: integer query values become strings.
    pairs = value.items() if isinstance(value, dict) else value or []
    return sorted((str(key), str(item)) for key, val in pairs
                  for item in (val if isinstance(val, (tuple, list)) else [val]))


class ProfileReplay:
    """Callable installed on one API's session.request; no network fallback."""

    def __init__(self, profile):
        self.profile = deepcopy(profile)
        self.frame_index = 0
        self.position = 0
        self.calls = []
        self.unexpected = []

    @property
    def frame(self):
        return self.profile["frames"][self.frame_index]

    def attach(self, api, monkeypatch):
        monkeypatch.setattr(api.session, "request", self)
        # Also block new/replaced sessions and direct requests from escaping.
        def forbidden_send(session, request, **kwargs):
            self._reject({"method": request.method, "url": request.url},
                         "network adapter fallback forbidden")
        monkeypatch.setattr(requests.sessions.Session, "send", forbidden_send)
        return self

    def _reject(self, call, reason):
        self.unexpected.append({**call, "reason": reason})
        raise AssertionError(f"Unexpected replay request: {reason}: {call}")

    def __call__(self, method, url, **kwargs):
        parsed = urlsplit(url)
        call = {"method": method.upper(), "url": url, "path": parsed.path,
                "params": _params(parse_qsl(parsed.query, keep_blank_values=True))
                + _params(kwargs.get("params")), "json": kwargs.get("json")}
        call["params"].sort()
        self.calls.append(call)
        if (parsed.scheme != "https" or parsed.netloc != "example.invalid"
                or parsed.fragment or parsed.username):
            self._reject(call, "only https://example.invalid is allowed")
        if call["method"] != "GET" and not (
            call["method"] == "POST" and parsed.path in READ_ONLY_POSTS
        ):
            self._reject(call, "writes/authentication are forbidden")
        if kwargs.get("data") is not None or kwargs.get("files") is not None:
            self._reject(call, "unrecorded request body")
        routes = self.frame["routes"]
        if self.position >= len(routes):
            self._reject(call, "frame already consumed")
        route = routes[self.position]
        ignored = set(route.get("ignore_params", []))
        # Only the portal cache-busting timestamp may be ignored, explicitly.
        assert ignored <= {"_"}
        actual_params = [(k, v) for k, v in call["params"] if k not in ignored]
        expected = (route["method"], route["path"], _params(route["params"]), route["json"])
        actual = (call["method"], call["path"], actual_params, call["json"])
        if actual != expected:
            self._reject(call, f"expected route {self.position}: {expected}")
        self.position += 1
        response = requests.Response()
        response.status_code = route["status"]
        response.url = url
        response.headers["Content-Type"] = "application/json"
        response.encoding = "utf-8"
        response._content = json.dumps(route["body"]).encode("utf-8")
        response.request = requests.Request(method, url).prepare()
        return response

    def assert_no_unexpected(self):
        assert not self.unexpected, f"Unexpected requests (possibly swallowed): {self.unexpected}"

    def assert_consumed(self):
        self.assert_no_unexpected()
        assert self.position == len(self.frame["routes"]), (
            f"Unconsumed routes in {self.frame['name']}: "
            f"{self.frame['routes'][self.position:]}"
        )

    def advance(self):
        self.assert_consumed()
        assert self.frame_index + 1 < len(self.profile["frames"])
        self.frame_index += 1
        self.position = 0
