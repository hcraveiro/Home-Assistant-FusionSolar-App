"""Network-incapable HTTP replies for real regional renewal-method regressions.

Shared by isolated pytest and the standalone actual-HA authentication checker.
No login method, parser, reset, or coordinator classification is supplied here.
"""
import json
from urllib.parse import urlsplit

import requests


LOGIN_PROTOCOL_CASES = (
    ("jp5", "login-503"), ("jp5", "login-429"), ("jp5", "login-non-json"),
    ("jp5", "redirect-503"), ("jp5", "redirect-429"), ("jp5", "login-timeout"),
    ("la5", "login-503"), ("la5", "login-429"), ("la5", "missing-redirect"),
    ("eu5", "pubkey-503"), ("eu5", "pubkey-429"), ("eu5", "pubkey-non-json"),
)
REQUIRED_PATH = "/rest/pvms/web/station/v2/overview/energy-flow"


class LoginProtocolReplies:
    """Start with a required-reader 401, then fail one real regional login."""

    def __init__(self, region, scenario):
        self.region, self.scenario = region, scenario
        self.calls = []
        self.required_calls = 0

    def response(self, method, url):
        parsed = urlsplit(url)
        assert parsed.scheme == "https" and parsed.netloc == "example.invalid"
        path = parsed.path
        self.calls.append((method.upper(), path))
        status, body = 200, b""
        if method.upper() == "GET" and path == REQUIRED_PATH:
            self.required_calls += 1
            status, body = 401, b'{"success": false}'
        elif path.endswith("/validate-user") and method.upper() == "POST":
            assert self.region in ("jp5", "la5")
            if self.scenario == "login-timeout":
                raise requests.Timeout("MOCK_RUNTIME synthetic login timeout")
            if self.scenario.startswith("redirect-"):
                body = json.dumps({"code": 0, "payload": {"redirectURL": "/MOCK_RUNTIME_sso"}}).encode()
            elif self.scenario in ("login-503", "login-429"):
                status = int(self.scenario.rsplit("-", 1)[1])
            elif self.scenario == "login-non-json":
                body = b"MOCK_RUNTIME temporary non-JSON response"
            else:
                assert self.scenario == "missing-redirect" and self.region == "la5"
        elif path == "/MOCK_RUNTIME_sso" and method.upper() == "GET":
            assert self.region == "jp5" and self.scenario.startswith("redirect-")
            status = int(self.scenario.rsplit("-", 1)[1])
        elif path == "/unisso/pubkey" and method.upper() == "GET":
            assert self.region == "eu5"
            if self.scenario != "pubkey-non-json":
                status = int(self.scenario.rsplit("-", 1)[1])
            body = b"MOCK_RUNTIME temporary non-JSON public key reply"
        elif method.upper() == "GET" and (
            (self.region == "la5" and path == "/")
            or (self.region == "eu5" and len(self.calls) == 2)
        ):
            # Normal regional pre-warm; never bypass the pubkey request.
            pass
        else:
            raise AssertionError(f"Unexpected offline login request: {method} {path}")
        reply = requests.Response()
        reply.status_code = status
        reply._content = body
        reply.url = url
        reply.headers["Content-Type"] = "application/json"
        return reply

    def assert_bounded(self):
        assert self.required_calls == 1, self.calls
        assert len(self.calls) == (2 if self.region == "jp5" and not self.scenario.startswith("redirect-") else 3), self.calls
