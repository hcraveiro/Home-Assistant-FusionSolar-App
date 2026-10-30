"""Exercise the real authentication mixin with mocked HTTP transport."""

import importlib.util
import json
from pathlib import Path
import sys
import types
from unittest.mock import Mock

import pytest
import requests


ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusion_solar_auth_tests"


@pytest.fixture(scope="module")
def auth_module():
    """Load production modules under a private package without Home Assistant imports."""
    for name, directory in ((PREFIX, ROOT), (f"{PREFIX}.api", ROOT / "api")):
        package = types.ModuleType(name)
        package.__path__ = [str(directory)]
        sys.modules[name] = package

    for name, path in (
        (f"{PREFIX}.const", ROOT / "const.py"),
        (f"{PREFIX}.utils", ROOT / "utils.py"),
        (f"{PREFIX}.api.exceptions", ROOT / "api/exceptions.py"),
        (f"{PREFIX}.api.auth", ROOT / "api/auth.py"),
    ):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)

    yield sys.modules[f"{PREFIX}.api.auth"]
    for name in list(sys.modules):
        if name == PREFIX or name.startswith(PREFIX + "."):
            del sys.modules[name]


def make_api(module, response=None, error=None):
    api = module.FusionSolarAuthMixin()
    api.connected = True
    api.request_timeout = 7
    api.session = Mock()
    if error is not None:
        api.session.request.side_effect = error
    else:
        api.session.request.return_value = response
    return api


def make_response(code=200, content_type="application/json", payload=None, text=None, headers=None):
    response = requests.Response()
    response.status_code = code
    response.headers.update({"Content-Type": content_type, **(headers or {})})
    if text is None:
        text = json.dumps(payload if payload is not None else {"data": []})
    response._content = text.encode("utf-8")
    return response


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (make_response(401), True),
        (make_response(403), True),
        (make_response(302, headers={"Location": "/unisso/login.action"}), True),
        (make_response(200, "text/html", text="<html>Sign in</html>"), True),
        (make_response(200, "text/html", text="<html>Operational overview</html>"), False),
        (make_response(200, payload={"data": []}), False),
    ],
)
def test_auth_page_detection(auth_module, response, expected):
    api = make_api(auth_module)
    assert api._response_looks_like_auth_failure(response) is expected


def test_json_success_preserves_session(auth_module):
    response = make_response(payload={"data": [1]})
    api = make_api(auth_module, response)
    actual_response, data = api._request_json("GET", "https://example.invalid", context="test")
    assert actual_response is response
    assert data == {"data": [1]}
    assert api.connected
    api.session.request.assert_called_once_with("GET", "https://example.invalid", timeout=7)


@pytest.mark.parametrize("code", [401, 403])
def test_auth_expiry_marks_disconnected(auth_module, code):
    api = make_api(auth_module, make_response(code))
    with pytest.raises(auth_module.APIAuthError):
        api._request_json("GET", "https://example.invalid", context="test")
    assert not api.connected


@pytest.mark.parametrize("error", [requests.Timeout("timeout"), requests.ConnectionError("reset")])
def test_transport_failures_are_connection_errors(auth_module, error):
    api = make_api(auth_module, error=error)
    with pytest.raises(auth_module.APIConnectionError):
        api._request_json("GET", "https://example.invalid", context="test")
    assert api.connected


def test_http_server_error_is_connection_error(auth_module):
    api = make_api(auth_module, make_response(500))
    with pytest.raises(auth_module.APIConnectionError):
        api._request_json("GET", "https://example.invalid", context="test")


def test_html_login_page_is_auth_failure(auth_module):
    api = make_api(auth_module, make_response(text="<html>Login expired</html>", content_type="text/html"))
    with pytest.raises(auth_module.APIAuthError):
        api._request_json("GET", "https://example.invalid", context="test")
    assert not api.connected


def test_invalid_non_html_json_is_connection_error(auth_module):
    api = make_api(auth_module, make_response(text="not-json"))
    with pytest.raises(auth_module.APIConnectionError):
        api._request_json("GET", "https://example.invalid", context="test")


def test_reset_session_clears_authentication_state(auth_module, monkeypatch):
    session = Mock()
    replacement = requests.Session()
    monkeypatch.setattr(auth_module.requests, "Session", lambda: replacement)
    api = auth_module.FusionSolarAuthMixin()
    api.session = session
    api.connected = True
    api.dp_session = "dummy"
    api.csrf = "dummy"
    api.csrf_time = 123
    api.captcha_input = "dummy"
    api.captcha_img = "dummy"

    api.reset_session()

    session.close.assert_called_once_with()
    assert api.session is replacement
    assert replacement.cookies.get("locale") == "en-us"
    assert not api.connected
    assert api.dp_session == ""
    assert api.csrf is None
    assert api.csrf_time is None
    assert api.captcha_input is None
    assert api.captcha_img is None


@pytest.mark.parametrize(("response_text", "expected"), [
    ("true", True),
    ("false", False),
    ('{"success":true}', True),
    ('{"success":false}', False),
    ('{"valid":true}', True),
    ('{"valid":false}', False),
    ('{"result":"success"}', True),
    ('{"result":"invalid"}', False),
    ("invalid", False),
    ("unexpected-response", False),
    ('{"errorCode":411}', False),
])
def test_eu5_captcha_prevalidation_accepts_only_explicit_success(
    auth_module, response_text, expected
):
    api = make_api(auth_module)
    api.login_host = "eu5.fusionsolar.huawei.com"
    api.session.post.return_value = make_response(text=response_text)
    assert api._prevalidate_captcha("1234") is expected
    assert api.session.post.call_args.kwargs["data"]["verifycode"] == "1234"


def test_eu5_captcha_prevalidation_rejects_http_errors(auth_module):
    api = make_api(auth_module)
    api.login_host = "eu5.fusionsolar.huawei.com"
    api.session.post.return_value = make_response(403, text="true")
    assert api._prevalidate_captcha("1234") is False


def test_eu5_captcha_response_does_not_log_secret_body(auth_module, caplog):
    api = make_api(auth_module)
    api.login_host = "eu5.fusionsolar.huawei.com"
    secret = "secret-session-token-test"
    api.session.post.return_value = make_response(text='{"valid":false,"secret":"'+secret+'"}')
    with caplog.at_level("DEBUG"):
        assert api._prevalidate_captcha("1234") is False
    assert secret not in caplog.text


def test_failed_api_response_does_not_log_sensitive_headers(auth_module, caplog):
    api = make_api(auth_module, make_response(
        code=500,
        text="secret-response-token-test",
        headers={"Set-Cookie": "dp-session=secret-cookie-test"},
    ))
    with caplog.at_level("DEBUG"):
        with pytest.raises(Exception):
            api._request_json("GET", "https://example.invalid", context="test")
    for secret in ("secret-response-token-test", "secret-cookie-test"):
        assert secret not in caplog.text


@pytest.mark.parametrize("response", [
    make_response(500, text="secret-body-marker", headers={"Set-Cookie": "dp-session=secret-cookie-marker"}),
    make_response(200, "text/html", text="<html>secret-body-marker</html>"),
    make_response(200, text="secret-body-marker"),
])
def test_http_failures_never_log_secrets(auth_module, caplog, response):
    api = make_api(auth_module, response)
    with caplog.at_level("DEBUG"):
        with pytest.raises((auth_module.APIConnectionError, auth_module.APIAuthError)):
            api._request_json("GET", "https://example.invalid", context="test")
    assert "secret-body-marker" not in caplog.text
    assert "secret-cookie-marker" not in caplog.text


def test_csrf_refresh_does_not_log_token(auth_module, caplog):
    api = make_api(auth_module)
    api.data_host = "example.invalid"
    api.csrf = None
    api.csrf_time = None
    api._request_json = Mock(return_value=(None, {"payload": "secret-csrf-marker"}))
    with caplog.at_level("DEBUG"):
        api.refresh_csrf()
    assert api.csrf == "secret-csrf-marker"
    assert "secret-csrf-marker" not in caplog.text
