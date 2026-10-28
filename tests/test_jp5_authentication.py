"""Isolated JP5 authentication flow regression tests."""

import ast
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urljoin, urlparse

import pytest
import requests


SOURCE = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app/api/auth.py"


class APIAuthError(Exception):
    pass


class APIConnectionError(Exception):
    pass


def load_method():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    method = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_login_jp5"
    )
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    scope = {
        "APIAuthError": APIAuthError,
        "APIConnectionError": APIConnectionError,
        "LOGIN_VALIDATE_USER_URL_LA5": "/rest/dp/uidm/unisso/v1/validate-user",
        "datetime": datetime,
        "timezone": timezone,
        "urljoin": urljoin,
        "urlparse": urlparse,
        "requests": requests,
        "_LOGGER": Mock(),
    }
    exec(compile(module, str(SOURCE), "exec"), scope)
    return scope["_login_jp5"]


def response(status, payload=None, location=None):
    return SimpleNamespace(
        status_code=status,
        json=lambda: payload,
        headers={"Location": location} if location else {},
    )


def fake_client(login_result, redirects=(), cookie="session"):
    session = Mock()
    session.post.return_value = login_result
    session.get.side_effect = redirects
    session.cookies.get.return_value = cookie
    client = SimpleNamespace(
        login_host="jp5.fusionsolar.huawei.com",
        user="example",
        pwd="placeholder",
        captcha_input=None,
        session=session,
        connected=False,
        refresh_csrf=Mock(),
        get_station_list=Mock(return_value={"data": {"list": []}}),
        _update_station_metadata_from_station_list=Mock(),
        _start_session_monitor=Mock(),
        station="station",
    )
    return client


def test_jp5_login_success_with_two_redirects():
    client = fake_client(
        response(200, {"code": 0, "payload": {"redirectURL": "/rest/dp/uidm/auth/v1/on-sso-credential-ready?ticket=secret"}}),
        [response(302, location="/rest/pvms/web/login/v1/redirecturl?isFirst=false"),
         response(302, location="/uniportal/pvmswebsite/assets/build/cloud.html"),
         response(200)],
    )
    assert load_method()(client) == (True, "station")
    assert client.connected
    assert client.session.get.call_count == 3
    kwargs = client.session.post.call_args.kwargs
    assert kwargs["json"] == {"username": "example", "password": "placeholder", "verifycode": ""}
    assert kwargs["headers"]["App-Id"] == "smartpvms"
    assert kwargs["params"]["service"] == "/rest/dp/uidm/auth/v1/on-sso-credential-ready"
    assert kwargs["allow_redirects"] is False


@pytest.mark.parametrize("login_result", [
    response(403),
    response(200, {"code": 1, "payload": {}}),
    response(200, {"code": 0, "payload": {}}),
])
def test_jp5_invalid_authentication(login_result):
    client = fake_client(login_result)
    with pytest.raises(APIAuthError):
        load_method()(client)
    assert not client.connected


def test_jp5_rejects_external_ticket_redirect():
    client = fake_client(response(200, {"code": 0, "payload": {"redirectURL": "https://attacker.example/ticket"}}))
    with pytest.raises(APIAuthError, match="unexpected origin"):
        load_method()(client)
    client.session.get.assert_not_called()


def test_jp5_requires_session_cookie():
    client = fake_client(
        response(200, {"code": 0, "payload": {"redirectURL": "/sso"}}),
        [response(302, location="/redirect"), response(302, location="/landing"), response(200)],
        cookie=None,
    )
    with pytest.raises(APIAuthError, match="cookie"):
        load_method()(client)
    assert not client.connected


def test_jp5_transport_failure_is_not_auth_failure():
    client = fake_client(response(200))
    client.session.post.side_effect = requests.Timeout("timeout")
    with pytest.raises(APIConnectionError):
        load_method()(client)


def test_jp5_dispatch_is_exact_host_match():
    source = SOURCE.read_text(encoding="utf-8")
    assert 'self.login_host == "jp5.fusionsolar.huawei.com"' in source
    assert 'return self._login_jp5()' in source

def test_jp5_rejects_external_location_on_second_redirect():
    client = fake_client(
        response(200, {"code": 0, "payload": {"redirectURL": "/sso"}}),
        [response(302, location="https://outside.example/ticket")],
    )
    with pytest.raises(APIAuthError, match="unexpected origin"):
        load_method()(client)
    assert client.session.get.call_count == 1


def test_jp5_stops_at_redirect_limit():
    client = fake_client(
        response(200, {"code": 0, "payload": {"redirectURL": "/sso"}}),
        [response(302, location="/sso") for _ in range(5)],
    )
    with pytest.raises(APIAuthError, match="limit exceeded"):
        load_method()(client)
    assert client.session.get.call_count == 5
