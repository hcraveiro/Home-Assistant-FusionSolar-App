"""Real JP5/LA5/EU5 login readers during production coordinator renewal.

Only requests.Session.request is replaced by fictional offline replies. The
initial stale fetch uses the real required JSON reader, reset is production, and
the regional login methods are executed, not replaced by typed exceptions.
"""
from unittest.mock import Mock

import pytest
import requests

from api_profiles.login_protocol_cases import LOGIN_PROTOCOL_CASES, LoginProtocolReplies, REQUIRED_PATH
from test_api_lifecycle_behavior import api_module  # noqa: F401
from test_coordinator_full_behavior import coordinator, coordinator_module  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize("region,scenario", LOGIN_PROTOCOL_CASES)
async def test_regional_renewal_protocol_failure_retries_later(
    coordinator, coordinator_module, api_module, monkeypatch, region, scenario,
):
    module = coordinator_module
    for name in ("APIAuthError", "APIAuthRejectedError", "APIAuthCaptchaError", "APIConnectionError", "APIDataStructureError"):
        monkeypatch.setattr(module, name, getattr(api_module, name))
    api = api_module.FusionSolarAPI("MOCK_RUNTIME_ACCOUNT", "MOCK_RUNTIME_UNUSED", "example.invalid", None)
    replies = LoginProtocolReplies(region, scenario)
    def request(session, method, url, **kwargs):
        return replies.response(method, url)
    monkeypatch.setattr(requests.sessions.Session, "request", request)
    coordinator.api = api
    api.connected = True
    # The real constructor normalizes arbitrary input as a Huawei host. Keep
    # every synthetic request on the same fictional origin as runtime mocks.
    api.login_host = api.data_host = "example.invalid"
    api.station = "MOCK_RUNTIME_STATION"
    api.battery_dn = "MOCK_RUNTIME_BATTERY"
    api.get_devices = Mock(side_effect=lambda: api._request_json(
        "GET", "https://example.invalid" + REQUIRED_PATH, context="MOCK_RUNTIME required fetch",
    ))
    api.login = Mock(wraps=getattr(api, "_login_" + region))
    api.reset_session = Mock(wraps=api.reset_session)
    try:
        with pytest.raises(module.UpdateFailed, match="Re-login failed") as failure:
            await coordinator.async_update_data()
        assert not isinstance(failure.value, module.ConfigEntryAuthFailed)
        replies.assert_bounded()
        api.login.assert_called_once_with()
        api.reset_session.assert_called_once_with()
        api.get_devices.assert_called_once_with()
    finally:
        api.close()


@pytest.mark.parametrize("status,optional,rejected", [(401, False, True), (403, False, True), (401, True, False), (403, True, False), (503, False, False), (429, False, False)])
def test_only_explicit_required_auth_status_marks_rejection(api_module, monkeypatch, status, optional, rejected):
    api = api_module.FusionSolarAPI("MOCK_RUNTIME_ACCOUNT", "unused", "example.invalid", None)
    response = requests.Response()
    response.status_code = status
    response._content = b'<html>MOCK_RUNTIME login temporarily unavailable</html>'
    response.headers["Content-Type"] = "text/html"
    monkeypatch.setattr(api.session, "request", Mock(return_value=response))
    try:
        with pytest.raises((api_module.APIAuthError, api_module.APIConnectionError)) as failure:
            api._request_json("GET", "https://example.invalid", context="MOCK_RUNTIME", optional=optional)
        assert isinstance(failure.value, api_module.APIAuthRejectedError) is rejected
    finally:
        api.close()
