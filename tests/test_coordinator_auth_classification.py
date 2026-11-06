"""Focused auth classification regressions; actual HA coverage is standalone.

Reuse the existing isolated coordinator fixture here. The companion disposable-HA
checker exercises HTTP 401 -> production reader -> actual DUC -> reauth flow.
"""
import pytest

from test_coordinator_full_behavior import coordinator, coordinator_module  # noqa: F401


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_at", ["login", "required_fetch"])
async def test_second_auth_rejection_requires_reauth(coordinator, coordinator_module, failure_at):
    module = coordinator_module
    coordinator.api.get_devices.side_effect = module.APIAuthError("MOCK_RUNTIME expired")
    if failure_at == "login":
        coordinator.api.login.side_effect = module.APIAuthError("MOCK_RUNTIME rejected")
    with pytest.raises(module.ConfigEntryAuthFailed, match="Authentication failed after session renewal"):
        await coordinator.async_update_data()
    coordinator.api.reset_session.assert_called_once()
    coordinator.api.login.assert_called_once()
    assert coordinator.api.get_devices.call_count == (1 if failure_at == "login" else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize("error", ["APIConnectionError", "APIDataStructureError", "RuntimeError"])
async def test_retry_non_auth_failure_remains_retryable(coordinator, coordinator_module, error):
    module = coordinator_module
    coordinator.api.get_devices.side_effect = module.APIAuthError("MOCK_RUNTIME expired")
    exception = RuntimeError if error == "RuntimeError" else getattr(module, error)
    coordinator.api.login.side_effect = exception("MOCK_RUNTIME temporary")
    with pytest.raises(module.UpdateFailed, match="Re-login failed"):
        await coordinator.async_update_data()
    coordinator.api.reset_session.assert_called_once()
    coordinator.api.login.assert_called_once()
    assert coordinator.api.get_devices.call_count == 1


@pytest.mark.asyncio
async def test_retry_captcha_sequence_is_unchanged(coordinator, coordinator_module):
    module = coordinator_module
    coordinator.api.get_devices.side_effect = module.APIAuthError("MOCK_RUNTIME expired")
    coordinator.api.login.side_effect = module.APIAuthCaptchaError("MOCK_RUNTIME captcha")
    with pytest.raises(module.ConfigEntryAuthFailed, match="Login requires CAPTCHA"):
        await coordinator.async_update_data()
    coordinator.api.reset_session.assert_called_once()
    coordinator.api.login.assert_called_once()
