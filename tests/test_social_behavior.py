"""Exercise production social-contribution request and mapping with mocked HTTP."""

import importlib.util
import json
from pathlib import Path
import sys
import types
from unittest.mock import Mock

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusion_solar_social_test"


@pytest.fixture(scope="module")
def modules():
    for name, directory in ((PREFIX, ROOT), (f"{PREFIX}.api", ROOT / "api")):
        package = types.ModuleType(name)
        package.__path__ = [str(directory)]
        sys.modules[name] = package
    for name, path in (
        ("const", ROOT / "const.py"),
        ("utils", ROOT / "utils.py"),
        ("api.exceptions", ROOT / "api/exceptions.py"),
        ("api.social", ROOT / "api/social.py"),
    ):
        fullname = f"{PREFIX}.{name}"
        spec = importlib.util.spec_from_file_location(fullname, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[fullname] = module
        spec.loader.exec_module(module)
    yield sys.modules[f"{PREFIX}.api.social"], sys.modules[f"{PREFIX}.api.exceptions"]
    for name in list(sys.modules):
        if name == PREFIX or name.startswith(PREFIX + "."):
            del sys.modules[name]


def make_api(modules, *, status=200, payload=None, raw=None):
    api = modules[0].FusionSolarSocialMixin()
    api.refresh_csrf = Mock()
    api.station = "example%20station"
    api.data_host = "eu5.fusionsolar.huawei.com"
    api.csrf = "dummy"
    api.session = Mock()
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = "application/json"
    response._content = (raw if raw is not None else json.dumps(payload if payload is not None else {"data": {}})).encode()
    api.session.get.return_value = response
    return api


def test_request_success_and_parameters(modules):
    api = make_api(modules, payload={"data": {"co2Reduction": "12 kg"}})
    assert api.call_social_contribution()["data"]["co2Reduction"] == "12 kg"
    api.refresh_csrf.assert_called_once()
    request_url = api.session.get.call_args.args[0]
    assert "dn=example+station" in request_url
    assert api.session.get.call_args.kwargs["headers"]["Roarand"] == "dummy"


def test_non_200_returns_connection_error(modules):
    api = make_api(modules, status=503)
    with pytest.raises(modules[1].APIConnectionError):
        api.call_social_contribution()


def test_bad_json_returns_auth_error(modules):
    api = make_api(modules, raw="<html>expired</html>")
    with pytest.raises(modules[1].APIAuthError):
        api.call_social_contribution()


@pytest.mark.parametrize("decoder_error", [json.JSONDecodeError, requests.exceptions.JSONDecodeError])
def test_json_decoder_errors_return_auth_error_without_logging_body(modules, caplog, decoder_error):
    api = make_api(modules, raw="private-response-marker")
    response = api.session.get.return_value
    error = decoder_error("private-decoder-marker", response.text, 0)
    response.json = Mock(side_effect=error)
    response.headers["Set-Cookie"] = "dp-session=private-cookie-marker"

    with caplog.at_level("DEBUG"):
        with pytest.raises(modules[1].APIAuthError) as caught:
            api.call_social_contribution()

    assert caught.value.__cause__ is error
    for marker in ("private-response-marker", "private-decoder-marker", "private-cookie-marker"):
        assert marker not in caplog.text


@pytest.mark.parametrize("error_type", [ValueError, TypeError, RuntimeError])
def test_json_programming_errors_are_not_misclassified(modules, error_type):
    api = make_api(modules)
    api.session.get.return_value.json = Mock(side_effect=error_type("programming error"))
    with pytest.raises(error_type, match="programming error"):
        api.call_social_contribution()


@pytest.mark.parametrize("status,payload,raw,expected_error", [
    (503, None, "private-response-marker", "APIConnectionError"),
    (200, {"session": "private-response-marker"}, None, "APIDataStructureError"),
])
def test_social_failures_never_log_response_or_session(modules, caplog, status, payload, raw, expected_error):
    api = make_api(modules, status=status, payload=payload, raw=raw)
    api.csrf = "private-csrf-marker"
    api.station = "private-station-marker"
    api.session.get.return_value.headers["Set-Cookie"] = "dp-session=private-cookie-marker"

    with caplog.at_level("DEBUG"):
        with pytest.raises(getattr(modules[1], expected_error)):
            api.call_social_contribution()

    assert caplog.records
    for marker in ("private-response-marker", "private-csrf-marker", "private-cookie-marker", "private-station-marker"):
        assert marker not in caplog.text


def test_missing_data_returns_structure_error(modules):
    api = make_api(modules, payload={"success": True})
    with pytest.raises(modules[1].APIDataStructureError):
        api.call_social_contribution()


def test_social_metric_mapping_and_rounding(modules):
    api = make_api(modules, payload={"data": {
        "standardCoalSavings": "3 kg",
        "standardCoalSavingsByYear": "2.5 kg",
        "co2Reduction": "14 kg",
        "co2ReductionByYear": "7.1 kg",
        "equivalentTreePlanting": "4.6",
        "equivalentTreePlantingByYear": "1.2",
    }})
    output = {}
    api.update_output_with_social_contribution(output)
    assert output == {
        "standard_coal_saved": 3.0,
        "standard_coal_saved_this_year": 2.5,
        "co2_avoided": 14.0,
        "co2_avoided_this_year": 7.1,
        "equivalent_trees_planted": 5,
        "equivalent_trees_planted_this_year": 1,
    }


def test_social_missing_metrics_are_unavailable(modules):
    api = make_api(modules)
    output = {}
    api.update_output_with_social_contribution(output)
    assert len(output) == 6
    assert all(value is None for value in output.values())
