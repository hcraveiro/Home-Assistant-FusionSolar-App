"""Issue #101 reported fields plus explicitly synthetic runtime completion."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from test_runtime_mock_api import runtime
from test_api_lifecycle_behavior import api_module

PROFILE = Path(__file__).parent / "fixtures/runtime_profiles/isitepower-mains-import.json"


def graph():
    profile = json.loads(PROFILE.read_text())
    return next(route["body"]["data"]["flow"] for route in profile["routes"]
                if route["path"].endswith("/v2/overview/energy-flow"))


@pytest.mark.parametrize("change", [
    "reported", "reverse", "idle", "hidden", "conflict", "duplicate_link",
    "duplicate_mains", "duplicate_cube", "missing_link", "missing_mains",
    "disconnected_cube", "disconnected_mains", "nan", "infinite", "wrong_unit",
    "wrong_endpoint", "duplicate_id", "missing_id", "unrelated_link",
])
def test_reported_graph_and_synthetic_rejection_cases(runtime, change):
    loader, backend = runtime
    api = backend.MockFusionSolarAPI(loader.load_profile("isitepower-mains-import"))
    flow = deepcopy(graph())
    mains, cube = flow["nodes"][-2:]
    link = flow["links"][0]
    if change == "reverse": link["flowing"] = "REVERSE"
    elif change == "idle": mains["description"]["value"] = "0kW"
    elif change == "hidden": link["visible"] = False
    elif change == "conflict": link["direction"] = "REVERSE"
    elif change == "duplicate_link": flow["links"].append(dict(link))
    elif change == "duplicate_mains": flow["nodes"].append(dict(mains))
    elif change == "duplicate_cube": flow["nodes"].append(dict(cube))
    elif change == "missing_link": flow["links"] = []
    elif change == "missing_mains": flow["nodes"].remove(mains)
    elif change == "disconnected_cube": cube["display"] = "DISCONNECTED"
    elif change == "disconnected_mains": mains["display"] = "DISCONNECTED"
    elif change == "nan": mains["description"]["value"] = "NaNkW"
    elif change == "infinite": mains["description"]["value"] = "9" * 400 + "kW"
    elif change == "wrong_unit": mains["description"]["value"] = "640W"
    elif change == "wrong_endpoint": link["toNode"] = "other"
    elif change == "duplicate_id": flow["nodes"].append({"id": mains["id"], "name": "other"})
    elif change == "missing_id": mains.pop("id")
    elif change == "unrelated_link": flow["links"].append({"fromNode": "other", "toNode": "elsewhere"})
    api._is_isitepower_m = True
    output = api._build_base_output()
    before = {key: value for key, value in output.items() if not key.endswith("_power")}
    api._parse_isitepower_grid_import(flow["nodes"], flow["links"], output)
    assert output["grid_consumption_power"] == (0.64 if change in ("reported", "unrelated_link") else None)
    assert output["grid_injection_power"] is None
    assert {key: value for key, value in output.items() if not key.endswith("_power")} == before
    api.close()


def test_complete_runtime_profile_repeated_poll_and_reopen(runtime):
    loader, backend = runtime
    for _ in range(2):
        api = backend.MockFusionSolarAPI(loader.load_profile("isitepower-mains-import"))
        api.login()
        for _ in range(2):
            devices = api.get_devices()
            by_id = {device.device_id: device for device in devices}
            assert by_id["Grid Consumption Power"].state == 0.64
            assert by_id["Grid Injection Power"].state is None
            assert not api.unexpected_requests
        api.close()
