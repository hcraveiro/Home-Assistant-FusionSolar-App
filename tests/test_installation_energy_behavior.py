"""Behavioral tests for installation and energy ratios using real production methods."""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusion_solar_installation_test"


@pytest.fixture(scope="module")
def modules():
    for name, directory in ((PREFIX, ROOT), (f"{PREFIX}.api", ROOT / "api")):
        module = types.ModuleType(name)
        module.__path__ = [str(directory)]
        sys.modules[name] = module
    for name, path in (
        ("const", ROOT / "const.py"),
        ("utils", ROOT / "utils.py"),
        ("api.exceptions", ROOT / "api/exceptions.py"),
        ("api.models", ROOT / "api/models.py"),
        ("api.signal_maps", ROOT / "api/signal_maps.py"),
        ("api.installation", ROOT / "api/installation.py"),
        ("api.energy_balance", ROOT / "api/energy_balance.py"),
    ):
        fullname = f"{PREFIX}.{name}"
        spec = importlib.util.spec_from_file_location(fullname, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[fullname] = module
        spec.loader.exec_module(module)
    yield (
        sys.modules[f"{PREFIX}.api.installation"],
        sys.modules[f"{PREFIX}.api.energy_balance"],
        sys.modules[f"{PREFIX}.api.exceptions"],
    )
    for name in list(sys.modules):
        if name == PREFIX or name.startswith(PREFIX + "."):
            del sys.modules[name]


def make_installation(modules):
    instance = modules[0].FusionSolarInstallationMixin()
    instance.station = "station-id"
    instance.data_host = "eu5.fusionsolar.huawei.com"
    instance.refresh_csrf = Mock()
    instance._request_json = Mock()
    instance.session = Mock()
    instance.session.cookies.get_dict.return_value = {}
    instance.battery_dn = None
    return instance


def test_base_output_has_all_periods(modules):
    output = make_installation(modules)._build_base_output()
    assert output["exit_code"] == "SUCCESS"
    for period in ("today", "week", "month", "year", "lifetime"):
        for prefix in ("panel_production", "grid_consumption", "grid_injection",
                       "battery_injection", "battery_consumption", "house_load"):
            assert output[f"{prefix}_{period}"] == 0.0


@pytest.mark.parametrize("nodes,links", [
    ([{"name": "solar"}], []),
    ([], [{"description": {"label": "grid", "value": "10 W"}}]),
])
def test_flow_fetch_parses_nodes_links(modules, nodes, links):
    api = make_installation(modules)
    api._request_json.return_value = (None, {"data": {"flow": {"nodes": nodes, "links": links}}})
    assert api._get_installation_flow_data() == (nodes, links)
    api.refresh_csrf.assert_called_once()
    assert api._request_json.call_args.kwargs["params"]["stationDn"] == "station-id"


def test_flow_fetch_requires_station(modules):
    api = make_installation(modules)
    api.station = None
    with pytest.raises(modules[2].APIDataStructureError):
        api._get_installation_flow_data()


@pytest.mark.parametrize("payload", [
    {}, {"data": {}}, {"data": {"flow": {"nodes": "invalid", "links": []}}},
    {"data": {"flow": {"nodes": [], "links": "invalid"}}},
])
def test_invalid_flow_shapes_are_rejected(modules, payload):
    api = make_installation(modules)
    api._request_json.return_value = (None, payload)
    with pytest.raises(modules[2].APIDataStructureError):
        api._get_installation_flow_data()


def test_battery_discovery_uses_first_id_and_preserves_existing(modules):
    api = make_installation(modules)
    nodes = [{"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": ["battery-1"]}]
    api._discover_battery_dn_from_flow_nodes(nodes)
    assert api.battery_dn == "battery-1"
    api._discover_battery_dn_from_flow_nodes([{"name": nodes[0]["name"], "devDn": "battery-2"}])
    assert api.battery_dn == "battery-1"


def test_battery_discovery_fallback_dn(modules):
    api = make_installation(modules)
    api._discover_battery_dn_from_flow_nodes([
        {"name": "unknown", "devDn": "ignore"},
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": [], "devDn": "battery-3"},
    ])
    assert api.battery_dn == "battery-3"


@pytest.mark.parametrize("power,expected_charge,expected_discharge", [
    ("4.5 kW", 3.0, 0.0),
    ("-2 kW", 0.0, 3.0),
    ("0", 0.0, 3.0),
])
def test_installation_node_power_sign(modules, power, expected_charge, expected_discharge):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([{
        "name": "neteco.pvms.devTypeLangKey.energy_store",
        "description": {"value": "3 kW"},
        "deviceTips": {"SOC": "52 %", "BATTERY_POWER": power},
    }], output)
    assert output["battery_percentage"] == 52
    assert output["battery_injection_power"] == expected_charge
    assert output["battery_consumption_power"] == expected_discharge


@pytest.mark.parametrize("load,expected_injection,expected_consumption", [
    (2.0, 3.0, 0.0),
    (8.0, 0.0, 3.0),
])
def test_grid_flow_direction(modules, load, expected_injection, expected_consumption):
    api = make_installation(modules)
    output = api._build_base_output()
    output.update(panel_production_power=5.0, house_load_power=load)
    api._parse_installation_flow_links([{
        "description": {"label": "neteco.pvms.energy.flow.buy.power", "value": "3 kW"}
    }], output)
    assert output["grid_injection_power"] == expected_injection
    assert output["grid_consumption_power"] == expected_consumption


@pytest.mark.parametrize("numerator,denominator,expected", [
    (5, 10, 50.0), (1, 3, 33.33), (0, 10, 0.0),
    (5, 0, 0.0), (5, -2, 0.0),
])
def test_ratio_calculation(modules, numerator, denominator, expected):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    assert api._calculate_ratio_percentage(numerator, denominator) == expected


def test_all_consumption_ratio_periods(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    output = {}
    for period in ("today", "week", "month", "year", "lifetime"):
        output.update({
            f"panel_production_consumption_{period}": 4,
            f"house_load_{period}": 8,
            f"panel_production_{period}": 10,
        })
    api._update_output_with_self_consumption_ratios(output)
    for period in ("today", "week", "month", "year", "lifetime"):
        assert output[f"self_consumption_ratio_{period}"] == 50
        assert output[f"self_consumption_ratio_by_production_{period}"] == 40


def test_battery_capacity_cached(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api.battery_capacity = 15
    api.refresh_csrf = Mock()
    output = {}
    api.update_output_with_battery_capacity(output)
    assert output["battery_capacity"] == 15
    api.refresh_csrf.assert_not_called()


def test_battery_capacity_fetched_when_unknown(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api.battery_capacity = None
    api.refresh_csrf = Mock()
    api.get_station_list = Mock(return_value={"data": {"list": [{"batteryCapacity": 15}]}})
    output = {}
    api.update_output_with_battery_capacity(output)
    assert output["battery_capacity"] == 15
    assert api.battery_capacity == 15
    api.refresh_csrf.assert_called_once()
