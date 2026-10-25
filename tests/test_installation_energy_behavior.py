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
    output.update(panel_production_power=5.0, house_load_power=load,
                  battery_consumption_power=0.0, battery_injection_power=0.0)
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


def test_device_assembly_keeps_partial_data(modules):
    api = make_installation(modules)
    api.get_inverter_metadata_devices = Mock(side_effect=RuntimeError("metadata temporarily unavailable"))
    api.get_inverter_realtime_data = Mock(side_effect=RuntimeError("inverter temporarily unavailable"))
    api.get_battery_devices = Mock(side_effect=RuntimeError("battery temporarily unavailable"))
    api.get_power_sensor_devices = Mock(side_effect=RuntimeError("meter temporarily unavailable"))
    assert api._build_inverter_devices() == []
    assert api._build_battery_devices() == []
    assert api._build_power_sensor_devices([]) == []


def test_inverter_metadata_can_survive_telemetry_failure(modules):
    api = make_installation(modules)
    sentinel = object()
    api.get_inverter_metadata_devices = Mock(return_value=[sentinel])
    api.get_inverter_realtime_data = Mock(side_effect=RuntimeError("not available"))
    assert api._build_inverter_devices() == [sentinel]


def test_inverter_unknown_signals_are_skipped(modules):
    api = make_installation(modules)
    api.get_inverter_metadata_devices = Mock(return_value=[])
    api.get_inverter_realtime_data = Mock(return_value={999999999: "2.0"})
    assert api._build_inverter_devices() == []


def test_installation_entities_created_from_output(modules):
    api = make_installation(modules)
    api.get_device_unique_id = lambda device_id, kind: "unique_" + device_id
    api.get_device_name = lambda device_id: device_id
    api.get_device_value = lambda device_id, kind, output: output.get(device_id.lower().replace(" ", "_"), 0)
    devices = api._build_installation_devices(api._build_base_output())
    assert devices
    assert all(device.device_unique_id.startswith("unique_") for device in devices)


def test_complete_device_orchestration_preserves_order(modules):
    api = make_installation(modules)
    api._get_installation_flow_data = Mock(return_value=([], []))
    api._discover_inverter_dn_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api._enrich_installation_output = Mock()
    api._build_installation_devices = Mock(return_value=["plant"])
    api._build_inverter_devices = Mock(return_value=["inverter"])
    api._build_battery_devices = Mock(return_value=["battery"])
    api._build_power_sensor_devices = Mock(return_value=["meter"])
    assert api.get_devices() == ["plant", "inverter", "battery", "meter"]
    api._discover_inverter_dn_from_flow_nodes.assert_called_once_with([])
    api._ensure_inverter_metadata_loaded.assert_called_once()


def test_week_energy_ignores_missing_markers(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    source = {"data": {"productPower": ["2.5 kWh", "--", "null", "3 kWh"]}}
    assert api.calculate_week_energy(source, [1, 2, 3, 4], "productPower") == 5.5
    assert api.calculate_week_energy({"data": {"productPower": []}}, [1], "productPower") == 0


def test_week_data_calls_daily_endpoint_without_waiting(modules, monkeypatch):
    energy_module = modules[1]
    api = energy_module.FusionSolarEnergyBalanceMixin()
    api.call_energy_balance = Mock(return_value={"data": {"totalBuyPower": "1 kWh"}})
    monkeypatch.setattr(energy_module.time, "sleep", lambda seconds: None)
    result = api.get_week_data()
    assert len(result) == energy_module.datetime.now().weekday() + 1
    assert api.call_energy_balance.call_count == len(result)
    assert all(call.args[0] == energy_module.ENERGY_BALANCE_CALL_TYPE.DAY
               for call in api.call_energy_balance.call_args_list)


@pytest.mark.parametrize(("frozen_time", "period", "expected_date", "expected_dim"), [
    ("2026-10-31T23:59:00", "MONTH", "2026-10-01 00:00:00", "4"),
    ("2026-11-01T00:01:00", "MONTH", "2026-11-01 00:00:00", "4"),
    ("2026-11-01T00:01:00", "PREVIOUS_MONTH", "2026-10-01 00:00:00", "4"),
    ("2026-12-31T23:59:00", "YEAR", "2026-01-01 00:00:00", "5"),
    ("2027-01-01T00:01:00", "YEAR", "2027-01-01 00:00:00", "5"),
    ("2027-01-01T00:01:00", "LIFETIME", "2027-01-01 00:00:00", "6"),
])
def test_energy_balance_request_date_boundaries(
    modules, monkeypatch, frozen_time, period, expected_date, expected_dim
):
    """Lock down current date-selection behavior without altering source totals."""
    from datetime import datetime
    from urllib.parse import parse_qs, urlsplit

    energy_module = modules[1]
    fixed = datetime.fromisoformat(frozen_time)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed if tz is None else fixed.replace(tzinfo=tz)

    monkeypatch.setattr(energy_module, "datetime", FrozenDatetime)
    api = energy_module.FusionSolarEnergyBalanceMixin()
    api.station = "station-id"
    api.data_host = "example.com"
    api.csrf = "test-csrf"
    api.refresh_csrf = Mock()
    api._request_json = Mock(return_value=(None, {"data": {"totalProductPower": "99 kWh"}}))
    call_type = energy_module.ENERGY_BALANCE_CALL_TYPE[period]
    result = api.call_energy_balance(call_type)
    params = parse_qs(urlsplit(api._request_json.call_args.args[1]).query)
    assert params["dateStr"] == [expected_date]
    assert params["timeDim"] == [expected_dim]
    assert int(params["queryTime"][0]) > 0
    assert result["data"]["totalProductPower"] == "99 kWh"


def test_energy_balance_explicit_day_across_year_boundary(modules, monkeypatch):
    """A requested day must not change when a new calendar year starts."""
    from datetime import datetime
    from urllib.parse import parse_qs, urlsplit

    energy_module = modules[1]
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2027, 1, 1, 0, 1)

    monkeypatch.setattr(energy_module, "datetime", FrozenDatetime)
    api = energy_module.FusionSolarEnergyBalanceMixin()
    api.station = "station-id"
    api.data_host = "example.com"
    api.csrf = "test-csrf"
    api.refresh_csrf = Mock()
    api._request_json = Mock(return_value=(None, {"data": {}}))
    api.call_energy_balance(
        energy_module.ENERGY_BALANCE_CALL_TYPE.DAY,
        specific_date=datetime(2026, 12, 31),
    )
    params = parse_qs(urlsplit(api._request_json.call_args.args[1]).query)
    assert params["dateStr"] == ["2026-12-31 00:00:00"]
    assert params["timeDim"] == ["2"]


@pytest.mark.parametrize(("date_text", "expected_offset"), [
    ("2026-03-29T00:30:00+00:00", 0),
    ("2026-03-29T02:30:00+01:00", 3600),
    ("2026-10-25T00:30:00+01:00", 3600),
    ("2026-10-25T02:30:00+00:00", 0),
])
def test_lisbon_dst_offset_at_boundaries(date_text, expected_offset):
    """Document real Europe/Lisbon DST transitions independently of the API."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    instant = datetime.fromisoformat(date_text)
    localized = instant.astimezone(ZoneInfo("Europe/Lisbon"))
    assert int(localized.utcoffset().total_seconds()) == expected_offset


def test_same_instant_can_have_different_local_calendar_days():
    """Host and station time zones can disagree around local midnight."""
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo

    instant = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
    lisbon = instant.astimezone(ZoneInfo("Europe/Lisbon"))
    utc = instant.astimezone(timezone.utc)
    assert lisbon.date().isoformat() == "2026-10-25"
    assert utc.date().isoformat() == "2026-10-25"

    instant = datetime(2026, 7, 1, 23, 30, tzinfo=timezone.utc)
    assert instant.astimezone(ZoneInfo("Europe/Lisbon")).date().isoformat() == "2026-07-02"
    assert instant.date().isoformat() == "2026-07-01"


def test_upstream_lifetime_spike_is_not_silently_clamped(modules):
    """Keep the upstream spike visible until its root cause is confirmed."""
    from unittest.mock import Mock

    energy_module = modules[1]
    api = energy_module.FusionSolarEnergyBalanceMixin()
    api.station = "station-id"
    api.data_host = "example.com"
    api.csrf = "test-csrf"
    api.refresh_csrf = Mock()
    upstream_values = ["1000 kWh", "1009.9 kWh", "1000 kWh"]
    api._request_json = Mock(
        side_effect=[(None, {"data": {"totalProductPower": value}})
                     for value in upstream_values]
    )
    actual = [
        api.call_energy_balance(
            energy_module.ENERGY_BALANCE_CALL_TYPE.LIFETIME
        )["data"]["totalProductPower"]
        for _ in upstream_values
    ]
    assert actual == upstream_values


def test_missing_isitepower_soc_is_not_reported_as_zero(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    assert output["battery_percentage"] is None
    api._parse_installation_flow_nodes([{
        "name": "neteco.pvms.devTypeLangKey.energy_store",
        "description": {"value": "--"},
        "deviceTips": {"SOC": "--", "BATTERY_POWER": "--"},
    }], output)
    assert output["battery_percentage"] is None


def test_isitepower_null_battery_tips_remain_unknown(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([{
        "name": "neteco.pvms.devTypeLangKey.energy_store",
        "description": {"value": "--"},
        "deviceTips": None,
    }], output)
    assert output["battery_percentage"] is None


def test_valid_battery_soc_zero_is_retained(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([{
        "name": "neteco.pvms.devTypeLangKey.energy_store",
        "description": {"value": "0 kW"},
        "deviceTips": {"SOC": "0 %", "BATTERY_POWER": "0 kW"},
    }], output)
    assert output["battery_percentage"] == 0.0


def test_live_power_placeholders_remain_unknown(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.string", "description": {"value": "--"}},
        {"name": "neteco.pvms.KPI.kpiView.electricalLoad", "description": {"value": None}},
        {"name": "neteco.pvms.devTypeLangKey.energy_store",
         "description": {"value": "--"},
         "deviceTips": {"SOC": "--", "BATTERY_POWER": None}},
    ], output)
    assert output["panel_production_power"] is None
    assert output["house_load_power"] is None
    assert output["battery_injection_power"] is None
    assert output["battery_consumption_power"] is None


def test_live_power_real_zero_remains_zero(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.string", "description": {"value": "0 kW"}},
        {"name": "neteco.pvms.KPI.kpiView.electricalLoad", "description": {"value": "0 kW"}},
        {"name": "neteco.pvms.devTypeLangKey.energy_store",
         "description": {"value": "0 kW"},
         "deviceTips": {"SOC": "0 %", "BATTERY_POWER": "0 kW"}},
    ], output)
    assert output["panel_production_power"] == 0
    assert output["house_load_power"] == 0
    assert output["battery_consumption_power"] == 0
    assert output["battery_injection_power"] == 0


def test_grid_direction_requires_complete_power_inputs(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    output.update(panel_production_power=2.0, house_load_power=1.0)
    api._parse_installation_flow_links([{
        "description": {"label": "neteco.pvms.energy.flow.buy.power", "value": "1 kW"}
    }], output)
    assert output["grid_injection_power"] is None
    assert output["grid_consumption_power"] is None
