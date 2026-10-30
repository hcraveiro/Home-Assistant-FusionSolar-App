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
        ("api.station", ROOT / "api/station.py"),
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
    instance.inverters = {"inverter-1": object()}
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
    api._discover_inverter_dns_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api._enrich_installation_output = Mock()
    api._build_installation_devices = Mock(return_value=["plant"])
    api._build_inverter_devices = Mock(return_value=["inverter"])
    api._build_battery_devices = Mock(return_value=["battery"])
    api._build_power_sensor_devices = Mock(return_value=["meter"])
    assert api.get_devices() == ["plant", "inverter", "battery", "meter"]
    api._discover_inverter_dns_from_flow_nodes.assert_called_once_with([])
    api._ensure_inverter_metadata_loaded.assert_called_once_with("inverter-1")


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


def test_grid_inference_confirmed_no_battery(modules):
    """Known zero installed capacity permits a battery-free energy balance."""
    api = make_installation(modules)
    api.battery_capacity = 0
    api.battery_dn = None
    output = api._build_base_output()
    output.update(panel_production_power=5.0, house_load_power=2.0)
    api._parse_installation_flow_links([{
        "description": {"label": "neteco.pvms.energy.flow.buy.power", "value": "3 kW"}
    }], output)
    assert output["grid_injection_power"] == 3.0
    assert output["grid_consumption_power"] == 0.0
    assert output["battery_consumption_power"] == 0.0


def test_previously_discovered_battery_requires_telemetry(modules):
    """A missing battery flow node cannot erase a known battery device."""
    api = make_installation(modules)
    api.battery_dn = "previously-discovered-battery"
    api.battery_capacity = 0
    output = api._build_base_output()
    output.update(panel_production_power=5.0, house_load_power=2.0)
    api._parse_installation_flow_links([{
        "description": {"label": "neteco.pvms.energy.flow.buy.power", "value": "3 kW"}
    }], output)
    assert output["grid_injection_power"] is None
    assert output["grid_consumption_power"] is None
    assert output["battery_consumption_power"] is None


def test_unknown_battery_presence_does_not_invent_zero(modules):
    """No battery DN alone does not prove an installation has no battery."""
    api = make_installation(modules)
    api.battery_dn = None
    api.battery_capacity = None
    output = api._build_base_output()
    output.update(panel_production_power=5.0, house_load_power=2.0)
    api._parse_installation_flow_links([{
        "description": {"label": "neteco.pvms.energy.flow.buy.power", "value": "3 kW"}
    }], output)
    assert output["grid_injection_power"] is None
    assert output["grid_consumption_power"] is None


def test_isitepower_power_cube_recovers_soc_without_inventing_power_direction(modules):
    """Reproduce the redacted iSitePower-M INTL flow in issue #49."""
    api = make_installation(modules)
    output = api._build_base_output()
    nodes = [
        {
            "mocId": 20822, "id": "1",
            "name": "neteco.pvms.devTypeLangKey.inverter",
            "display": "HIDE", "devIds": [], "deviceTips": None,
            "description": {"value": "--"},
        },
        {
            "mocId": 60014, "id": "6",
            "name": "neteco.pvms.devTypeLangKey.power_cube",
            "description": {
                "label": "neteco.pvms.devTypeLangKey.energy_store",
                "value": "3.13kW",
            },
            "devIds": ["battery-1", "battery-2", "battery-3"],
            "deviceTips": {"SOC": "46%"},
        },
        {
            "mocId": 60043,
            "name": "neteco.pvms.devTypeLangKey.string",
            "description": {"value": "3.24kW"},
        },
        {
            "mocId": 60001,
            "name": "neteco.pvms.pcs.station.energyflow.mains",
            "description": {"value": "0.33kW"},
        },
        {
            "mocId": 60010,
            "name": "neteco.pvms.KPI.kpiView.electricalLoad",
            "description": {"value": "0.33kW"},
        },
    ]
    api._parse_installation_flow_nodes(nodes, output)
    api._discover_battery_dn_from_flow_nodes(nodes)

    assert output["battery_percentage"] == 46
    assert output["panel_production_power"] == 3.24
    assert output["house_load_power"] == 0.33
    assert output["battery_consumption_power"] is None
    assert output["battery_injection_power"] is None
    assert output["grid_consumption_power"] is None
    assert output["grid_injection_power"] is None
    assert api.battery_dn is None


def test_isitepower_power_cube_ignores_unverified_or_missing_soc(modules):
    api = make_installation(modules)
    node = {
        "name": "neteco.pvms.devTypeLangKey.power_cube",
        "description": {
            "label": "neteco.pvms.devTypeLangKey.energy_store",
            "value": "2.2kW",
        },
        "deviceTips": None,
    }
    output = api._build_base_output()
    api._parse_installation_flow_nodes([node], output)
    assert output["battery_percentage"] is None
    assert output["battery_injection_power"] is None
    node["deviceTips"] = {"SOC": "--"}
    api._parse_installation_flow_nodes([node], output)
    assert output["battery_percentage"] is None


def test_unrelated_node_cannot_impersonate_isitepower_soc(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([{
        "name": "neteco.pvms.pcs.station.energyflow.mains",
        "description": {
            "label": "neteco.pvms.devTypeLangKey.energy_store",
            "value": "7kW",
        },
        "deviceTips": {"SOC": "72%"},
    }], output)
    assert output["battery_percentage"] is None


def test_isitepower_genuine_zero_soc_is_not_discarded(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([{
        "name": "neteco.pvms.devTypeLangKey.power_cube",
        "description": {"label": "neteco.pvms.devTypeLangKey.energy_store", "value": "0kW"},
        "deviceTips": {"SOC": "0%"},
    }], output)
    assert output["battery_percentage"] == 0


def test_isitepower_power_cube_marks_nonstandard_energy_architecture(modules):
    api = make_installation(modules)
    output = api._build_base_output()
    api._parse_installation_flow_nodes([{
        "mocId": 60014,
        "name": "neteco.pvms.devTypeLangKey.power_cube",
        "description": {"label": "neteco.pvms.devTypeLangKey.energy_store", "value": "0.01kW"},
        "deviceTips": {"SOC": "100%"},
    }], output)
    assert api._is_isitepower_m is True
    assert output["battery_percentage"] == 100


@pytest.mark.parametrize(("reading", "expected"), [
    ("1376.860 kWh", 1376.860),
    ("1376860 Wh", 1376.860),
    ("0 kWh", 0.0),
    ("--", None),
    ("null", None),
    ("", None),
    (None, None),
    ("garbage", None),
    ("NaN", None),
])
def test_isitepower_grid_counter_is_not_guessed_from_missing_data(modules, reading, expected):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    output = {}
    api._set_grid_energy(output, "lifetime", "consumption", {"totalBuyPower": reading})
    assert output["grid_consumption_lifetime"] == expected


def test_isitepower_missing_grid_fields_are_unknown(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    output = {}
    api._set_grid_energy(output, "lifetime", "consumption", {})
    api._set_grid_energy(output, "lifetime", "injection", {"totalOnGridPower": "--"})
    assert output == {
        "grid_consumption_lifetime": None,
        "grid_injection_lifetime": None,
    }


def test_existing_plant_grid_zero_remains_unchanged(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = False
    output = {}
    api._set_grid_energy(output, "year", "consumption", {"totalBuyPower": "0 kWh"})
    assert output["grid_consumption_year"] == 0


@pytest.mark.parametrize(("capacity", "expected"), [
    (None, None), ("", None), ("0", None),
    ("15", 15.0), ("15.0 kWh", 15.0),
])
def test_isitepower_battery_capacity_unverified_zero_is_unknown(modules, capacity, expected):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    api.station = "selected"
    api.battery_capacity = None
    api.refresh_csrf = Mock()
    api.get_station_list = Mock(return_value={"data": {"list": [
        {"dn": "other", "batteryCapacity": "99"},
        {"dn": "selected", "batteryCapacity": capacity},
    ]}})
    output = {}
    api.update_output_with_battery_capacity(output)
    assert output["battery_capacity"] == expected
    assert api.battery_capacity == expected


def test_isitepower_base_output_keeps_unverified_counters_unknown(modules):
    api = make_installation(modules)
    api._get_installation_flow_data = Mock(return_value=([{
        "mocId": 60014,
        "name": "neteco.pvms.devTypeLangKey.power_cube",
        "description": {"label": "neteco.pvms.devTypeLangKey.energy_store", "value": "0.01kW"},
        "deviceTips": {"SOC": "100%"},
    }], []))
    api._discover_inverter_dns_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api._enrich_installation_output = Mock()
    api._build_installation_devices = Mock(side_effect=lambda output: [output.copy()])
    api._build_inverter_devices = Mock(return_value=[])
    api._build_battery_devices = Mock(return_value=[])
    api._build_power_sensor_devices = Mock(return_value=[])
    api.get_optimizer_devices = Mock(return_value=[])
    result = api.get_devices()[0]
    assert all(result[f"grid_consumption_{period}"] is None
               for period in ("today", "week", "month", "year", "lifetime"))
    assert all(result[f"grid_injection_{period}"] is None
               for period in ("today", "week", "month", "year", "lifetime"))
    assert result["battery_capacity"] is None
    assert result["battery_percentage"] == 100


def test_isitepower_zero_station_capacity_does_not_prove_no_battery(modules):
    """An INTL power_cube exists even when conventional station capacity is zero."""
    api = make_installation(modules)
    api._is_isitepower_m = True
    api.battery_capacity = 0
    api.battery_dn = None
    output = api._build_base_output()
    output.update(panel_production_power=3.24, house_load_power=0.33)
    api._parse_installation_flow_links([{
        "description": {
            "label": "neteco.pvms.energy.flow.buy.power",
            "value": "0.33kW",
        },
    }], output)
    assert output["battery_consumption_power"] is None
    assert output["battery_injection_power"] is None
    assert output["grid_consumption_power"] is None
    assert output["grid_injection_power"] is None


def test_isitepower_missing_energy_balance_keeps_live_readings(modules):
    """A nonstandard history payload cannot suppress a healthy flow response."""
    api = make_installation(modules)
    api._is_isitepower_m = True
    api.battery_capacity = 0
    api.update_output_with_battery_capacity = Mock(side_effect=KeyError("batteryCapacity"))
    api.update_output_with_energy_balance = Mock(side_effect=KeyError("totalBuyPower"))
    api.update_output_with_social_contribution = Mock()
    api._update_output_with_self_consumption_ratios = Mock()
    output = api._build_base_output()
    output.update(
        battery_capacity=None,
        panel_production_power=0.53,
        house_load_power=0.38,
        battery_percentage=100,
        grid_consumption_lifetime=None,
        grid_injection_lifetime=None,
    )
    api._enrich_installation_output(output)
    assert output["exit_code"] == "SUCCESS"
    assert output["panel_production_power"] == 0.53
    assert output["house_load_power"] == 0.38
    assert output["battery_percentage"] == 100
    assert output["grid_consumption_lifetime"] is None
    assert output["grid_injection_lifetime"] is None
    assert output["battery_capacity"] is None


def test_regular_installation_energy_errors_still_propagate(modules):
    api = make_installation(modules)
    api._is_isitepower_m = False
    api.update_output_with_battery_capacity = Mock(side_effect=KeyError("batteryCapacity"))
    with pytest.raises(KeyError):
        api._enrich_installation_output(api._build_base_output())


def test_isitepower_capacity_never_falls_back_to_another_station(modules):
    """A selected INTL station cannot borrow battery size from an unrelated plant."""
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api.station = "NE=SELECTED"
    api._is_isitepower_m = True
    api.battery_capacity = None
    api.refresh_csrf = Mock()
    api.get_station_list = Mock(return_value={"data": {"list": [
        {"dn": "NE=OTHER", "batteryCapacity": 30},
    ]}})
    output = {}
    api.update_output_with_battery_capacity(output)
    assert output["battery_capacity"] is None
    assert api.battery_capacity is None


def test_isitepower_architecture_flag_is_rechecked_on_every_refresh(modules):
    """An earlier power_cube must not mark unrelated later flow polls as iSitePower-M."""
    api = make_installation(modules)
    api._is_isitepower_m = True
    api._get_installation_flow_data = Mock(return_value=([], []))
    api._discover_inverter_dns_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api._enrich_installation_output = Mock()
    api._build_installation_devices = Mock(return_value=[])
    api._build_inverter_devices = Mock(return_value=[])
    api._build_battery_devices = Mock(return_value=[])
    api._build_power_sensor_devices = Mock(return_value=[])
    api.get_optimizer_devices = Mock(return_value=[])
    api.get_devices()
    assert api._is_isitepower_m is False


def test_isitepower_explicit_zero_energy_is_kept_as_zero(modules):
    """A genuine zero remains distinct from missing or unrecognized data."""
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    output = {}
    api._set_grid_energy(output, "month", "consumption", {"totalBuyPower": "0 kWh"})
    api._set_grid_energy(output, "month", "injection", {"totalOnGridPower": 0})
    assert output == {
        "grid_consumption_month": 0.0,
        "grid_injection_month": 0.0,
    }


def test_isitepower_partial_energy_balance_keeps_unverified_periods_unknown(modules):
    """A missing energy schema must not suppress valid measurements or create zeros."""
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    api.refresh_csrf = Mock()
    api.call_energy_balance = Mock(side_effect=[
        {"data": {"totalBuyPower": "1.25 kWh", "totalProductPower": "0.5kWh"}},
        {"data": {"totalBuyPower": "2.5 kWh"}},
        {"data": {"totalBuyPower": "1376.860 kWh"}},
    ])
    api.get_week_data = Mock(return_value=[
        {"data": {"totalBuyPower": "0.2 kWh"}},
        {"data": {"totalBuyPower": "0.3 kWh"}},
    ])
    output = {category + "_" + period: None
              for period in ("today", "week", "month", "year", "lifetime")
              for category in ("grid_consumption", "grid_injection", "panel_production",
                               "panel_production_consumption", "house_load",
                               "battery_injection", "battery_consumption")}
    api.update_output_with_energy_balance(output)
    assert output["grid_consumption_month"] == 1.25
    assert output["grid_consumption_year"] == 2.5
    assert output["grid_consumption_lifetime"] == 1376.860
    assert output["grid_consumption_today"] == 0.3
    assert output["grid_consumption_week"] == 0.5
    assert output["panel_production_month"] == 0.5
    assert output["grid_injection_lifetime"] is None
    assert output["panel_production_year"] is None
    assert output["battery_injection_month"] is None
    assert output["self_consumption_ratio_today"] is None


def test_isitepower_independent_period_failures_do_not_erase_good_periods(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    api.call_energy_balance = Mock(side_effect=[
        {"data": {"totalBuyPower": "2.3kWh"}},
        {"unexpected": "schema"},
        {"data": {"totalBuyPower": "10 kWh"}},
    ])
    api.get_week_data = Mock(return_value=[])
    output = {"grid_consumption_month": None, "grid_consumption_year": None,
              "grid_consumption_lifetime": None}
    api.update_output_with_energy_balance(output)
    assert output["grid_consumption_month"] == 2.3
    assert output["grid_consumption_year"] is None
    assert output["grid_consumption_lifetime"] == 10


def test_isitepower_missing_day_prevents_partial_week_total(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    api.call_energy_balance = Mock(return_value={"data": {}})
    api.get_week_data = Mock(return_value=[
        {"data": {"totalBuyPower": "0.3 kWh"}},
        {"data": {"totalBuyPower": "--"}},
        {"data": {"totalBuyPower": "0.2 kWh"}},
    ])
    output = {"grid_consumption_week": None}
    api.update_output_with_energy_balance(output)
    assert output["grid_consumption_week"] is None
    assert output["grid_consumption_today"] == 0.2


def test_isitepower_ratio_does_not_claim_zero_without_source(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    output = {
        "panel_production_consumption_today": None,
        "house_load_today": "2",
        "panel_production_today": "4",
    }
    api._update_output_with_self_consumption_ratios(output)
    assert output["self_consumption_ratio_today"] is None
    assert output["self_consumption_ratio_by_production_today"] is None
    output["panel_production_consumption_today"] = 1
    api._update_output_with_self_consumption_ratios(output)
    assert output["self_consumption_ratio_today"] == 50
    assert output["self_consumption_ratio_by_production_today"] == 25


def test_isitepower_zero_capacity_never_proves_missing_battery(modules):
    api = make_installation(modules)
    api.battery_dn = None
    api.battery_capacity = 0
    api._is_isitepower_m = True
    output = api._build_base_output()
    output.update(panel_production_power=2, house_load_power=1)
    api._parse_installation_flow_links([{
        "description": {"label": "neteco.pvms.energy.flow.buy.power",
                        "value": "1kW"}
    }], output)
    assert output["battery_injection_power"] is None
    assert output["battery_consumption_power"] is None
    assert output["grid_consumption_power"] is None


def test_isitepower_installation_survives_partial_energy_sources(modules):
    api = make_installation(modules)
    api._get_installation_flow_data = Mock(return_value=([{
        "mocId": 60014, "name": "neteco.pvms.devTypeLangKey.power_cube",
        "description": {"label": "neteco.pvms.devTypeLangKey.energy_store",
                        "value": "0.01kW"},
        "deviceTips": {"SOC": "73%"},
    }], []))
    api._discover_inverter_dns_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api.update_output_with_battery_capacity = Mock(side_effect=KeyError("batteryCapacity"))
    api.update_output_with_energy_balance = Mock(side_effect=KeyError("totalBuyPower"))
    api.update_output_with_social_contribution = Mock()
    api._update_output_with_self_consumption_ratios = Mock()
    api._build_installation_devices = Mock(side_effect=lambda output: [output.copy()])
    api._build_inverter_devices = Mock(return_value=[])
    api._build_battery_devices = Mock(return_value=[])
    api._build_power_sensor_devices = Mock(return_value=[])
    api.get_optimizer_devices = Mock(return_value=[])
    data = api.get_devices()[0]
    assert data["battery_percentage"] == 73
    assert data["grid_consumption_lifetime"] is None
    assert data["battery_capacity"] is None
    assert data["exit_code"] == "SUCCESS"


def test_isitepower_failed_energy_response_never_exposes_payload_totals(modules):
    """Even numeric fields in a failed Huawei response cannot be trusted."""
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    api.call_energy_balance = Mock(side_effect=[
        {"success": False, "data": {"totalBuyPower": "9999 kWh"}},
        {"success": True, "data": {"totalBuyPower": "1.5kWh"}},
        {"success": False, "data": {"totalBuyPower": "500 kWh"}},
    ])
    api.get_week_data = Mock(return_value=[
        {"success": False, "data": {"totalBuyPower": "20 kWh"}},
        {"success": True, "data": {"totalBuyPower": "0.3 kWh"}},
    ])
    output = {}
    api.update_output_with_energy_balance(output)
    assert output["grid_consumption_month"] is None
    assert output["grid_consumption_year"] == 1.5
    assert output["grid_consumption_lifetime"] is None
    assert output["grid_consumption_today"] == 0.3
    assert output.get("grid_consumption_week") is None


def test_isitepower_api_disconnect_does_not_interrupt_station_updates(modules):
    """A transient optional energy failure should not discard live SOC/power."""
    from unittest.mock import Mock
    api = make_installation(modules)
    api._is_isitepower_m = True
    api.update_output_with_battery_capacity = Mock()
    api.update_output_with_energy_balance = Mock(
        side_effect=modules[2].APIConnectionError("connection reset")
    )
    api.update_output_with_social_contribution = Mock()
    api._update_output_with_self_consumption_ratios = Mock()
    output = api._build_base_output()
    output.update(
        battery_percentage=73, panel_production_power=0.53,
        house_load_power=0.38, grid_consumption_lifetime=None,
    )
    api._enrich_installation_output(output)
    assert output["battery_percentage"] == 73
    assert output["panel_production_power"] == 0.53
    assert output["grid_consumption_lifetime"] is None
    assert output["exit_code"] == "SUCCESS"


def test_isitepower_optional_energy_disconnect_preserves_other_periods(modules):
    api = modules[1].FusionSolarEnergyBalanceMixin()
    api._is_isitepower_m = True
    api.call_energy_balance = Mock(side_effect=[
        {"data": {"totalBuyPower": "2kWh"}},
        modules[2].APIConnectionError("temporary disconnect"),
        {"data": {"totalBuyPower": "25kWh"}},
    ])
    api.get_week_data = Mock(side_effect=modules[2].APIConnectionError("daily request disconnected"))
    output = {}
    api.update_output_with_energy_balance(output)
    assert output["grid_consumption_month"] == 2
    assert output["grid_consumption_lifetime"] == 25
    assert output.get("grid_consumption_year") is None
    assert output.get("grid_consumption_today") is None


@pytest.mark.parametrize(("flag", "capacity", "expected"), [
    ("true", 0, None),
    (True, "0", None),
    ("TRUE", None, None),
    ("false", 0, 0),
    ("false", "0.00", 0.0),
    ("false", "15.5", 15.5),
    ("false", "--", None),
    ("true", "0.00", None),
    (False, 15, 15),
    ("true", "15.0 kWh", 15.0),
])
def test_station_flags_prevent_isitepower_zero_capacity_poisoning(
    modules, flag, capacity, expected
):
    """Station metadata is parsed before the first power_cube update."""
    station_module = sys.modules[f"{PREFIX}.api.station"]
    api = station_module.FusionSolarStationMixin()
    api.station = "NE=SELECTED"
    api.station_name = None
    api.battery_capacity = None
    api._update_station_metadata_from_station_list({"data": {"list": [
        {"dn": "NE=SELECTED", "existISitePowerM": flag,
         "batteryCapacity": capacity},
    ]}})
    assert api.battery_capacity == expected
    assert api._station_is_isitepower_m is (str(flag).lower() == "true")


def test_station_flag_keeps_unknown_battery_when_flow_node_temporarily_missing(modules):
    """A missing power_cube on one poll must not reclassify the station."""
    api = make_installation(modules)
    api._station_is_isitepower_m = True
    api.battery_capacity = None
    api._get_installation_flow_data = Mock(return_value=([], []))
    api._discover_inverter_dns_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api._enrich_installation_output = Mock()
    api._build_installation_devices = Mock(side_effect=lambda output: [output.copy()])
    api._build_inverter_devices = Mock(return_value=[])
    api._build_battery_devices = Mock(return_value=[])
    api._build_power_sensor_devices = Mock(return_value=[])
    api.get_optimizer_devices = Mock(return_value=[])
    readings = api.get_devices()[0]
    assert api._is_isitepower_m is True
    assert readings["battery_capacity"] is None
    assert readings["grid_consumption_lifetime"] is None
    assert readings["battery_injection_lifetime"] is None


def test_batteryless_station_string_capacity_restores_grid_power(modules):
    """Reproduce #103 with a battery-free SUN2000 station-list response."""
    station_module = sys.modules[f"{PREFIX}.api.station"]
    station_api = station_module.FusionSolarStationMixin()
    station_api.station = "NE=SELECTED"
    station_api.station_name = None
    station_api.battery_capacity = None
    station_api._update_station_metadata_from_station_list({"data": {"list": [{
        "dn": "NE=SELECTED", "existISitePowerM": False,
        "batteryCapacity": "0.00",
    }]}})
    assert station_api.battery_capacity == 0.0

    api = make_installation(modules)
    api.battery_capacity = station_api.battery_capacity
    output = api._build_base_output()
    api._parse_installation_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.string",
         "description": {"value": "3.668 kW"}},
        {"name": "neteco.pvms.KPI.kpiView.electricalLoad",
         "description": {"value": "0.614 kW"}},
    ], output)
    api._parse_installation_flow_links([{
        "description": {
            "label": "neteco.pvms.energy.flow.buy.power",
            "value": "3.054 kW",
        },
    }], output)
    assert output["battery_consumption_power"] == 0.0
    assert output["battery_injection_power"] == 0.0
    assert output["grid_injection_power"] == 3.054
    assert output["grid_consumption_power"] == 0.0


@pytest.mark.parametrize("capacity", ["--", None, "unavailable", "NaN"])
def test_unknown_station_capacity_does_not_invent_missing_battery(modules, capacity):
    station_module = sys.modules[f"{PREFIX}.api.station"]
    station_api = station_module.FusionSolarStationMixin()
    station_api.station = "NE=SELECTED"
    station_api.station_name = None
    station_api.battery_capacity = None
    station_api._update_station_metadata_from_station_list({"data": {"list": [{
        "dn": "NE=SELECTED", "existISitePowerM": False,
        "batteryCapacity": capacity,
    }]}})
    assert station_api.battery_capacity is None

def test_isitepower_verified_mains_import(modules):
    api = make_installation(modules)
    api._is_isitepower_m = True
    output = api._build_base_output()
    nodes = [
        {"id": "42", "mocId": 60001,
         "name": "neteco.pvms.pcs.station.energyflow.mains",
         "display": "CONNECTED", "description": {"value": "0.260kW"}},
        {"id": "77", "mocId": 60014,
         "name": "neteco.pvms.devTypeLangKey.power_cube"},
    ]
    links = [{"fromNode": "42", "toNode": "77",
              "flowing": "FORWARD", "visible": True, "direction": None}]
    api._parse_isitepower_grid_import(nodes, links, output)
    assert output["grid_consumption_power"] == 0.260
    assert output["grid_injection_power"] is None


@pytest.mark.parametrize("node_value,flowing,visible,expected", [
    ("0.260kW", "REVERSE", True, None),
    ("0.260kW", None, True, None),
    ("0.260kW", "FORWARD", False, None),
    ("--", "FORWARD", True, None),
    ("NaNkW", "FORWARD", True, None),
    ("260W", "FORWARD", True, None),
    ("0kW", "FORWARD", True, None),
    ("0.260kW", "FORWARD", True, 0.260),
])
def test_isitepower_grid_import_requires_proven_graph(
    modules, node_value, flowing, visible, expected
):
    api = make_installation(modules)
    api._is_isitepower_m = True
    output = api._build_base_output()
    nodes = [
        {"id": "8", "mocId": 60001,
         "name": "neteco.pvms.pcs.station.energyflow.mains",
         "display": "CONNECTED", "description": {"value": node_value}},
        {"id": "6", "mocId": 60014,
         "name": "neteco.pvms.devTypeLangKey.power_cube"},
    ]
    links = [{"fromNode": "8", "toNode": "6",
              "flowing": flowing, "visible": visible}]
    api._parse_isitepower_grid_import(nodes, links, output)
    assert output["grid_consumption_power"] == expected
    assert output["grid_injection_power"] is None


def test_isitepower_grid_import_rejects_ambiguous_and_disconnected_nodes(modules):
    api = make_installation(modules)
    api._is_isitepower_m = True
    output = api._build_base_output()
    mains = {"id": "8", "mocId": 60001,
             "name": "neteco.pvms.pcs.station.energyflow.mains",
             "display": "CONNECTED", "description": {"value": "0.26kW"}}
    cube = {"id": "6", "mocId": 60014,
            "name": "neteco.pvms.devTypeLangKey.power_cube"}
    link = {"fromNode": "8", "toNode": "6",
            "flowing": "FORWARD", "visible": True}
    for nodes, links in [
        ([dict(mains, display="DISCONNECTED"), cube], [link]),
        ([mains, cube, dict(mains)], [link]),
        ([mains, cube], [link, dict(link)]),
        ([mains, cube], []),
        ([mains, cube], [dict(link, fromNode="6", toNode="8")]),
        ([mains, cube], [dict(link, toNode="other")]),
    ]:
        output["grid_consumption_power"] = None
        api._parse_isitepower_grid_import(nodes, links, output)
        assert output["grid_consumption_power"] is None


def test_isitepower_grid_import_does_not_change_regular_installation(modules):
    api = make_installation(modules)
    api._is_isitepower_m = False
    output = api._build_base_output()
    api._parse_isitepower_grid_import(
        [{"id": "8", "mocId": 60001,
          "name": "neteco.pvms.pcs.station.energyflow.mains",
          "display": "CONNECTED", "description": {"value": "0.26kW"}},
         {"id": "6", "mocId": 60014,
          "name": "neteco.pvms.devTypeLangKey.power_cube"}],
        [{"fromNode": "8", "toNode": "6", "flowing": "FORWARD", "visible": True}],
        output,
    )
    assert output["grid_consumption_power"] is None



def test_isitepower_get_devices_uses_only_verified_mains_import(modules):
    """Full installation orchestration must ignore conventional grid guesses."""
    api = make_installation(modules)
    api._station_is_isitepower_m = True
    nodes = [
        {"id": "42", "mocId": 60001,
         "name": "neteco.pvms.pcs.station.energyflow.mains",
         "display": "CONNECTED", "description": {"value": "0.260kW"}},
        {"id": "77", "mocId": 60014,
         "name": "neteco.pvms.devTypeLangKey.power_cube"},
    ]
    links = [
        {"fromNode": "42", "toNode": "77", "flowing": "FORWARD",
         "visible": True},
        {"description": {"label": "neteco.pvms.energy.flow.buy.power",
                         "value": "9.0 kW"}},
    ]
    api._get_installation_flow_data = Mock(return_value=(nodes, links))
    api._discover_inverter_dns_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api._enrich_installation_output = Mock()
    api._build_installation_devices = Mock(side_effect=lambda output: [output.copy()])
    api._build_inverter_devices = Mock(return_value=[])
    api._build_battery_devices = Mock(return_value=[])
    api._build_power_sensor_devices = Mock(return_value=[])
    api.get_optimizer_devices = Mock(return_value=[])
    output = api.get_devices()[0]
    assert output["grid_consumption_power"] == 0.260
    assert output["grid_injection_power"] is None
    assert output["grid_consumption_lifetime"] is None


def test_isitepower_get_devices_leaves_unverified_grid_unknown(modules):
    api = make_installation(modules)
    api._station_is_isitepower_m = True
    nodes = [
        {"id": "42", "mocId": 60001,
         "name": "neteco.pvms.pcs.station.energyflow.mains",
         "display": "CONNECTED", "description": {"value": "0.260kW"}},
        {"id": "77", "mocId": 60014,
         "name": "neteco.pvms.devTypeLangKey.power_cube"},
    ]
    links = [
        {"fromNode": "42", "toNode": "77", "flowing": "REVERSE",
         "visible": True},
        {"description": {"label": "neteco.pvms.energy.flow.buy.power",
                         "value": "9.0 kW"}},
    ]
    api._get_installation_flow_data = Mock(return_value=(nodes, links))
    api._discover_inverter_dns_from_flow_nodes = Mock()
    api._ensure_inverter_metadata_loaded = Mock()
    api._enrich_installation_output = Mock()
    api._build_installation_devices = Mock(side_effect=lambda output: [output.copy()])
    api._build_inverter_devices = Mock(return_value=[])
    api._build_battery_devices = Mock(return_value=[])
    api._build_power_sensor_devices = Mock(return_value=[])
    api.get_optimizer_devices = Mock(return_value=[])
    output = api.get_devices()[0]
    assert output["grid_consumption_power"] is None
    assert output["grid_injection_power"] is None
