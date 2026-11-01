"""Regression tests for independent battery discovery and entity scoping."""

from types import SimpleNamespace
from unittest.mock import Mock

import ast
import logging
import time
from pathlib import Path
from urllib.parse import unquote

# Extract the independent discovery/build methods. The CI test environment
# deliberately does not install the Home Assistant runtime.
source_path = (
    Path(__file__).resolve().parents[1]
    / "custom_components/fusion_solar_app/api/installation.py"
)
module_ast = ast.parse(source_path.read_text(encoding="utf-8"))
class_ast = next(
    node for node in module_ast.body
    if isinstance(node, ast.ClassDef) and node.name == "FusionSolarInstallationMixin"
)
methods = [
    node for node in class_ast.body
    if isinstance(node, ast.FunctionDef)
    and node.name in {
        "_discover_battery_dn_from_flow_nodes",
        "_build_battery_devices",
        "_discover_additional_batteries_from_v3",
    }
]
test_ast = ast.Module(
    body=[ast.ClassDef(
        name="FusionSolarInstallationMixin",
        bases=[],
        keywords=[],
        body=methods,
        decorator_list=[],
    )],
    type_ignores=[],
)
namespace = {"Any": object, "Device": object, "_LOGGER": logging.getLogger(__name__), "time": time, "unquote": unquote}
exec(compile(ast.fix_missing_locations(test_ast), str(source_path), "exec"), namespace)
FusionSolarInstallationMixin = namespace["FusionSolarInstallationMixin"]


def _fake_api():
    api = SimpleNamespace(
        battery_dn=None,
        battery_dns=[],
        battery_model="primary",
        battery_serial_number="serial-primary",
        battery_software_version="1",
        _battery_entity_dn=None,
    )
    api._discover_battery_dn_from_flow_nodes = (
        lambda nodes: FusionSolarInstallationMixin._discover_battery_dn_from_flow_nodes(api, nodes)
    )
    api._discover_additional_batteries_from_v3 = (
        lambda: FusionSolarInstallationMixin._discover_additional_batteries_from_v3(api)
    )
    api._build_battery_devices = (
        lambda: FusionSolarInstallationMixin._build_battery_devices(api)
    )
    return api


def test_discovers_all_batteries_and_deduplicates():
    api = _fake_api()
    api._discover_battery_dn_from_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": ["BAT_A", "BAT_B", "BAT_A"]},
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devDn": "BAT_C"},
    ])
    assert api.battery_dns == ["BAT_A", "BAT_B", "BAT_C"]
    assert api.battery_dn == "BAT_A"


def test_single_battery_keeps_unscoped_entities():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A"]
    seen = []

    def fetch():
        seen.append((api.battery_dn, api._battery_entity_dn))
        return [api.battery_dn]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["BAT_A"]
    assert seen == [("BAT_A", None)]
    assert api.battery_dn == "BAT_A"


def test_secondary_battery_is_scoped_and_metadata_restored():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]
    seen = []

    def fetch():
        seen.append((api.battery_dn, api._battery_entity_dn, api.battery_model))
        api.battery_model = "model-" + api.battery_dn
        return [api.battery_dn]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["BAT_A", "BAT_B"]
    assert seen == [("BAT_A", None, "primary"), ("BAT_B", "BAT_B", None)]
    assert api.battery_dn == "BAT_A"
    assert api.battery_model == "model-BAT_A"
    assert api._battery_entity_dn is None


def test_secondary_failure_does_not_remove_primary():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]

    def fetch():
        if api.battery_dn == "BAT_B":
            raise RuntimeError("HTTP 500")
        return ["primary"]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["primary"]
    assert api.battery_dn == "BAT_A"


def test_repeated_discovery_preserves_primary_and_stable_order():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api._discover_battery_dn_from_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": ["BAT_B", "BAT_A"]},
    ])
    api._discover_battery_dn_from_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": ["BAT_C", "BAT_B"]},
    ])
    assert api.battery_dn == "BAT_A"
    assert api.battery_dns == ["BAT_A", "BAT_B", "BAT_C"]


def test_discovery_ignores_missing_and_malformed_identifiers():
    api = _fake_api()
    api._discover_battery_dn_from_flow_nodes([
        {"name": "unrelated", "devIds": ["IGNORE"]},
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": [None, "", " ", {}, False]},
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devDn": None},
    ])
    assert api.battery_dns == []
    assert api.battery_dn is None


def test_all_secondary_failures_restore_primary_state():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B", "BAT_C"]
    api.get_battery_devices = lambda: (["primary"] if api.battery_dn == "BAT_A"
                                      else (_ for _ in ()).throw(RuntimeError("temporary failure")))
    assert api._build_battery_devices() == ["primary"]
    assert api.battery_dn == "BAT_A"
    assert api._battery_entity_dn is None
    assert api.battery_model == "primary"
    assert api.battery_serial_number == "serial-primary"


def test_secondary_scoping_is_stable_across_refreshes():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]
    seen = []

    def fetch():
        seen.append((api.battery_dn, api._battery_entity_dn))
        return [api.battery_dn]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["BAT_A", "BAT_B"]
    assert api._build_battery_devices() == ["BAT_A", "BAT_B"]
    assert seen == [("BAT_A", None), ("BAT_B", "BAT_B")] * 2


def test_primary_failure_does_not_prevent_secondary_polling():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]
    seen = []

    def fetch():
        seen.append((api.battery_dn, api._battery_entity_dn))
        if api.battery_dn == "BAT_A":
            raise RuntimeError("primary offline")
        return ["secondary"]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["secondary"]
    assert seen == [("BAT_A", None), ("BAT_B", "BAT_B")]
    assert api.battery_dn == "BAT_A"
    assert api._battery_entity_dn is None
    assert api.battery_model == "primary"


def test_primary_metadata_is_restored_after_secondary_mutation():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]

    def fetch():
        api.battery_model = "model-" + api.battery_dn
        api.battery_serial_number = "serial-" + api.battery_dn
        api.battery_software_version = "version-" + api.battery_dn
        return [api.battery_dn]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["BAT_A", "BAT_B"]
    assert api.battery_model == "model-BAT_A"
    assert api.battery_serial_number == "serial-BAT_A"
    assert api.battery_software_version == "version-BAT_A"
    assert api._battery_entity_dn is None


def test_repeated_polling_never_changes_primary_dn():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_B", "BAT_A", "BAT_B"]
    api.get_battery_devices = lambda: [api.battery_dn]
    for _ in range(3):
        assert api._build_battery_devices().count("BAT_A") == 1
        assert api.battery_dn == "BAT_A"
        assert api._battery_entity_dn is None


def test_primary_battery_registry_identity_remains_legacy():
    """Guard registry contract: old installations must not migrate IDs."""
    sensor_source = (source_path.parent.parent / "sensor.py").read_text(encoding="utf-8")
    sensor_ast = ast.parse(sensor_source)
    function = next(node for node in sensor_ast.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_build_device_info")
    battery_section = ast.get_source_segment(sensor_source, function)
    assert 'device.dn is not None' in battery_section
    assert 'getattr(coordinator.api, "battery_dn", None)' in battery_section
    assert 'f"{controller_name}_{station_dn}_battery_{battery_dn}"' in battery_section
    assert 'name="Fusion Solar Battery" if not is_secondary' in battery_section


def test_secondary_battery_uses_its_own_device_dn_not_primary_metadata():
    sensor_source = (source_path.parent.parent / "sensor.py").read_text(encoding="utf-8")
    sensor_ast = ast.parse(sensor_source)
    function = next(node for node in sensor_ast.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_build_device_info")
    section = ast.get_source_segment(sensor_source, function)
    assert 'device.dn if is_secondary' in section
    assert '"FusionSolar Battery" if is_secondary' in section
    assert 'None if is_secondary' in section


def test_secondary_and_primary_unique_ids_remain_distinct():
    api_source = (source_path.parent / "__init__.py").read_text(encoding="utf-8")
    api_ast = ast.parse(api_source)
    cls = next(node for node in api_ast.body if isinstance(node, ast.ClassDef)
               and node.name == "FusionSolarAPI")
    methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)
               and node.name in {"get_device_unique_id", "sanitize_id_segment"}]
    assert len(methods) == 2
    namespace = {"DeviceType": object}
    module = ast.Module(body=[ast.ClassDef(name="API", bases=[], keywords=[],
                         body=methods, decorator_list=[])], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(source_path), "exec"), namespace)
    api = namespace["API"]()
    api.station = "station-A"
    api.controller_name = "fusion_solar_app"
    primary = api.get_device_unique_id("Battery Module 1 Pack 1 SOH", None)
    secondary = api.get_device_unique_id("Battery Module 1 Pack 1 SOH", None, dn="BAT_B")
    assert primary == "fusion_solar_app_station-a_battery_module_1_pack_1_soh"
    assert secondary != primary
    assert "bat_b" in secondary


def _configure_v3_api(api, nodes, inverter_count=2):
    api.station = "NE=STATION"
    api.data_host = "example.invalid"
    api.inverters = {f"INV_{i}": object() for i in range(inverter_count)}
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A"]
    calls = []

    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return None, {"success": True, "data": {"flow": {"nodes": nodes}}}

    api._request_json = request
    return calls


def test_v3_supplements_only_battery_discovery_for_two_inverters():
    api = _fake_api()
    calls = _configure_v3_api(api, [
        {"name": "neteco.pvms.devTypeLangKey.energy_store",
         "devIds": ["BAT_A", "BAT_B"]},
    ])
    api._discover_additional_batteries_from_v3()
    assert api.battery_dn == "BAT_A"
    assert api.battery_dns == ["BAT_A", "BAT_B"]
    assert len(calls) == 1
    assert calls[0][0] == "GET"
    assert "/station/v3/overview/energy-flow" in calls[0][1]
    assert calls[0][2]["params"]["featureId"] == "aifc"
    api._discover_additional_batteries_from_v3()
    assert len(calls) == 1


def test_v3_never_probes_single_inverter_installations():
    api = _fake_api()
    calls = _configure_v3_api(api, [], inverter_count=1)
    api._discover_additional_batteries_from_v3()
    assert calls == []
    assert api.battery_dns == ["BAT_A"]


def test_v3_rejects_unrelated_or_ambiguous_battery_ids():
    api = _fake_api()
    calls = _configure_v3_api(api, [
        {"name": "neteco.pvms.devTypeLangKey.energy_store",
         "devIds": ["OTHER_1", "OTHER_2"]},
    ])
    api._discover_additional_batteries_from_v3()
    assert len(calls) == 1
    assert api.battery_dn == "BAT_A"
    assert api.battery_dns == ["BAT_A"]


def test_v3_failure_does_not_change_primary_and_is_rate_limited():
    api = _fake_api()
    calls = _configure_v3_api(api, [])

    def failing_request(*args, **kwargs):
        calls.append((args, kwargs))
        raise RuntimeError("HTTP 500")

    api._request_json = failing_request
    api._discover_additional_batteries_from_v3()
    api._discover_additional_batteries_from_v3()
    assert len(calls) == 1
    assert api.battery_dn == "BAT_A"
    assert api.battery_dns == ["BAT_A"]


def test_battery_discovery_order_changes_never_replace_primary():
    api = _fake_api()
    api._discover_battery_dn_from_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": ["BAT_A", "BAT_B"]},
    ])
    original_primary = api.battery_dn
    for ids in (["BAT_B", "BAT_A"], ["BAT_B"], ["BAT_A", "BAT_B"]):
        api._discover_battery_dn_from_flow_nodes([
            {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": ids},
        ])
        assert api.battery_dn == original_primary
        assert api.battery_dns == ["BAT_A", "BAT_B"]


def test_v3_reversed_order_does_not_reassign_primary():
    api = _fake_api()
    _configure_v3_api(api, [
        {"name": "neteco.pvms.devTypeLangKey.energy_store",
         "devIds": ["BAT_B", "BAT_A"]},
    ])
    api._discover_additional_batteries_from_v3()
    assert api.battery_dn == "BAT_A"
    assert api.battery_dns == ["BAT_A", "BAT_B"]


def test_v3_retries_after_cooldown_and_recovers_from_missing_flow():
    api = _fake_api()
    calls = _configure_v3_api(api, [])
    times = iter([1000, 1001, 4601])
    original_request = api._request_json

    def request(method, url, **kwargs):
        if len(calls) == 0:
            calls.append((method, url, kwargs))
            return None, {"success": True, "data": {"flow": {}}}
        return original_request(method, url, **kwargs)

    api._request_json = request
    module_time = FusionSolarInstallationMixin._discover_additional_batteries_from_v3.__globals__["time"]
    old_monotonic = module_time.monotonic
    try:
        module_time.monotonic = lambda: next(times)
        api._discover_additional_batteries_from_v3()
        api._discover_additional_batteries_from_v3()
        api._discover_additional_batteries_from_v3()
    finally:
        module_time.monotonic = old_monotonic
    assert len(calls) == 2
    assert api.battery_dn == "BAT_A"
    assert api.battery_dns == ["BAT_A"]



def test_aggregate_station_soc_and_capacity_are_not_assigned_to_individual_batteries():
    """Station-wide SOC and capacity cannot be treated as per-battery telemetry."""
    installation_source = ast.parse(source_path.read_text(encoding="utf-8"))
    installation_class = next(
        node for node in installation_source.body
        if isinstance(node, ast.ClassDef) and node.name == "FusionSolarInstallationMixin"
    )
    build_station = next(
        node for node in installation_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "_build_installation_devices"
    )
    station_namespace = {
        "Device": lambda **kwargs: SimpleNamespace(dn=None, **kwargs),
        "DEVICES": [
            {"id": "Battery Percentage", "type": "percentage", "icon": "mdi:battery"},
            {"id": "Battery Capacity", "type": "energy", "icon": "mdi:battery"},
        ],
    }
    exec(
        compile(ast.fix_missing_locations(ast.Module(body=[build_station], type_ignores=[])),
                str(source_path), "exec"),
        station_namespace,
    )

    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]
    api.get_device_unique_id = lambda device_id, dtype: "station-" + device_id
    api.get_device_name = lambda device_id: device_id
    api.get_device_value = lambda device_id, dtype, output: output[device_id]
    api.get_battery_devices = lambda: [
        SimpleNamespace(device_id="Battery Charge/Discharge Power",
                        dn=api._battery_entity_dn, state=1.0)
    ]

    aggregate = {"Battery Percentage": 57.0, "Battery Capacity": 30.0}
    station_devices = station_namespace["_build_installation_devices"](api, aggregate)
    battery_devices = api._build_battery_devices()

    assert {device.device_id: device.state for device in station_devices} == aggregate
    assert all(device.dn is None for device in station_devices)
    assert {device.device_unique_id for device in station_devices} == {
        "station-Battery Percentage", "station-Battery Capacity"
    }
    assert len(battery_devices) == 2
    assert not any(
        device.device_id in {"Battery Percentage", "Battery Capacity"}
        for device in battery_devices
    )
    assert api.battery_dn == "BAT_A"
    assert api._battery_entity_dn is None


def test_station_aggregate_soc_and_capacity_are_not_copied_to_individual_batteries():
    """Station-wide SoC/capacity must not masquerade as per-battery telemetry.

    The legacy installation sensors remain intact. Individual battery SoC and
    capacity need independently verified Huawei API fields before being added.
    """
    battery_source = (source_path.parent / "battery.py").read_text(encoding="utf-8")
    battery_tree = ast.parse(battery_source)
    battery_mixin = next(
        node for node in battery_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "FusionSolarBatteryMixin"
    )
    battery_builder = next(
        node for node in battery_mixin.body
        if isinstance(node, ast.FunctionDef) and node.name == "get_battery_devices"
    )
    battery_labels = {
        node.value for node in ast.walk(battery_builder)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "Battery Percentage" not in battery_labels
    assert "Battery Capacity" not in battery_labels

    installation_builder = next(
        node for node in class_ast.body
        if isinstance(node, ast.FunctionDef) and node.name == "_build_installation_devices"
    )
    installation_source = ast.get_source_segment(
        source_path.read_text(encoding="utf-8"), installation_builder
    )
    assert "for device in DEVICES" in installation_source

    # A discovered secondary battery must not inherit station-level aggregate
    # readings merely because both battery DNs are now available.
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]
    api.station_output = {"battery_percentage": 63, "battery_capacity": 30.0}

    def per_battery_readings():
        return [{"dn": api.battery_dn, "name": "Battery Charge/Discharge Power"}]

    api.get_battery_devices = per_battery_readings
    actual = api._build_battery_devices()
    assert [device["dn"] for device in actual] == ["BAT_A", "BAT_B"]
    assert all(device["name"] not in {"Battery Percentage", "Battery Capacity"} for device in actual)
