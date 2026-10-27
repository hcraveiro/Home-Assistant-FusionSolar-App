"""Regression tests for the verified iSitePower-M INTL cluster signal IDs."""

import importlib.util
from pathlib import Path

import pytest

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "custom_components/fusion_solar_app/api/isitepower.py"
)
spec = importlib.util.spec_from_file_location("isitepower_parser_test", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_discovers_only_power_cube_cluster_dns():
    nodes = [
        {"name": "neteco.pvms.devTypeLangKey.inverter", "mocId": 20822,
         "id": "1", "devIds": []},
        {"name": "neteco.pvms.devTypeLangKey.power_cube", "mocId": 60014,
         "id": "6", "devIds": ["DEVICE_D", "DEVICE_F", "DEVICE_E", "DEVICE_D"]},
        {"name": "converter", "mocId": 60092, "devIds": ["CONVERTER"]},
    ]
    assert module.discover_cluster_dns(nodes) == [
        "DEVICE_D", "DEVICE_F", "DEVICE_E"
    ]


@pytest.mark.parametrize(("raw", "unit", "expected"), [
    ("9.6 kWh", "kWh", 9.6),
    ("9.6", "kWh", 9.6),
    ("43%", "%", 43),
    ("--", "%", None),
    ("NaN", "kWh", None),
    ("1 MW", "kWh", None),
    (True, "kWh", None),
])
def test_strict_unit_parser(raw, unit, expected):
    assert module.parse_measurement(raw, unit) == expected


def test_three_cluster_signal_mapping_and_capacity():
    samples = {
        "DEVICE_D": [
            {"id": 10001, "value": "5"},
            {"id": 10005, "value": "45%"},
            {"id": 2101296, "value": "9.6", "unit": "kWh"},
        ],
        "DEVICE_E": [
            {"id": 10001, "value": "5"},
            {"id": 10005, "value": "43"},
            {"id": 2101296, "value": "9.6", "unit": "kWh"},
        ],
        "DEVICE_F": [
            {"id": 10001, "value": "4"},
            {"id": 10005, "value": "40%"},
            {"id": 2101296, "value": "9.6", "unit": "kWh"},
        ],
    }
    readings = {dn: module.parse_cluster_signals(rows) for dn, rows in samples.items()}
    assert readings["DEVICE_D"]["state"] == "Charging"
    assert readings["DEVICE_F"]["state"] == "Discharging"
    assert [readings[dn]["soc"] for dn in samples] == [45, 43, 40]
    assert module.aggregate_cluster_capacity(list(samples), readings) == pytest.approx(28.8)


def test_no_guessed_capacity_when_any_cluster_missing():
    readings = {
        "A": {"capacity_kwh": 9.6},
        "B": {"capacity_kwh": 9.6},
    }
    assert module.aggregate_cluster_capacity(["A", "B", "C"], readings) is None
    assert module.aggregate_cluster_capacity(["A", "A"], readings) is None


def test_zero_soc_is_valid_but_zero_capacity_is_not():
    result = module.parse_cluster_signals([
        {"id": 10005, "value": "0%"},
        {"id": 2101296, "value": "0 kWh"},
        {"id": 10001, "value": "unknown"},
    ])
    assert result == {"state": None, "soc": 0, "capacity_kwh": None}
