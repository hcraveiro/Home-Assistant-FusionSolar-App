"""Regression coverage for v1.6.5 registry and migration stabilization."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "custom_components" / "fusion_solar_app"


def test_optimizer_uses_compatible_parent_link():
    source = (ROOT / "sensor.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    builder = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_build_device_info"
    )
    optimizer = next(
        node for node in ast.walk(builder)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.BoolOp)
        and "Optimizer " in (ast.get_source_segment(source, node.test) or "")
    )
    segment = ast.get_source_segment(source, optimizer)
    assert "_parent_device_link(" in segment
    assert '"via_device_id": optimizer_parent_id' not in segment
    assert "inverter_device is not None" in segment
    assert "else plant_identifier" in segment


def test_duplicate_migration_is_non_destructive_and_quiet():
    source = (ROOT / "__init__.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    migration = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "_async_migrate_inverter_unique_ids"
    )
    segment = ast.get_source_segment(source, migration)
    assert segment.count("devices = dr.async_get(hass)") == 1
    assert "registry.async_get_entity_id(" in segment
    assert ' _LOGGER.debug(' in segment or "_LOGGER.debug(" in segment
    assert "return None" in segment
