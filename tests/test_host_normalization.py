"""Host normalization regression cases without Home Assistant imports."""

import ast
from pathlib import Path
import re

import pytest


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "fusion_solar_app"
    / "api"
    / "auth.py"
)


def load_host_normalizer():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "normalize_fusionsolar_host"
    )
    namespace = {"re": re}
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
            str(SOURCE),
            "exec",
        ),
        namespace,
    )
    return namespace["normalize_fusionsolar_host"]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        (None, "eu5.fusionsolar.huawei.com"),
        ("", "eu5.fusionsolar.huawei.com"),
        ("EU5", "eu5.fusionsolar.huawei.com"),
        ("https://eu5.fusionsolar.huawei.com/path", "eu5.fusionsolar.huawei.com"),
        ("uni004eu5.fusionsolar.huawei.com", "eu5.fusionsolar.huawei.com"),
        ("region004eu5", "eu5.fusionsolar.huawei.com"),
        ("https://sg5.fusionsolar.huawei.com:443/", "sg5.fusionsolar.huawei.com"),
    ],
)
def test_fusionsolar_host_normalization(host, expected):
    assert load_host_normalizer()(host) == expected
