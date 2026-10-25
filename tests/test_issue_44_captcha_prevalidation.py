"""Regression tests for explicit CAPTCHA pre-validation results (#35, #44)."""

import ast
from pathlib import Path
import types
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app/api/auth.py"


def extract_prevalidation():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    klass = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "FusionSolarAuthMixin")
    method = next(node for node in klass.body if isinstance(node, ast.FunctionDef) and node.name == "_prevalidate_captcha")
    namespace = {"_LOGGER": types.SimpleNamespace(debug=lambda *args: None), "LOGIN_HEADERS_1_STEP_REFERER": "/unisso/login.action"}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(SOURCE), "exec"), namespace)
    return namespace["_prevalidate_captcha"]


class CaptchaValidationTests(unittest.TestCase):
    def test_explicit_results_only(self):
        method = extract_prevalidation()
        cases = [
            (True, True), (False, False),
            ({"success": True}, True), ({"success": False}, False),
            ({"success": False, "data": True}, False),
            ({"data": True}, False),
            ("true", True), ("false", False),
            ("ok", True), ("unknown captcha response", False),
            ("not valid", False), ("411", False),
            ("", False),
        ]
        for response_value, expected in cases:
            with self.subTest(response_value=response_value):
                response = types.SimpleNamespace(
                    status_code=200, text=str(response_value), headers={"Content-Type": "application/json"},
                    json=lambda value=response_value: value,
                )
                session = types.SimpleNamespace(post=lambda *args, **kwargs: response)
                api = types.SimpleNamespace(login_host="eu5.fusionsolar.huawei.com", session=session)
                self.assertEqual(method(api, "abcd"), expected)

    def test_non_200_is_failure(self):
        method = extract_prevalidation()
        response = types.SimpleNamespace(status_code=500, text="true", headers={"Content-Type": "application/json"}, json=lambda: True)
        api = types.SimpleNamespace(
            login_host="eu5.fusionsolar.huawei.com",
            session=types.SimpleNamespace(post=lambda *args, **kwargs: response),
        )
        self.assertFalse(method(api, "abcd"))


if __name__ == "__main__":
    unittest.main()
