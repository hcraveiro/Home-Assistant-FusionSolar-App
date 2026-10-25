"""Regression tests for transient FusionSolar connection failures (#45)."""

import ast
import asyncio
import logging
import time
import threading
from contextlib import nullcontext
import types
import unittest
from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "fusion_solar_app"
    / "coordinator.py"
)


class APIConnectionError(Exception):
    """Simulated transient API connection error."""


class APIAuthError(Exception):
    """Simulated authentication error."""


def load_retry_method():
    """Compile the production retry helper without importing Home Assistant."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "_fetch_devices_with_connection_retry"
    ]
    if len(methods) != 1:
        raise AssertionError("Expected a single connection retry method")
    method = methods[0]
    method.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {
        "Device": object,
        "APIConnectionError": APIConnectionError,
        "_LOGGER": logging.getLogger(__name__),
        "time": time,
    }
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace[method.name]


class SessionSerializationTests(unittest.TestCase):
    def test_api_call_uses_shared_session_lock(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        methods = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "_call_api_serialized"
        ]
        self.assertEqual(len(methods), 1)
        module = ast.fix_missing_locations(ast.Module(body=[methods[0]], type_ignores=[]))
        namespace = {"nullcontext": nullcontext}
        exec(compile(module, str(SOURCE), "exec"), namespace)
        serialize = namespace["_call_api_serialized"]
        lock = threading.RLock()
        coordinator = types.SimpleNamespace(api=types.SimpleNamespace(_session_lock=lock))
        observed = []
        def callback():
            observed.append(lock._is_owned())
            return "ok"
        self.assertEqual(serialize(coordinator, callback), "ok")
        self.assertEqual(observed, [True])

    def test_api_call_without_lock_uses_safe_fallback(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        method = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_call_api_serialized"
        )
        module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
        namespace = {"nullcontext": nullcontext}
        exec(compile(module, str(SOURCE), "exec"), namespace)
        coordinator = types.SimpleNamespace(api=types.SimpleNamespace())
        self.assertEqual(namespace["_call_api_serialized"](coordinator, lambda: 42), 42)


class FaultInjectionTests(unittest.TestCase):
    def test_opt_in_failure_is_consumed_once(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        methods = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name in {"_call_api_serialized", "arm_test_connection_failure"}
        ]
        self.assertEqual(len(methods), 2)
        module = ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[]))
        namespace = {
            "nullcontext": nullcontext,
            "APIConnectionError": APIConnectionError,
            "_LOGGER": logging.getLogger(__name__),
        }
        exec(compile(module, str(SOURCE), "exec"), namespace)
        coordinator = types.SimpleNamespace(
            api=types.SimpleNamespace(_session_lock=threading.RLock()),
            _test_connection_failure_armed=False,
        )
        coordinator.arm_test_connection_failure = lambda: namespace[
            "arm_test_connection_failure"
        ](coordinator)

        def get_devices():
            return ["device"]

        self.assertEqual(
            namespace["_call_api_serialized"](coordinator, get_devices), ["device"]
        )
        coordinator.arm_test_connection_failure()
        with self.assertRaisesRegex(APIConnectionError, "Synthetic"):
            namespace["_call_api_serialized"](coordinator, get_devices)
        self.assertFalse(coordinator._test_connection_failure_armed)
        self.assertEqual(
            namespace["_call_api_serialized"](coordinator, get_devices), ["device"]
        )


class ConnectionRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.retry_method = staticmethod(load_retry_method())

    def run_poll(self, responses):
        calls = []
        iterator = iter(responses)

        def get_devices():
            calls.append("fetch")
            result = next(iterator)
            if isinstance(result, Exception):
                raise result
            return result

        async def run_in_executor(func, *args):
            if func is time.sleep:
                return None
            return func(*args)

        coordinator = types.SimpleNamespace(
            api=types.SimpleNamespace(get_devices=get_devices),
            hass=types.SimpleNamespace(async_add_executor_job=run_in_executor),
            _call_api_serialized=lambda method: method(),
        )
        return coordinator, calls

    def test_successful_request_not_retried(self):
        coordinator, calls = self.run_poll([["device"]])
        result = asyncio.run(self.retry_method(coordinator))
        self.assertEqual(result, ["device"])
        self.assertEqual(len(calls), 1)

    def test_transient_failure_retried_once(self):
        coordinator, calls = self.run_poll([
            APIConnectionError("Connection reset by peer"), ["device"]
        ])
        result = asyncio.run(self.retry_method(coordinator))
        self.assertEqual(result, ["device"])
        self.assertEqual(len(calls), 2)

    def test_persistent_connection_failure_propagates_after_two_attempts(self):
        coordinator, calls = self.run_poll([
            APIConnectionError("Disconnected"), APIConnectionError("Disconnected")
        ])
        with self.assertRaises(APIConnectionError):
            asyncio.run(self.retry_method(coordinator))
        self.assertEqual(len(calls), 2)

    def test_authentication_failure_is_not_retried(self):
        coordinator, calls = self.run_poll([APIAuthError("Expired session")])
        with self.assertRaises(APIAuthError):
            asyncio.run(self.retry_method(coordinator))
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
