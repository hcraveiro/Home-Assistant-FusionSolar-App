"""Offline real-transport energy pacing regression tests."""
from test_auth_transport_behavior import auth_module, make_api, make_response
import pytest
import threading
from concurrent.futures import ThreadPoolExecutor


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def clock(auth_module, monkeypatch):
    clock = Clock()
    # Replace the module's clock, not the process-wide time module.
    monkeypatch.setattr(auth_module, "time", clock)
    return clock


def request(api, module, kind="MONTH"):
    return api._request_json("GET", "https://example.test/rest/pvms/web/station/v2/overview/energy-balance"
                             + "?timeDim=" + kind, context="energy")


def test_all_periods_start_at_least_two_seconds_apart(auth_module, clock):
    api = make_api(auth_module, make_response())
    starts = []
    api.session.request.side_effect = lambda *a, **k: (starts.append(clock.now) or make_response())
    for kind in ("MONTH", "DAY", "DAY", "PREVIOUS_MONTH", "YEAR", "LIFETIME"):
        request(api, auth_module, kind)
    assert starts == [0, 2, 4, 6, 8, 10]
    assert clock.sleeps == [2] * 5  # No initial or trailing pause, even at clock zero.


def test_failure_counts_slow_response_needs_no_extra_wait(auth_module, clock):
    api = make_api(auth_module, make_response(418))
    with pytest.raises(auth_module.APIConnectionError):
        request(api, auth_module)
    api.session.request.return_value = make_response()
    request(api, auth_module, "DAY")
    assert clock.now == 2
    clock.now += 3
    request(api, auth_module, "YEAR")
    assert clock.sleeps == [2]


def test_concurrent_calls_share_transport_lock(auth_module, clock):
    api = make_api(auth_module, make_response())
    starts = []
    barrier = threading.Barrier(4)
    api.session.request.side_effect = lambda *a, **k: (starts.append(clock.now) or make_response())

    def worker():
        barrier.wait(timeout=5)
        request(api, auth_module)

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(worker) for _ in range(4)]
        for future in futures:
            future.result(timeout=5)
    assert starts == [0, 2, 4, 6]


def test_instances_non_energy_and_closed_are_independent(auth_module, clock):
    first = make_api(auth_module, make_response())
    second = make_api(auth_module, make_response())
    request(first, auth_module)
    request(second, auth_module)
    first._request_json("GET", "https://example.test/device", context="device")
    assert clock.sleeps == []
    first._closed = True
    with pytest.raises(auth_module.APIConnectionError):
        request(first, auth_module)
    assert first.session.request.call_count == 2
    assert clock.sleeps == []
