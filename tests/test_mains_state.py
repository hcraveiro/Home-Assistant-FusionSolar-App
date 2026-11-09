"""Strict mains identity and sampling regression (Off is synthetic only)."""
import copy
import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

PATH = Path(__file__).resolve().parents[1] / 'custom_components/fusion_solar_app/api/mains.py'
spec = importlib.util.spec_from_file_location('mains_test', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_historical_sanitized_association_fixture():
    fixture = json.loads((Path(__file__).parent / 'fixtures/mains-state-provenance.json').read_text())
    dn = module.discover_mains_dn([fixture['flow']['node']])
    assert dn == 'MAINS_DEVICE_A' and dn != fixture['flow']['node']['id']
    assert module.parse_mains_state({'code': fixture['sampling']['code'], 'data': {
        'rootDevTypeId': fixture['sampling']['rootDevTypeId'],
        'displayList': [fixture['sampling']['row']]}}, dn) is True


def node(dns=None):
    return {'name': 'neteco.pvms.pcs.station.energyflow.mains', 'mocId': 60001,
            'id': '8', 'devIds': ['MAINS_DEVICE_A'] if dns is None else dns,
            'description': {'value': '0.00kW'}}


def sample(value='1'):
    return {'code': 0, 'data': {'rootDevTypeId': 36892, 'displayList': [
        {'id': 10001, 'mocId': 10001, 'dataType': 'ENUM', 'signalType': 'DI',
         'typeId': 36892, 'dn': 'MAINS_DEVICE_A', 'value': value,
         'enumList': {'0': 'Mains Off', '1': 'Mains On'}}]}}


@pytest.mark.parametrize('value,expected', [('1', True), ('0', False), (1, True), (0, False),
    (None, None), (True, None), (False, None), (' 1', None), ('on', None), (1.0, None), ('', None)])
def test_strict_state(value, expected):
    assert module.parse_mains_state(sample(value), 'MAINS_DEVICE_A') is expected


@pytest.mark.parametrize('mutation', ['root', 'dn', 'type', 'duplicate', 'id', 'moc', 'enum', 'signal', 'code'])
def test_rejects_unverified_response(mutation):
    response = copy.deepcopy(sample())
    row = response['data']['displayList'][0]
    if mutation == 'root': response['data']['rootDevTypeId'] = 37895
    if mutation == 'dn': row['dn'] = '8'
    if mutation == 'type': row['typeId'] = 37895
    if mutation == 'duplicate': response['data']['displayList'].append(copy.deepcopy(row))
    if mutation == 'id': row['id'] = 10002
    if mutation == 'moc': row['mocId'] = 10002
    if mutation == 'enum': row['dataType'] = 'FLOAT'
    if mutation == 'signal': row['signalType'] = 'AI'
    if mutation == 'code': response['code'] = False
    assert module.parse_mains_state(response, 'MAINS_DEVICE_A') is None


@pytest.mark.parametrize('nodes,expected', [([node()], 'MAINS_DEVICE_A'),
    ([node([])], None), ([node(['A', 'B'])], None), ([node(), node()], None),
    ([node([None])], None), ([], None)])
def test_discovery(nodes, expected):
    assert module.discover_mains_dn(nodes) == expected


@pytest.mark.parametrize('verified', [False, True])
def test_optional_discovery_bounded_and_isolated(verified):
    calls = []
    api = SimpleNamespace(_is_isitepower_m=verified, station='STATION_A', csrf='x',
                          data_host='example.invalid', refresh_csrf=lambda: None)
    def request(method, url, **kwargs):
        calls.append((method, kwargs))
        return None, {'success': True, 'failCode': 0, 'data': {'flow': {'nodes': []}}}
    api._request_json = request
    module.refresh_mains(api, [])
    module.refresh_mains(api, [])
    assert len(calls) == (1 if verified else 0)
    assert api._mains_state is None


@pytest.mark.parametrize('response', [None, {}, {'success': False, 'failCode': 0},
    {'success': True, 'failCode': False}, {'success': True, 'failCode': 1},
    {'success': True, 'failCode': 0, 'data': {'flow': {'nodes': [node(), node()]}}}])
def test_v3_failure_does_not_sample_or_synthesize_off(response):
    calls = []
    api = SimpleNamespace(_is_isitepower_m=True, station='STATION_A', csrf='x',
                          data_host='example.invalid', refresh_csrf=lambda: None)
    def request(method, *a, **k):
        calls.append(method)
        return None, response
    api._request_json = request
    module.refresh_mains(api, [])
    assert calls == ['GET']
    assert api._mains_state is None


def test_missing_dn_probe_retries_at_hour_boundary_then_stops_after_success(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    calls = []
    discoveries = [[], [], [node()]]
    api = SimpleNamespace(_is_isitepower_m=True, station='STATION_A', csrf='x',
                          data_host='example.invalid', refresh_csrf=lambda: None)
    def request(method, *args, **kwargs):
        calls.append(method)
        if method == 'GET':
            return None, {'success': True, 'failCode': 0,
                          'data': {'flow': {'nodes': discoveries.pop(0)}}}
        return None, sample()
    api._request_json = request
    for now, expected_gets in [(100, 1), (3699.999, 1), (3700, 2),
                               (7299.999, 2), (7300, 3), (10900, 3)]:
        clock[0] = now
        module.refresh_mains(api, [])
        assert calls.count('GET') == expected_gets
        assert api._mains_state is (True if now >= 7300 else None)
    assert calls == ['GET', 'GET', 'GET', 'POST', 'POST']
    assert api._mains_dn == 'MAINS_DEVICE_A'


def test_real_v3_shape_supplies_only_identity_and_caches_dn():
    calls = []
    api = SimpleNamespace(_is_isitepower_m=True, station='STATION_A', csrf='x',
                          data_host='example.invalid', refresh_csrf=lambda: None)
    def request(method, *a, **k):
        calls.append((method, k))
        if method == 'GET':
            return None, {'success': True, 'failCode': 0, 'data': {'flow': {'nodes': [node()]}}}
        return None, sample()
    api._request_json = request
    module.refresh_mains(api, [])
    assert api._mains_state is True
    assert calls[0][1]['params'] == {'stationDn': 'STATION_A', 'featureId': 'aifc'}
    assert all(call[1]['optional'] is True for call in calls)
    module.refresh_mains(api, [])
    assert [c[0] for c in calls] == ['GET', 'POST', 'POST']


def test_zero_power_on_then_http_failure_and_recovery():
    api = SimpleNamespace(_is_isitepower_m=True, station='STATION_A', csrf='x',
                          data_host='example.invalid', refresh_csrf=lambda: None)
    api._request_json = lambda *a, **k: (None, sample())
    module.refresh_mains(api, [node()])
    assert api._mains_state is True
    def failed(*a, **k):
        raise RuntimeError('HTTP failure/closed API')
    api._request_json = failed
    module.refresh_mains(api, [node()])
    assert api._mains_state is None
    api._request_json = lambda *a, **k: (None, sample('0'))
    module.refresh_mains(api, [node()])
    assert api._mains_state is False
    module.refresh_mains(api, [node(), node()])
    assert api._mains_dn is None and api._mains_state is None


def test_reader_form_and_recovery():
    calls = []
    api = SimpleNamespace(csrf='csrf', data_host='example.invalid', refresh_csrf=lambda: None)
    response = sample()
    def request(*args, **kwargs):
        calls.append((args, kwargs))
        return None, response
    api._request_json = request
    assert module.fetch_mains_state(api, 'MAINS_DEVICE_A') is True
    assert calls[0][1]['optional'] is True
    assert calls[0][1]['data']['samplingSigQueryCon.dn'] == 'MAINS_DEVICE_A'
    assert calls[0][1]['data']['samplingSigQueryCon.pageSize'] == '10'
    response['data']['displayList'][0]['value'] = '0'
    assert module.fetch_mains_state(api, 'MAINS_DEVICE_A') is False
    response['code'] = 1
    assert module.fetch_mains_state(api, 'MAINS_DEVICE_A') is None
    response['code'] = 0
    assert module.fetch_mains_state(api, 'MAINS_DEVICE_A') is False
