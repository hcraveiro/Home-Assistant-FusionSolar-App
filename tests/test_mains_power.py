"""Mains power uses independent, identity-verified sampling rows."""
import copy
from pathlib import Path
import pytest
from test_mains_state import module, sample, node
from types import SimpleNamespace


def test_historical_fixture():
    import json
    fixture = json.loads((Path(__file__).parent / 'fixtures/mains-power-provenance.json').read_text())
    response = {'code': 0, 'data': {'rootDevTypeId': fixture['rootDevTypeId'],
                                 'displayList': [fixture['row']]}}
    assert module.parse_mains_power(response, 'MAINS_DEVICE_A') == 0


def power(value='0.000'):
    response = sample()
    response['data']['displayList'].append(dict(id=10010, mocId=10010,
        typeId=36892, dataType='FLOAT', dn='MAINS_DEVICE_A', value=value, unit='kW'))
    return response


@pytest.mark.parametrize('value,expected', [('0.000', 0), ('2.345', 2.345),
    ('-1.2', -1.2), (0, 0), (True, None), (False, None), (None, None),
    ('NaN', None), ('inf', None), (float('inf'), None), ('bad', None), ('', None)])
def test_numeric(value, expected):
    assert module.parse_mains_power(power(value), 'MAINS_DEVICE_A') == expected


@pytest.mark.parametrize('field,value', [('dn', 'other'), ('typeId', 1),
    ('mocId', 1), ('id', 1), ('dataType', 'ENUM'), ('unit', 'W'),
    ('unit', None), ('unit', 'garbage')])
def test_invalid_row(field, value):
    response = power()
    response['data']['displayList'][1][field] = value
    assert module.parse_mains_power(response, 'MAINS_DEVICE_A') is None
    assert module.parse_mains_state(response, 'MAINS_DEVICE_A') is True


@pytest.mark.parametrize('mutation', ['duplicate', 'root', 'code', 'missing'])
def test_invalid_response(mutation):
    response = power()
    if mutation == 'duplicate': response['data']['displayList'].append(copy.deepcopy(response['data']['displayList'][1]))
    if mutation == 'root': response['data']['rootDevTypeId'] = 1
    if mutation == 'code': response['code'] = False
    if mutation == 'missing': response['data']['displayList'].pop()
    assert module.parse_mains_power(response, 'MAINS_DEVICE_A') is None


def test_shared_request_independence_and_failure():
    calls = []
    response = power()
    response['data']['displayList'][0]['value'] = 'invalid'
    api = SimpleNamespace(_is_isitepower_m=True, station='STATION_A', csrf='x',
        data_host='example.invalid', refresh_csrf=lambda: None)
    def request(*args, **kwargs):
        calls.append(args)
        return None, response
    api._request_json = request
    module.refresh_mains(api, [node()])
    assert len(calls) == 1
    assert api._mains_state is None and api._mains_active_power == 0
    response['data']['displayList'][0]['value'] = '0'  # synthetic Off only
    module.refresh_mains(api, [node()])
    assert api._mains_state is False and api._mains_active_power == 0
    response['data']['displayList'][1]['value'] = None
    module.refresh_mains(api, [node()])
    assert api._mains_state is False and api._mains_active_power is None
    response['code'] = 1
    module.refresh_mains(api, [node()])
    assert api._mains_state is None and api._mains_active_power is None
