#!/usr/bin/env python3
"""Actual HA binary platform, offline HTTP replay. Off is synthetic, not field evidence."""
from __future__ import annotations
import asyncio
from copy import deepcopy
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from check_runtime_homeassistant import ROOT, DOMAIN, require


def mains_profile(load_profile):
    profile = load_profile('isitepower-mains-import')
    profile['id'] = 'synthetic-mains-disposable'
    profile['title'] = 'MOCK disposable mains transitions'
    profile['origin'] = 'synthetic'
    dn = 'MOCK_RUNTIME_MAINS_A'
    for route in profile['routes']:
        if '/v3/' in route['path']:
            route['body']['data']['flow']['nodes'] = [{
                'mocId': 60001, 'id': '8', 'name': 'neteco.pvms.pcs.station.energyflow.mains',
                'devIds': [dn], 'display': 'CONNECTED', 'description': {'value': '0.00kW'}}]
        elif route['path'].endswith('energy-flow'):
            for node in route['body']['data']['flow']['nodes']:
                if node.get('mocId') == 60001:
                    node['description']['value'] = '0.00kW'
    sampling = {'method': 'POST', 'path': '/rest/neteco/monitor/v1/signal/common/sampling-signal',
                'params': {}, 'json': None, 'status': 200,
                'body': {'code': 0, 'data': {'rootDevTypeId': 36892, 'displayList': [{
                    'id': 10001, 'mocId': 10001, 'typeId': 36892, 'dn': dn,
                    'dataType': 'ENUM', 'signalType': 'DI', 'value': '1'}]}}}
    # Mock router matches exact form bodies, just like the production reader.
    sampling['data'] = {'samplingSigQueryCon.dn': dn, 'samplingSigQueryCon.pageSize': '10',
        'samplingSigQueryCon.pageIndex': '1', 'queryScene.businessDevice': '0',
        'queryScene.bindQuery': 'false', 'queryScene.queryAODO': 'false',
        'filterParams.name': '', 'filterParams.displayGroup': '', 'filterParams.signalType': 'AI;DI;AO;DO;OTHER'}
    index = len(profile['routes'])
    profile['routes'].append(sampling)
    profile['frames'] = []
    for name, value in [('on-zero-power', '1'), ('off-synthetic', '0'), ('garbage', None),
                        ('permission-error', '1'), ('recovery', '1')]:
        body = deepcopy(sampling['body'])
        body['data']['displayList'][0]['value'] = value
        profile['frames'].append({'id': name, 'responses': [{'route': index, 'body': body,
            'status': 403 if name == 'permission-error' else 200}]})
    return profile


async def run():
    from homeassistant import loader
    from homeassistant.bootstrap import async_load_base_functionality
    from homeassistant.config_entries import ConfigEntries, ConfigEntryState
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import entity_registry as er
    from custom_components.fusion_solar_app.mock_profile import load_profile
    os.environ['FUSIONSOLAR_DEV_PROFILE_DIR'] = str(ROOT / 'tests/fixtures/runtime_profiles')
    profile = mains_profile(load_profile)
    initial = deepcopy(profile['frames'][0])
    initial['id'] = 'initial-invalid'
    initial['responses'][0]['body']['data']['displayList'][0]['value'] = None
    profile['frames'].insert(0, initial)
    with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
        root = Path(tmp)
        (root / 'profiles').mkdir()
        (root / 'profiles' / f"{profile['id']}.json").write_text(json.dumps(profile))
        os.environ['FUSIONSOLAR_DEV_PROFILE_DIR'] = str(root / 'profiles')
        (root / 'custom_components').symlink_to(ROOT / 'custom_components', target_is_directory=True)
        hass = HomeAssistant(tmp)
        hass.config.skip_pip = True
        hass.config.time_zone = 'UTC'
        hass.config.latitude = hass.config.longitude = 0
        loader.async_setup(hass)
        hass.config_entries = ConfigEntries(hass, {})
        try:
            with patch('requests.sessions.Session.send', side_effect=AssertionError('Network forbidden')):
                require(await async_load_base_functionality(hass), 'Base HA setup')
                await hass.async_start()
                result = await hass.config_entries.flow.async_init(DOMAIN, context={'source': 'mock'})
                result = await hass.config_entries.flow.async_configure(result['flow_id'], {'mock_profile': profile['id']})
                require(result['type'] == 'create_entry', str(result))
                entry = result['result']
                await hass.async_block_till_done()
                require(entry.state is ConfigEntryState.LOADED, str(entry.reason))
                coordinator = hass.data[DOMAIN][entry.entry_id].coordinator
                api = coordinator.api
                report = []
                entity_id = None
                for i, expected in enumerate([None, 'on', 'off', 'unavailable', 'unavailable', 'on']):
                    if i:
                        api.queue_frame('advance')
                        await coordinator.async_refresh()
                        await hass.async_block_till_done()
                    entities = [e for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
                                if e.domain == 'binary_sensor']
                    if expected is None:
                        require(not entities, 'Invalid initial sampling created an unverified binary entity')
                        require(api._mains_state is None and coordinator.last_update_success,
                                'Invalid optional initial sample failed the main poll')
                        report.append({'frame': api.frame_id, 'state': 'not_created', 'registered_binary_entities': 0})
                        continue
                    require(len(entities) == 1, f'Expected one mains entity: {entities}')
                    require(entity_id is None or entity_id == entities[0].entity_id, 'Identity changed')
                    entity_id = entities[0].entity_id
                    state = hass.states.get(entity_id)
                    require(state.state == expected, f'{api.frame_id}: {state.state} != {expected}')
                    require(state.attributes['device_class'] == 'connectivity', 'Wrong class')
                    require(coordinator.last_update_success and not api.unexpected_requests, 'Poll isolation')
                    report.append({'frame': api.frame_id, 'state': state.state})
                # A second account for the identical station must own distinct
                # entities, devices and parent links through the b20 resolver.
                from homeassistant.config_entries import ConfigEntry
                from homeassistant.helpers import device_registry as dr
                from types import MappingProxyType
                other = ConfigEntry(version=1, minor_version=1, domain=DOMAIN, source='user',
                    title='MOCK second mains account', unique_id='MOCK_RUNTIME_SECOND_MAINS_ACCOUNT',
                    data={**entry.data, 'username': 'MOCK_RUNTIME_SECOND_ACCOUNT'}, options={},
                    discovery_keys=MappingProxyType({}), subentries_data=[])
                await hass.config_entries.async_add(other)
                await hass.async_block_till_done()
                require(other.state is ConfigEntryState.LOADED, 'Second account setup')
                other_coordinator = hass.data[DOMAIN][other.entry_id].coordinator
                require(not [e for e in er.async_entries_for_config_entry(er.async_get(hass), other.entry_id)
                             if e.domain == 'binary_sensor'], 'Second account initially unverified entity created')
                other_coordinator.api.queue_frame('advance')
                await other_coordinator.async_refresh()
                await hass.async_block_till_done()
                second = [e for e in er.async_entries_for_config_entry(er.async_get(hass), other.entry_id)
                          if e.domain == 'binary_sensor']
                require(len(second) == 1, 'Second account binary sensor missing')
                first = er.async_get(hass).async_get(entity_id)
                require(first.unique_id != second[0].unique_id and first.device_id != second[0].device_id,
                        'Same-station account identity collision')
                registry = dr.async_get(hass)
                first_device = registry.async_get(first.device_id)
                second_device = registry.async_get(second[0].device_id)
                require(first_device.via_device_id != second_device.via_device_id,
                        'Same-station parent device collision')
                require(await hass.config_entries.async_unload(other.entry_id), 'Second unload failed')
                require(hass.states.get(entity_id).state == 'on', 'Second unload affected first account')
                require(await hass.config_entries.async_unload(entry.entry_id), 'Unload failed')
                await hass.async_block_till_done()
                remaining = hass.states.get(entity_id)
                require(remaining is None or remaining.state == 'unavailable', 'Binary platform retained active state after unload')
                require(entry.entry_id not in hass.data.get(DOMAIN, {}), 'Runtime retained after unload')
                require(api._closed, 'API not closed after platform unload')
                print(json.dumps({'status': 'passed', 'frames': report, 'platform_unloaded': True}))
        finally:
            for entry in hass.config_entries.async_entries(DOMAIN):
                if entry.state is ConfigEntryState.LOADED:
                    await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_stop(force=True)
            await hass.async_block_till_done()

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    asyncio.run(run())
