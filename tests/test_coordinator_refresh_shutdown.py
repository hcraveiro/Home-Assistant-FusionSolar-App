"""Fast complete-refresh lock regressions; real-HA race is checked separately."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from test_coordinator_full_behavior import coordinator, coordinator_module  # noqa: F401


@pytest.mark.asyncio
async def test_shutdown_drains_async_retry_gap_and_rejects_queued_work(
    coordinator, coordinator_module, monkeypatch,
):
    module = coordinator_module
    coordinator._update_lock = asyncio.Lock()
    coordinator._shutdown_requested = False
    entered, release, shutdown_started = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def active_update():
        entered.set()
        await release.wait()
        return "MOCK_RUNTIME data"

    async def base_shutdown(self):
        self._shutdown_requested = True
        shutdown_started.set()

    monkeypatch.setattr(module.DataUpdateCoordinator, "async_shutdown", base_shutdown, raising=False)
    coordinator.async_update_data = AsyncMock(side_effect=active_update)
    active = asyncio.create_task(coordinator._async_update_data_locked())
    await asyncio.wait_for(entered.wait(), 1)
    queued = asyncio.create_task(coordinator._async_update_data_locked())
    shutdown = asyncio.create_task(coordinator.async_shutdown())
    try:
        await asyncio.wait_for(shutdown_started.wait(), 1)
        assert not shutdown.done()
        release.set()
        assert await asyncio.wait_for(active, 1) == "MOCK_RUNTIME data"
        with pytest.raises(module.UpdateFailed, match="shutting down"):
            await asyncio.wait_for(queued, 1)
        await asyncio.wait_for(shutdown, 1)
        coordinator.async_update_data.assert_awaited_once()
        with pytest.raises(module.UpdateFailed, match="shutting down"):
            await coordinator._async_update_data_locked()
        await coordinator.async_shutdown()  # HA may invoke the unload callback too.
    finally:
        release.set()
        await asyncio.gather(active, queued, shutdown, return_exceptions=True)


@pytest.mark.asyncio
async def test_refresh_lock_is_released_on_failure(coordinator, coordinator_module):
    module = coordinator_module
    coordinator._update_lock = asyncio.Lock()
    coordinator._shutdown_requested = False
    coordinator.async_update_data = AsyncMock(side_effect=[module.UpdateFailed("temporary"), "recovered"])
    with pytest.raises(module.UpdateFailed, match="temporary"):
        await coordinator._async_update_data_locked()
    assert not coordinator._update_lock.locked()
    assert await asyncio.wait_for(coordinator._async_update_data_locked(), 1) == "recovered"
