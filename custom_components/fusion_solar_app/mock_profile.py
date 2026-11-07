"""Opt-in runtime HTTP profiles. Pure stdlib; never imports HA or the API.

Profiles are external developer data, not integration package resources. Missing or
invalid opt-in never enables the mock backend. All identities must be fictional.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from copy import deepcopy

PROFILE_DIR_ENV = "FUSIONSOLAR_DEV_PROFILE_DIR"
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
FICTIONAL_PREFIX = "MOCK_RUNTIME_"
READ_ONLY_POST_PATHS = frozenset({
    "/rest/pvms/web/station/v1/station/station-list",
    "/rest/neteco/web/config/device/v2/device-status-query",
    "/rest/pvms/web/station/v1/layout/device-tree-page",
    "/rest/pvms/web/station/v1/layout/device-sampling-data",
    "/rest/neteco/monitor/v1/signal/common/sampling-signal",
})
READ_ONLY_GET_PATHS = frozenset({
    "/rest/dpcloud/auth/v1/keep-alive",
    "/rest/pvms/web/station/v2/overview/energy-flow",
    "/rest/pvms/web/station/v3/overview/energy-flow",
    "/rest/pvms/web/station/v2/overview/energy-balance",
    "/rest/pvms/web/station/v1/station/social-contribution",
    "/rest/neteco/web/config/device/v1/children-list",
    "/rest/neteco/web/config/device/v1/config/query-moc-config-signal",
    "/rest/neteco/web/config/device/v1/moc-type-name",
    "/rest/pvms/web/device/v1/get-battery-type",
    "/rest/pvms/web/device/v1/device-realtime-data",
    "/rest/pvms/web/device/v1/device-real-kpi",
    "/rest/pvms/web/device/v1/deviceExt/get-config-signals",
    "/rest/pvms/web/device/v1/query-battery-dc",
    "/rest/pvms/web/station/v1/layout",
    "/rest/pvms/web/station/v1/layout/station-simple-devicedata",
    "/rest/pvms/web/station/v1/layout/optimizer-info",
})
_DYNAMIC = {"$timestamp_ms", "$date_midnight", "$date_epoch_ms", "$timezone_hours"}
_IDENTITY_KEYS = {
    "dn", "stationDn", "deviceDn", "inverterDn", "parentDn", "bindInverterDn",
    "devDn", "devId", "devIds", "parentDevId", "dnId", "sn", "serial", "bindNode",
    "conditionParams.parentDn", "invertDnlist", "samplingSigQueryCon.dn",
}


def _root() -> Path:
    value = os.environ.get(PROFILE_DIR_ENV)
    if not value:
        raise ValueError(f"Developer profiles require {PROFILE_DIR_ENV}")
    root = Path(value).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Developer profile root must be a directory")
    return root


def _contained(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError("Profile paths must be relative")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("Profile path escapes developer root")
    return path


def _fictional(value):
    if isinstance(value, list):
        for item in value:
            _fictional(item)
    elif not isinstance(value, str) or not value.startswith(FICTIONAL_PREFIX):
        raise ValueError("All station/device identities must start with MOCK_RUNTIME_")


def _check_identities(value):
    if isinstance(value, dict):
        # Serial numbers can also be embedded as values in signal responses.
        signal_id = str(value.get("id") or value.get("signal") or value.get("signalId") or "")
        if signal_id == "50012" or "serial number" in str(value.get("name", "")).lower():
            raw = value.get("realValue", value.get("value"))
            if raw not in (None, "", "--", "null"):
                _fictional(raw)
        for key, item in value.items():
            if key in _IDENTITY_KEYS:
                _fictional(item)
            elif key == "50012":
                _fictional(item.get("realValue", item.get("value")) if isinstance(item, dict) else item)
            elif key == "schemaData" and isinstance(item, str):
                _check_identities(json.loads(item))
            else:
                _check_identities(item)
    elif isinstance(value, list):
        for item in value:
            _check_identities(item)


def validate_profile(profile: dict) -> dict:
    """Validate a resolved profile again at the API boundary; return an owned copy."""
    profile = deepcopy(profile)
    if profile.get("schema_version") != 1 or not _ID.fullmatch(profile.get("id", "")):
        raise ValueError("Invalid runtime profile schema/id")
    if not isinstance(profile.get("title"), str) or not profile["title"].strip():
        raise ValueError("Profile title is required")
    station = profile.get("station", {})
    _fictional(station.get("dn"))
    if not str(station.get("name", "")).startswith("MOCK "):
        raise ValueError("Station name must be explicitly fictional")
    _check_identities(profile)
    routes = profile.get("routes")
    if not isinstance(routes, list) or not routes:
        raise ValueError("Profile needs HTTP routes")
    for route in routes:
        method, path = route.get("method"), route.get("path")
        if not isinstance(path, str) or not path.startswith("/rest/") or any(c in path for c in "?#"):
            raise ValueError("Invalid HTTP route path")
        if not ((method == "GET" and path in READ_ONLY_GET_PATHS)
                or (method == "POST" and path in READ_ONLY_POST_PATHS)):
            raise ValueError("Only explicitly known read-only operations are allowed")
        if path.endswith("device-sampling-data"):
            if not isinstance(route.get("json"), list):
                raise ValueError("Optimizer sampling requires an explicit fictional DN list")
            _fictional(route["json"])
        if not isinstance(route.get("params", {}), dict):
            raise ValueError("Route params must be an object")
        for key, value in route.get("params", {}).items():
            if isinstance(value, str) and value.startswith("$") and value not in _DYNAMIC:
                raise ValueError("Unknown dynamic query validator")
            allowed = {"_": "$timestamp_ms", "clientTime": "$timestamp_ms",
                       "dateStr": "$date_midnight", "queryTime": "$date_epoch_ms",
                       "timeZone": "$timezone_hours"}
            if isinstance(value, str) and value in _DYNAMIC:
                if allowed.get(key) != value:
                    raise ValueError("Dynamic validator is not allowed on this query key")
        if "body" not in route or "body_file" in route:
            raise ValueError("Runtime profile bodies must be resolved")
        if not isinstance(route.get("status", 200), int) or not 100 <= route.get("status", 200) <= 599:
            raise ValueError("Invalid HTTP response status")
    frames = profile.get("frames", [])
    if not isinstance(frames, list):
        raise ValueError("frames must be a list")
    names = set()
    for frame in frames:
        if not isinstance(frame, dict) or set(frame) - {"id", "responses", "invalidate_battery_config"}:
            raise ValueError("Invalid scenario frame fields")
        name = frame.get("id", "")
        if not isinstance(name, str) or not _ID.fullmatch(name) or name in names:
            raise ValueError("Frame IDs must be unique safe names")
        names.add(name)
        if type(frame.get("invalidate_battery_config", False)) is not bool:
            raise ValueError("Invalid cache invalidation flag")
        responses = frame.get("responses", [])
        if not isinstance(responses, list):
            raise ValueError("responses must be a list")
        seen = set()
        for response in responses:
            if not isinstance(response, dict) or set(response) - {"route", "body", "status", "exception"}:
                raise ValueError("Invalid frame response fields")
            index = response.get("route")
            if type(index) is not int or not 0 <= index < len(routes) or index in seen:
                raise ValueError("Invalid/duplicate frame route index")
            seen.add(index)
            if "exception" in response:
                if response["exception"] not in ("timeout", "connection") or set(response) != {"route", "exception"}:
                    raise ValueError("Only declared timeout/connection exceptions are supported")
            else:
                if "body" not in response or type(response.get("status", 200)) is not int or not 100 <= response.get("status", 200) <= 599:
                    raise ValueError("Frame HTTP response requires body and valid status")
    return profile


def load_profile(profile_id: str) -> dict:
    """Resolve a safe profile ID and body files strictly underneath the opt-in root."""
    if not isinstance(profile_id, str) or not _ID.fullmatch(profile_id):
        raise ValueError("Invalid developer profile ID")
    root = _root()
    profile = json.loads(_contained(root, f"{profile_id}.json").read_text(encoding="utf-8"))
    if profile.get("id") != profile_id:
        raise ValueError("Profile ID does not match its filename")
    for route in profile.get("routes", []):
        if "body_file" in route:
            if "body" in route:
                raise ValueError("Choose body or body_file, not both")
            route["body"] = json.loads(_contained(root, route.pop("body_file")).read_text(encoding="utf-8"))
    return validate_profile(profile)


def list_profiles() -> dict[str, str]:
    """List valid developer choices; missing/broken opt-in fails closed."""
    try:
        root = _root()
    except (OSError, ValueError):
        return {}
    profiles = {}
    for path in sorted(root.glob("*.json")):
        try:
            profile = load_profile(path.stem)
            profiles[profile["id"]] = profile["title"]
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            continue
    return profiles
