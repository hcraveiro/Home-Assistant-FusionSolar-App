from typing import Any

from .models import DeviceType


DEVICES = [
    {"id": "House Load Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "House Load Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "Panel Production Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Panel Production Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:solar-panel"},
    {"id": "Self Consumption Ratio Today", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Week", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Month", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Year", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio Lifetime", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Today", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Week", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Month", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Year", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Self Consumption Ratio By Production Lifetime", "type": DeviceType.SENSOR_RATIO, "icon": "mdi:percent-outline"},
    {"id": "Battery Consumption Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging-100"},
    {"id": "Battery Injection Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Battery Injection Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:battery-charging"},
    {"id": "Grid Consumption Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Consumption Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-export"},
    {"id": "Grid Injection Power", "type": DeviceType.SENSOR_KW, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Today", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Week", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Month", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Year", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Grid Injection Lifetime", "type": DeviceType.SENSOR_KWH, "icon": "mdi:transmission-tower-import"},
    {"id": "Battery Percentage", "type": DeviceType.SENSOR_PERCENTAGE, "icon": ""},
    {"id": "Battery Capacity", "type": DeviceType.SENSOR_KW, "icon": "mdi:home-lightning-bolt-outline"},
    {"id": "Standard Coal Saved", "type": DeviceType.SENSOR_KG, "icon": "mdi:mine"},
    {"id": "Standard Coal Saved This Year", "type": DeviceType.SENSOR_KG, "icon": "mdi:mine"},
    {"id": "CO2 Avoided", "type": DeviceType.SENSOR_KG, "icon": "mdi:molecule-co2"},
    {"id": "CO2 Avoided This Year", "type": DeviceType.SENSOR_KG, "icon": "mdi:molecule-co2"},
    {"id": "Equivalent Trees Planted", "type": DeviceType.SENSOR_COUNT, "icon": "mdi:tree"},
    {"id": "Equivalent Trees Planted This Year", "type": DeviceType.SENSOR_COUNT, "icon": "mdi:tree"},
    {"id": "Last Authentication Time", "type": DeviceType.SENSOR_TIME, "icon": "mdi:clock-outline"},
]

BATTERY_MODULE_1_SIGNAL_IDS = [
    230320252,  # [Module 1] No.
    230320459,  # [Module 1] [DC/DC] Working status
    230320275,  # [Module 1] [DC/DC] SN
    230320146,  # [Module 1] [DC/DC] Software version
    230320463,  # [Module 1] [DC/DC] SOC
    230320473,  # [Module 1] [DC/DC] Charge and discharge power
    230320462,  # [Module 1] [DC/DC] Internal temperature
    230320469,  # [Module 1] [DC/DC] Daily charge energy
    230320470,  # [Module 1] [DC/DC] Daily discharge energy
    230320108,  # [Module 1] Total discharge energy
    230320107,  # [Module 1] Total charge energy
    230320460,  # [Module 1] [DC/DC] Bus voltage
    230320461,  # [Module 1] [DC/DC] Bus current
    230320514,  # [Module 1] Battery pack quantity
    230320265,  # [Module 1] [Battery pack 1] No.
    230320266,  # [Module 1] [Battery pack 2] No.
    230320267,  # [Module 1] [Battery pack 3] No.
    230320148,  # [Module 1] [Battery pack 1] SN
    230320165,  # [Module 1] [Battery pack 2] SN
    230320181,  # [Module 1] [Battery pack 3] SN
    230320147,  # [Module 1] [Battery pack 1] Software version
    230320164,  # [Module 1] [Battery pack 2] Software version
    230320180,  # [Module 1] [Battery pack 3] Software version
    230320151,  # [Module 1] [Battery pack 1] Operating status
    230320168,  # [Module 1] [Battery pack 2] Operating status
    230320184,  # [Module 1] [Battery pack 3] Operating status
    230320159,  # [Module 1] [Battery pack 1] Voltage
    230320174,  # [Module 1] [Battery pack 2] Voltage
    230320190,  # [Module 1] [Battery pack 3] Voltage
    230320158,  # [Module 1] [Battery pack 1] Charge/Discharge power
    230320173,  # [Module 1] [Battery pack 2] Charge/Discharge power
    230320189,  # [Module 1] [Battery pack 3] Charge/Discharge power
    230320446,  # [Module 1] [Battery pack 1] Maximum temperature
    230320448,  # [Module 1] [Battery pack 2] Maximum temperature
    230320450,  # [Module 1] [Battery pack 3] Maximum temperature
    230320447,  # [Module 1] [Battery pack 1] Minimum temperature
    230320449,  # [Module 1] [Battery pack 2] Minimum temperature
    230320451,  # [Module 1] [Battery pack 3] Minimum temperature
    230320152,  # [Module 1] [Battery pack 1] SOC
    230320169,  # [Module 1] [Battery pack 2] SOC
    230320185,  # [Module 1] [Battery pack 3] SOC
    230320163,  # [Module 1] [Battery pack 1] Total discharge energy
    230320179,  # [Module 1] [Battery pack 2] Total discharge energy
    230320194,  # [Module 1] [Battery pack 3] Total discharge energy
    230320492,  # [Module 1] [Battery pack 1] Battery Health Check
    230320493,  # [Module 1] [Battery pack 2] Battery Health Check
    230320494,  # [Module 1] [Battery pack 3] Battery Health Check
    230320498,  # [Module 1] [Battery pack 1] Heating Status
    230320499,  # [Module 1] [Battery pack 2] Heating Status
    230320500,  # [Module 1] [Battery pack 3] Heating Status
    230320154,  # [Module 1] [Battery pack 1] SOH
    230320170,  # [Module 1] [Battery pack 2] SOH
    230320186,  # [Module 1] [Battery pack 3] SOH
    230320663,  # [Module 1] [Battery pack 1] Data collection status
    230320664,  # [Module 1] [Battery pack 2] Data collection status
    230320665,  # [Module 1] [Battery pack 3] Data collection status
]

BASE_INVERTER_SIGNAL_MAP = {
    10008: {"id": "Inverter Grid Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10011: {"id": "Inverter Phase A Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10012: {"id": "Inverter Phase B Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10013: {"id": "Inverter Phase C Voltage", "type": DeviceType.SENSOR_VOLTAGE, "icon": "mdi:flash"},
    10014: {"id": "Inverter Grid Current", "type": DeviceType.SENSOR_CURRENT, "icon": "mdi:current-ac"},
    10015: {"id": "Inverter Phase B Current", "type": DeviceType.SENSOR_CURRENT, "icon": "mdi:current-ac"},
    10016: {"id": "Inverter Phase C Current", "type": DeviceType.SENSOR_CURRENT, "icon": "mdi:current-ac"},
    10021: {"id": "Inverter Grid Frequency", "type": DeviceType.SENSOR_FREQUENCY, "icon": "mdi:sine-wave"},
    10023: {"id": "Inverter Internal Temperature", "type": DeviceType.SENSOR_TEMPERATURE, "icon": "mdi:thermometer"},
    10024: {"id": "Inverter Insulation Resistance", "type": DeviceType.SENSOR_RESISTANCE, "icon": "mdi:omega"},
    10020: {"id": "Inverter Power Factor", "type": DeviceType.SENSOR_POWER_FACTOR, "icon": "mdi:angle-acute"},
    10025: {"id": "Inverter Status", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:information-outline"},
    10027: {"id": "Inverter Startup Time", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:clock-outline"},
    10028: {"id": "Inverter Last Shutdown Time", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:clock-outline"},
    21029: {"id": "Inverter Output Mode", "type": DeviceType.SENSOR_TEXT, "icon": "mdi:transmission-tower"},
}


def _build_dynamic_pv_signal_map(max_pv_inputs: int = 20) -> dict[int, dict[str, Any]]:
    """Build PV voltage/current/power signal definitions dynamically."""
    signal_map: dict[int, dict[str, Any]] = {}

    for pv_index in range(1, max_pv_inputs + 1):
        base_signal_id = 11001 + ((pv_index - 1) * 3)
        signal_map[base_signal_id] = {
            "id": f"Inverter PV{pv_index} Voltage",
            "type": DeviceType.SENSOR_VOLTAGE,
            "icon": "mdi:solar-panel",
        }
        signal_map[base_signal_id + 1] = {
            "id": f"Inverter PV{pv_index} Current",
            "type": DeviceType.SENSOR_CURRENT,
            "icon": "mdi:solar-panel",
        }
        signal_map[base_signal_id + 2] = {
            "id": f"Inverter PV{pv_index} Power",
            "type": DeviceType.SENSOR_KW,
            "icon": "mdi:solar-panel",
        }

    return signal_map


def get_inverter_signal_map() -> dict[int, dict[str, Any]]:
    """Return the complete inverter signal definition map."""
    return {**BASE_INVERTER_SIGNAL_MAP, **_build_dynamic_pv_signal_map()}
