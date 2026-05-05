# Home Assistant FusionSolar App Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Default-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub release](https://img.shields.io/github/release/hcraveiro/Home-Assistant-FusionSolar-App.svg)](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App/releases/)

Integrate FusionSolar App into Home Assistant without requiring Kiosk mode or the Northbound API / OpenAPI.

This integration was built for FusionSolar users who only have access to the regular FusionSolar App account. If you already have access to the official Northbound API / OpenAPI, please consider using [Tijs Verkoyen's Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar).

## Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Forecast configuration](#forecast-configuration)
- [Supported hosts / regions](#supported-hosts--regions)
- [Device organization](#device-organization)
- [Sensors](#sensors)
  - [Plant / energy sensors](#plant--energy-sensors)
  - [Battery sensors](#battery-sensors)
  - [Battery module sensors](#battery-module-sensors)
  - [Battery module pack sensors](#battery-module-pack-sensors)
  - [Built-in ratio sensors](#built-in-ratio-sensors)
  - [Social contribution sensors](#social-contribution-sensors)
  - [Inverter real-time sensors](#inverter-real-time-sensors)
  - [Power sensor / power meter sensors](#power-sensor--power-meter-sensors)
  - [Diagnostic sensors](#diagnostic-sensors)
- [Card configuration](#card-configuration)
- [Optional: Home Assistant package example (extra sensors)](#optional-home-assistant-package-example-extra-sensors)
- [Example Lovelace cards (using the extra sensors)](#example-lovelace-cards-using-the-extra-sensors)
- [Solar Production Forecast](#solar-production-forecast)
  - [Forecast providers](#forecast-providers)
  - [Native forecast provider](#native-forecast-provider)
  - [Solcast forecast provider](#solcast-forecast-provider)
  - [Forecast calculation](#forecast-calculation)
  - [Forecast attributes](#forecast-attributes)
  - [Forecast cache](#forecast-cache)
  - [Forecast smoothing and outlier filtering](#forecast-smoothing-and-outlier-filtering)
  - [Recorder and database usage](#recorder-and-database-usage)
  - [Notes and limitations](#notes-and-limitations)
- [Dashboard example](#dashboard-example)
- [FAQ](#faq)
- [Credits](#credits)

## Installation

This integration can be added as a custom repository in HACS and installed from there.

After installing it in HACS, add it in Home Assistant:

**Settings → Devices & Services → Add Integration → Search for “FusionSolar App Integration”**

The integration is configured entirely through the config flow.

## Configuration

To access FusionSolar App you need a regular FusionSolar App account provided by your installer or system administrator.

You will need:

- **Username**
- **Password**
- **FusionSolar host / region**

The integration logs in using the same credentials you use in the FusionSolar App web frontend.

The default sensor update interval is **60 seconds**.  
FusionSolar App data is usually refreshed only every few minutes (commonly around 5 minutes depending on region / account / backend behaviour), but the shorter Home Assistant polling interval ensures the sensors update as soon as new data becomes available.

After configuring the integration, you can open the config entry and press **Configure** to change:

- update interval
- forecast provider
- Solcast forecast sensor, when using Solcast

> Setting a very short interval will not force FusionSolar to provide fresher data than the backend actually exposes, and may generate unnecessary load.

## Forecast configuration

The integration includes a solar production forecast for the current day.

By default, new config entries use the built-in **Native** forecast provider. This provider estimates the current day production using the recent production history stored in Home Assistant Recorder.

You can change the forecast provider from the integration options:

**Settings → Devices & Services → FusionSolar App Integration → Configure**

Available forecast providers:

| Provider | Description |
|---|---|
| `Native (last 7 days)` | Built-in statistical forecast based on the last 7 days of local production history |
| `Solcast` | Uses a Solcast forecast sensor already available in Home Assistant |

When selecting **Solcast**, the options flow will ask you to select the Solcast forecast sensor to use.

The selected Solcast sensor must expose a `detailedHourly` attribute with entries containing:

| Attribute | Description |
|---|---|
| `period_start` | Start timestamp for the forecast period |
| `pv_estimate` | Estimated PV production for that period, in kWh |

Example supported Solcast sensor:

```yaml
sensor.solcast_pv_forecast_forecast_today
```

The integration converts the selected Solcast forecast into the same internal forecast format used by the native provider. This means dashboards can keep using the same FusionSolar forecast sensor and the same ApexCharts attributes regardless of the selected provider.

## Supported hosts / regions

The integration supports a flexible host input and normalizes several common FusionSolar host formats.

You can typically enter any of the following forms:

- `eu5`
- `region01eu5`
- `uni002eu5`
- `eu5.fusionsolar.huawei.com`
- `https://eu5.fusionsolar.huawei.com`

The integration normalizes those values internally and applies the correct login flow for the region.

It also includes improved handling for:

- different regional login patterns
- session refresh / reauthentication
- login flows inferred from real FusionSolar frontend behaviour
- HAR-based validation of region-specific behaviour
- improved compatibility with current EU5 frontend login flows, while preserving legacy fallback behaviour where needed

## Device organization

This integration organizes entities into separate Home Assistant devices when the corresponding hardware is available:

- **Fusion Solar Installation**: installation-wide / plant-wide metrics
- **Fusion Solar Inverter**: inverter-specific realtime and PV string metrics
- **Fusion Solar Battery**: battery-specific metrics, module diagnostics and pack diagnostics
- **Fusion Solar Power Sensor**: power meter / power sensor technical metrics

This makes the entity model cleaner and closer to the real FusionSolar device structure.

## Sensors

After setting up the integration, the entities are organized into multiple Home Assistant devices:

- **Fusion Solar Installation**: plant-wide energy, forecast, social contribution and ratio sensors
- **Fusion Solar Inverter**: inverter real-time electrical and PV string sensors
- **Fusion Solar Battery**: battery status, battery metadata, battery module sensors and battery module pack sensors
- **Fusion Solar Power Sensor**: power meter / power sensor electrical and metering sensors

### Plant / energy sensors

These sensors belong to the **Fusion Solar Installation** device and represent plant-wide / system-wide values:

- Panels Production (kW)
- Panels Production Today (kWh)
- Panels Production Week (kWh)
- Panels Production Month (kWh)
- Panels Production Year (kWh)
- Panels Production Lifetime (kWh)

- Panels Production Consumption Today (kWh)
- Panels Production Consumption Week (kWh)
- Panels Production Consumption Month (kWh)
- Panels Production Consumption Year (kWh)
- Panels Production Consumption Lifetime (kWh)

- House Load (kW)
- House Load Today (kWh)
- House Load Week (kWh)
- House Load Month (kWh)
- House Load Year (kWh)
- House Load Lifetime (kWh)

- Battery Consumption (kW)
- Battery Consumption Today (kWh)
- Battery Consumption Week (kWh)
- Battery Consumption Month (kWh)
- Battery Consumption Year (kWh)
- Battery Consumption Lifetime (kWh)

- Battery Injection (kW)
- Battery Injection Today (kWh)
- Battery Injection Week (kWh)
- Battery Injection Month (kWh)
- Battery Injection Year (kWh)
- Battery Injection Lifetime (kWh)

- Grid Consumption (kW)
- Grid Consumption Today (kWh)
- Grid Consumption Week (kWh)
- Grid Consumption Month (kWh)
- Grid Consumption Year (kWh)
- Grid Consumption Lifetime (kWh)

- Grid Injection (kW)
- Grid Injection Today (kWh)
- Grid Injection Week (kWh)
- Grid Injection Month (kWh)
- Grid Injection Year (kWh)
- Grid Injection Lifetime (kWh)

- Last Authentication Time
- PV Forecasted Today (kWh)
- PV Remaining Today (kWh)

### Battery sensors

The battery is exposed as a dedicated Home Assistant device and includes:

- Battery Percentage (%)
- Battery Capacity
- Battery Operating Status
- Battery Charge/Discharge Mode
- Battery Backup Time
- Battery Energy Charged Today (kWh)
- Battery Energy Discharged Today (kWh)
- Battery Charge/Discharge Power (kW)
- Battery Bus Voltage (V)

The battery device also exposes hardware metadata when available from the FusionSolar frontend / API, including:

- Battery model
- Battery firmware version
- Battery serial number

### Battery module sensors

Battery module diagnostic sensors are exposed dynamically when available.

Depending on your battery system, you may see sensors such as:

- Battery Module 1 Bus Current
- Battery Module 1 Internal Temperature
- Battery Module 1 Total Charge Energy
- Battery Module 1 Total Discharge Energy

- Battery Module 2 Bus Current
- Battery Module 2 Internal Temperature
- Battery Module 2 Total Charge Energy
- Battery Module 2 Total Discharge Energy

- ...
- Battery Module N Bus Current / Internal Temperature / Total Charge Energy / Total Discharge Energy

The integration detects battery modules dynamically instead of assuming a fixed single-module layout.

### Battery module pack sensors

Battery pack diagnostic sensors are also exposed dynamically per module and per pack when available.

Depending on your battery system, you may see sensors such as:

- Battery Module 1 Pack 1 Operating Status
- Battery Module 1 Pack 1 Voltage
- Battery Module 1 Pack 1 Charge/Discharge Power
- Battery Module 1 Pack 1 Maximum Temperature
- Battery Module 1 Pack 1 Minimum Temperature
- Battery Module 1 Pack 1 SOH
- Battery Module 1 Pack 1 Total Discharge Energy
- Battery Module 1 Pack 1 Battery Health Check
- Battery Module 1 Pack 1 Heating Status

- Battery Module 1 Pack 2 Operating Status
- Battery Module 1 Pack 2 Voltage
- Battery Module 1 Pack 2 Charge/Discharge Power
- Battery Module 1 Pack 2 Maximum Temperature
- Battery Module 1 Pack 2 Minimum Temperature
- Battery Module 1 Pack 2 SOH
- Battery Module 1 Pack 2 Total Discharge Energy
- Battery Module 1 Pack 2 Battery Health Check
- Battery Module 1 Pack 2 Heating Status

- ...
- Battery Module N Pack P ...

These sensors are grouped under the dedicated battery device.

### Built-in ratio sensors

The integration includes native self-consumption ratio sensors, so you no longer need to create those manually in templates if these are the metrics you want.

#### Self consumption ratio

Share of house load covered by self-consumed solar energy:

- Self Consumption Ratio Today (%)
- Self Consumption Ratio Week (%)
- Self Consumption Ratio Month (%)
- Self Consumption Ratio Year (%)
- Self Consumption Ratio Lifetime (%)

#### Self consumption ratio by production

Share of solar production that was self-consumed instead of exported:

- Self Consumption Ratio By Production Today (%)
- Self Consumption Ratio By Production Week (%)
- Self Consumption Ratio By Production Month (%)
- Self Consumption Ratio By Production Year (%)
- Self Consumption Ratio By Production Lifetime (%)

### Social contribution sensors

The integration also exposes the social / environmental contribution values shown by FusionSolar:

- Standard Coal Saved (kg)
- Standard Coal Saved This Year (kg)
- CO2 Avoided (kg)
- CO2 Avoided This Year (kg)
- Equivalent Trees Planted
- Equivalent Trees Planted This Year

These values are taken from the same FusionSolar frontend endpoint used by the official web UI.

### Inverter real-time sensors

The inverter is exposed as a dedicated Home Assistant device.

The following sensors are fetched directly from the inverter device and require the inverter to be reachable through the API:

- Inverter Grid Voltage (V)
- Inverter Grid Current (A, phase A on 3-phase systems)
- Inverter Phase A Voltage (V)
- Inverter Phase B Voltage (V)
- Inverter Phase C Voltage (V)
- Inverter Phase B Current (A)
- Inverter Phase C Current (A)
- Inverter Grid Frequency (Hz)
- Inverter Internal Temperature (°C)
- Inverter Insulation Resistance (MΩ)
- Inverter Power Factor
- Inverter Status
- Inverter Startup Time
- Inverter Last Shutdown Time
- Inverter Output Mode

#### Dynamic PV string sensors

PV string sensors are discovered dynamically based on what the FusionSolar frontend / API actually exposes for the inverter.

This means the integration only creates the PV inputs that appear to be valid for your inverter, instead of exposing a fixed set blindly.

Depending on your inverter and API response, you may see sensors such as:

- Inverter PV1 Voltage (V)
- Inverter PV1 Current (A)
- Inverter PV1 Power (kW)

- Inverter PV2 Voltage (V)
- Inverter PV2 Current (A)
- Inverter PV2 Power (kW)

- ...
- Inverter PVN Voltage / Current / Power

The integration uses both real-time inverter endpoints and HAR-validated FusionSolar frontend behaviour to avoid exposing placeholder PV inputs that do not really exist for the device.

The inverter device also exposes hardware metadata when available from the FusionSolar frontend / API, including:

- Inverter model
- Inverter firmware version
- Inverter serial number

### Power sensor / power meter sensors

When a FusionSolar power sensor / power meter is available, it is exposed as a dedicated Home Assistant device.

Depending on your system and what the frontend exposes, you may see sensors such as:

- Power Sensor Status
- Power Sensor Usage
- Power Sensor Direction
- Power Sensor Grid Voltage
- Power Sensor Grid Current
- Power Sensor Active Power
- Power Sensor Power Factor
- Power Sensor Grid Frequency
- Power Sensor Grid Consumption Total
- Power Sensor Grid Injection Total

These values are taken directly from the power sensor / meter device endpoints and are intended as technical diagnostics / metering sensors, separate from the installation-wide aggregate energy sensors.

### Diagnostic sensors

Some sensors are primarily useful for diagnostics and troubleshooting rather than day-to-day dashboards, including:

- Last Authentication Time
- Inverter Startup Time
- Inverter Last Shutdown Time
- Inverter Output Mode
- Battery Backup Time
- Battery module diagnostic sensors
- Battery module pack diagnostic sensors
- Power sensor / power meter sensors

## Card configuration

I have configured a card using [flixlix](https://github.com/flixlix)'s [power-flow-card-plus](https://github.com/flixlix/power-flow-card-plus) that looks something like this:

<a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card.png"></a>

You can use a configuration like this:

```yaml
type: custom:power-flow-card-plus
entities:
  battery:
    state_of_charge: sensor.battery_percentage
    entity:
      consumption: sensor.battery_consumption_power
      production: sensor.battery_injection_power
  grid:
    entity:
      consumption: sensor.grid_consumption_power
      production: sensor.grid_injection_power
    secondary_info: {}
  solar:
    secondary_info: {}
    entity: sensor.panel_production_power
  home:
    secondary_info: {}
    entity: sensor.house_load_power
clickable_entities: true
display_zero_lines: true
use_new_flow_rate_model: true
w_decimals: 0
kw_decimals: 1
min_flow_rate: 0.75
max_flow_rate: 6
max_expected_power: 2000
min_expected_power: 0.01
watt_threshold: 1000
transparency_zero_lines: 0
```

You can find `fusionsolar.png` in the `assets` folder. Put it in your Home Assistant `www` folder (`/config/www`).

## Optional: Home Assistant package example (extra sensors)

If you want some **extra calculated sensors** (net battery power, grid net power, PV self-consumption at the current moment, etc.) you can still add them using a Home Assistant package.

> Note: some historical / period-based self-consumption ratios are now built into the integration natively, so you may not need all the template examples below anymore.

### How to use this (Packages)

1. Enable packages in your `/config/configuration.yaml` if you do not already use them:

```yaml
homeassistant:
  packages: !include_dir_named packages
```

2. Create a new file, for example:

`/config/packages/fusionsolar_app_extra_sensors.yaml`

3. Paste the YAML below into that file.

4. Restart Home Assistant.

### Example package file (YAML)

```yaml
template:
  - sensor:
      - name: "Battery net power"
        unique_id: battery_power_net
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set discharge = states('sensor.battery_consumption_power') | float(0) %}
          {% set charge = states('sensor.battery_injection_power') | float(0) %}
          {{ (charge - discharge) | round(0) }}

      - name: "Battery charging power"
        unique_id: battery_charging_power
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set discharge = states('sensor.battery_consumption_power') | float(0) %}
          {% set charge = states('sensor.battery_injection_power') | float(0) %}
          {{ (charge if charge > 0 else 0) | round(0) }}

      - name: "Battery discharging power"
        unique_id: battery_discharging_power
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set discharge = states('sensor.battery_consumption_power') | float(0) %}
          {{ (discharge if discharge > 0 else 0) | round(0) }}

  - sensor:
      - name: "Battery total power"
        unique_id: battery_power_total
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set discharge = states('sensor.battery_consumption_power') | float(0) %}
          {% set charge = states('sensor.battery_injection_power') | float(0) %}
          {{ (charge + discharge) | round(0) }}

  - sensor:
      - name: "Grid net power"
        unique_id: grid_net_power
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set imp = states('sensor.grid_consumption_power')|float(0) %}
          {% set exp = states('sensor.grid_injection_power')|float(0) %}
          {{ (exp - imp) | round(0) }}

      - name: "PV self-consumed power"
        unique_id: pv_self_consumed_power
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set pv = states('sensor.panel_production_power')|float(0) %}
          {% set exp = states('sensor.grid_injection_power')|float(0) %}
          {{ max(0, pv - exp) | round(0) }}

      - name: "PV cover now"
        unique_id: pv_cover_now
        unit_of_measurement: "%"
        state: >
          {% set load = states('sensor.house_load_power')|float(0) %}
          {% set pv = states('sensor.panel_production_power')|float(0) %}
          {% if load > 0 %}
            {{ (min(1, pv/load) * 100) | round(0) }}
          {% else %}
            0
          {% endif %}

      - name: "Self-sufficiency now"
        unique_id: self_sufficiency_now
        unit_of_measurement: "%"
        state: >
          {% set load = states('sensor.house_load_power')|float(0) %}
          {% set imp = states('sensor.grid_consumption_power')|float(0) %}
          {% if load > 0 %}
            {{ ((1 - min(1, imp/load)) * 100) | round(0) }}
          {% else %}
            0
          {% endif %}

  - sensor:
      - name: "Energy mode"
        unique_id: energy_mode
        state: >
          {% set pv = states('sensor.panel_production_power')|float(0) %}
          {% set imp = states('sensor.grid_consumption_power')|float(0) %}
          {% set exp = states('sensor.grid_injection_power')|float(0) %}
          {% if exp > 50 %}
            🌞📤 Export mode
          {% elif pv > imp %}
            🌤️👍 PV powering the house
          {% elif imp > 50 %}
            🌙📥 Import mode
          {% else %}
            😴 Quiet moment
          {% endif %}

sensor:
  - platform: integration
    source: sensor.house_load_power
    name: House load energy
    unit_prefix: k
    round: 2

  - platform: integration
    source: sensor.grid_consumption_power
    name: Grid import energy
    unit_prefix: k
    round: 2

  - platform: integration
    source: sensor.grid_injection_power
    name: Grid export energy
    unit_prefix: k
    round: 2

  - platform: integration
    source: sensor.panel_production_power
    name: PV energy
    unit_prefix: k
    round: 2
```

## Example Lovelace cards (using the extra sensors)

### Entities card

```yaml
type: entities
title: FusionSolar (Extra sensors)
entities:
  - entity: sensor.energy_mode
  - entity: sensor.battery_power_net
  - entity: sensor.battery_charging_power
  - entity: sensor.battery_discharging_power
  - entity: sensor.grid_net_power
  - entity: sensor.pv_self_consumed_power
  - entity: sensor.pv_cover_now
  - entity: sensor.self_sufficiency_now
```

### Gauge cards (PV cover + self-sufficiency)

```yaml
type: vertical-stack
cards:
  - type: grid
    columns: 2
    square: false
    cards:
      - type: gauge
        name: PV cover now
        entity: sensor.pv_cover_now
        min: 0
        max: 100
        severity:
          green: 60
          yellow: 35
          red: 0
      - type: gauge
        name: Self-sufficiency now
        entity: sensor.self_sufficiency_now
        min: 0
        max: 100
        severity:
          green: 60
          yellow: 40
          red: 0

  - type: custom:apexcharts-card
    header:
      show: true
      title: Power (W) – 24h
      show_states: true
    graph_span: 24h
    now:
      show: true
    all_series_config:
      stroke_width: 1
    series:
      - entity: sensor.panel_production_power
        name: PV
        type: area
      - entity: sensor.house_load_power
        name: Load
        type: line
      - entity: sensor.grid_consumption_power
        name: Import
        type: line
      - entity: sensor.grid_injection_power
        name: Export
        type: line
      - entity: sensor.grid_net_power
        name: Grid net
        type: line

  - type: entities
    title: Details
    entities:
      - entity: sensor.energy_mode
      - entity: sensor.pv_self_consumed_power
      - entity: sensor.grid_net_power
      - entity: sensor.panel_production_power
      - entity: sensor.house_load_power
      - entity: sensor.grid_consumption_power
      - entity: sensor.grid_injection_power
```

That looks something like this:

<a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card2.PNG"></a>

## Solar Production Forecast

This integration exposes two additional forecast sensors for the current day panel production:

| Sensor | Description |
|---|---|
| `PV Forecasted Today` | Estimated total panel production for the current day, in kWh |
| `PV Remaining Today` | Estimated remaining panel production for the current day, in kWh |

The forecast provider is configurable from the integration options.

The selected provider is exposed through the forecast sensor attributes, so dashboards and diagnostics can identify whether the current forecast came from the native provider or from Solcast.

### Forecast providers

The integration currently supports two forecast providers:

| Provider | Description |
|---|---|
| `Native (last 7 days)` | Uses Home Assistant Recorder history from the local `Panel Production Today` sensor |
| `Solcast` | Uses an existing Solcast forecast sensor selected by the user |

The forecast provider can be changed from:

**Settings → Devices & Services → FusionSolar App Integration → Configure**

The FusionSolar forecast sensors keep the same entity IDs and attributes regardless of the selected provider.

This means a dashboard can use:

```yaml
data_generator: |
  return entity.attributes.forecast_power_chart || [];
```

and it will work with either the native provider or the Solcast provider.

### Native forecast provider

The native forecast provider is the default.

It builds a local statistical forecast from the historical values of the `Panel Production Today` sensor stored in Home Assistant Recorder.

> This is not a weather-based forecast. It is a local statistical forecast based on your own recent production history.

#### How it works

The native forecast model uses the last 7 days of panel production history and applies weighted averages to estimate the expected production curve for the current day.

Recent days have more influence than older days:

```text
Day -1: 40%
Day -2: 25%
Day -3: 15%
Day -4: 10%
Day -5: 5%
Day -6: 3%
Day -7: 2%
```

For each time interval, the integration calculates the historical production delta and builds a daily forecast delta curve.

Because FusionSolar App data is not updated continuously, some days may contain artificial gaps or jumps. For example, if the API skips a few update cycles and then reports the accumulated production later, a single 5-minute interval may appear to contain an unrealistic production spike.

To reduce the impact of this, the native forecast uses a robust average for each interval. Very low or very high outliers are filtered out before calculating the weighted average. This helps avoid cases where missing data produces false zero values or delayed API updates produce unrealistic power spikes.

The resulting delta curve is then smoothed while preserving the expected total energy.

### Solcast forecast provider

The Solcast forecast provider allows the integration to use an existing Solcast forecast sensor from Home Assistant.

When this provider is selected, the integration options will ask for the Solcast forecast sensor to use.

The selected sensor must expose a `detailedHourly` attribute with items similar to:

```yaml
detailedHourly:
  - period_start: "2026-05-05T10:00:00+01:00"
    pv_estimate: 3.5285
    pv_estimate10: 2.0755
    pv_estimate90: 4.1334
```

The integration reads:

| Solcast attribute | Used for |
|---|---|
| `detailedHourly[].period_start` | Forecast timestamp |
| `detailedHourly[].pv_estimate` | Forecasted hourly energy |
| `estimate` | Estimated full-day production |
| `estimate10` | Lower estimate / P10 value |
| `estimate90` | Upper estimate / P90 value |
| `analysis.confidence` | Confidence value, when available |

#### Solcast smoothing

Solcast `detailedHourly` data is hourly. To make it useful in the same dashboards as the native 5-minute forecast, the integration converts it into a 5-minute curve.

The conversion:

- treats each hourly `pv_estimate` as the average power shape for that hour
- interpolates smoothly between hourly forecast centres
- blends the forecast into the current real panel production power near `now`
- applies a small moving average smoothing window
- normalizes the resulting curve so the remaining expected energy is preserved

This avoids a stepped chart while still keeping the Solcast daily energy estimate consistent.

#### Solcast forecast scope

The Solcast forecast generated by this integration is only built from the current moment forward.

In practice:

- past chart data comes from the real FusionSolar sensors
- the forecast curve starts at `now`
- future points come from the selected Solcast forecast sensor
- if the current Solcast hour is already partially elapsed, only the remaining part of that hour is used

This avoids replacing real measured production with forecast values.

When using dashboard offsets to view past days, the Solcast forecast does not reconstruct what the forecast was on those historical days. It only represents the current day forecast available from the selected Solcast sensor.

### Forecast calculation

During the day, the forecast combines:

- the real production already measured today
- the remaining forecasted production from the selected provider

In simplified terms:

```text
forecasted total today = current actual production + remaining forecasted production
```

The `PV Remaining Today` sensor represents only the estimated production still expected for the rest of the current day.

### Forecast attributes

The forecast sensor exposes a raw `curve` attribute. Each point in the curve contains:

| Attribute | Description |
|---|---|
| `time` | Timestamp of the curve point |
| `value` | Cumulative production at that time, in kWh |
| `delta_kwh` | Production during that interval, in kWh |
| `power_w` | Estimated power for that interval, in W |
| `source` | Either `actual`, `actual_now` or `forecast` |

The sensor also exposes provider and diagnostic attributes:

| Attribute | Description |
|---|---|
| `provider` | Forecast provider currently used, for example `native` or `solcast` |
| `provider_entity_id` | Source entity used by the provider, when applicable |
| `source_entity_id` | Main source entity used to build the forecast |
| `actual_now_value` | Current measured daily production, in kWh |
| `remaining_today` | Estimated remaining production today, in kWh |
| `correction_factor` | Correction factor used by the forecast provider, when applicable |
| `generated_at` | Timestamp when the forecast was generated |
| `step_minutes` | Forecast curve step size |
| `days` | Number of historical days used by the provider, when applicable |
| `estimate10_kwh` | Lower estimate from Solcast, when available |
| `estimate90_kwh` | Upper estimate from Solcast, when available |
| `confidence` | Confidence value from Solcast, when available |

The sensor also exposes ApexCharts-ready attributes:

| Attribute | Description |
|---|---|
| `forecast_power_chart` | Forecasted instant power series, ready to be used by ApexCharts |
| `forecast_cumulative_chart` | Forecasted cumulative production series, ready to be used by ApexCharts |

The same attributes are used for both native and Solcast providers.

This allows a dashboard to keep the same ApexCharts configuration when switching forecast provider.

### Forecast cache

The native forecast uses a persistent daily cache.

The historical forecast curve is built once per day and reused during the day. If Home Assistant restarts, the cache is restored when possible. If the cache is missing, outdated or incompatible, it is rebuilt automatically.

The cache may also be rebuilt automatically when the forecast algorithm changes between integration versions.

The Solcast provider does not use the native historical cache. It builds its curve from the selected Solcast sensor attributes each time the coordinator refreshes.

### Forecast smoothing and outlier filtering

Historical solar production can contain short spikes caused by clouds, shading, API update delays, sensor updates or Recorder sampling intervals.

To make the forecast more useful for dashboards, the native provider applies:

- weighted historical averaging
- robust outlier filtering
- delta-curve smoothing

The Solcast provider applies:

- smooth interpolation between hourly forecast points
- blending from current real power to forecasted power
- moving average smoothing
- energy normalization

This avoids unrealistic instant power spikes without losing the expected daily production shape.

### Recorder and database usage

The forecast sensors expose large attributes such as `curve`, `forecast_power_chart` and `forecast_cumulative_chart`.

These attributes are useful for dashboards, but they should not be stored repeatedly in the Recorder database.

To avoid unnecessary database growth, the integration marks forecast sensor attributes as unrecorded. The current state of the sensors can still be stored by Recorder, but the large attributes are not stored historically.

The forecast sensors intentionally do not expose a `state_class`. This prevents Home Assistant from generating long-term statistics for forecast values, which are not real measurements and can change throughout the day.

This means:

- the current forecast value is still available as the sensor state
- the current forecast attributes are still available for dashboards
- large forecast attributes are not stored in Recorder
- long-term statistics are not generated for forecast sensors

### Notes and limitations

For the native provider, the forecast depends on Home Assistant Recorder history. For best results, make sure the source sensor `Panel Production Today` has at least a few days of history available.

The first forecast days may be less accurate until enough historical data exists.

For the Solcast provider, the forecast depends on the selected Solcast sensor being available and exposing a valid `detailedHourly` attribute.

FusionSolar App data is usually updated every few minutes, not continuously. Depending on your region, account and API behaviour, updates may arrive roughly every 5 minutes or sometimes slightly later. This can create visible jumps in charts based on cumulative production sensors.

The forecast is designed to reduce the impact of those jumps, but the real-time production chart may still show short spikes if it is derived from cumulative energy values instead of using a direct instant power sensor.

## Dashboard example

The following dashboard section shows:

- realtime panel production
- realtime forecasted production
- cumulative panel production
- cumulative forecasted production
- forecasted and remaining production sensors

The same dashboard works with either the native forecast provider or the Solcast forecast provider.

### Screenshot

<a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card3.png"></a>

### Required custom cards

This dashboard example uses:

- `custom:apexcharts-card`
- `custom:card-templater`
- `custom:mushroom-chips-card`

### Optional helper

The dashboard example uses an `input_number` helper to navigate between days:

```yaml
input_number:
  graph_offset:
    name: Graph Offset
    min: 0
    max: 30
    step: 1
    mode: box
```

The date chip expects a template sensor similar to this:

```yaml
template:
  - sensor:
      - name: Graph Offset Date
        state: >
          {% set offset = states('input_number.graph_offset') | int(0) %}
          {{ (as_timestamp(now()) - (offset * 86400)) | timestamp_custom('%Y-%m-%d', true) }}
```

### Dashboard YAML

```yaml
type: grid
cards:
  - type: heading
    heading: Energy Management
    heading_style: title
    icon: mdi:solar-power
  - type: custom:mushroom-chips-card
    alignment: center
    chips:
      - type: entity
        entity: input_number.graph_offset
        content_info: none
        icon: mdi:arrow-left
        tap_action:
          action: call-service
          service: input_number.increment
          service-data:
            entity_id: input_number.graph_offset
          target:
            entity_id: input_number.graph_offset
      - type: template
        content: |
          {{ states('sensor.graph_offset_date') }}
        icon: mdi:calendar
        tap_action:
          action: none
      - type: entity
        entity: input_number.graph_offset
        content_info: none
        icon: mdi:arrow-right
        tap_action:
          action: call-service
          service: input_number.decrement
          service-data:
            entity_id: input_number.graph_offset
          target:
            entity_id: input_number.graph_offset
      - type: entity
        entity: input_number.graph_offset
        name: Today
        content_info: name
        icon: mdi:home
        tap_action:
          action: call-service
          service: input_number.set_value
          service-data:
            entity_id: input_number.graph_offset
          target:
            entity_id: input_number.graph_offset
          data:
            value: 0
  - type: custom:card-templater
    entities:
      - input_number.graph_offset
    card:
      type: custom:apexcharts-card
      graph_span: 24h
      header:
        show: true
        title: Realtime Panel Production
      span:
        start: day
        offset_template: "-{{ states('input_number.graph_offset') }}d"
      all_series_config:
        stroke_width: 2
      experimental:
        hidden_by_default: true
      apex_config:
        yaxis:
          title:
            text: kW
      series:
        - entity: sensor.house_load_power
          name: House Load
          type: area
          extend_to: false
        - entity: sensor.panel_production_power
          name: Panel Production
          type: area
          extend_to: false
        - entity: sensor.fusion_solar_ne_xxxxx_pv_forecasted_today
          name: Forecast Power
          type: area
          unit: kW
          color: blue
          opacity: 0.7
          data_generator: |
            return entity.attributes.forecast_power_chart || [];
        - entity: sensor.battery_injection_power
          name: Battery Charge
          type: area
          extend_to: false
          show:
            hidden_by_default: true
        - entity: sensor.grid_consumption_power
          name: Grid Consumption
          type: area
          extend_to: false
          show:
            hidden_by_default: true
        - entity: sensor.battery_consumption_power
          name: Battery Discharge
          type: area
          extend_to: false
          show:
            hidden_by_default: true
  - type: custom:apexcharts-card
    graph_span: 24h
    span:
      start: day
    header:
      show: true
      title: Cumulative Panel Production
    all_series_config:
      stroke_width: 2
    apex_config:
      yaxis:
        title:
          text: kWh
        labels:
          formatter: |
            EVAL:function (val) {
              if (val === null || val === undefined) return "";
              const num = Number(val);
              if (isNaN(num)) return "";
              return num.toFixed(1);
            }
    series:
      - entity: sensor.panel_production_today
        name: Actual
        type: line
        extend_to: now
      - entity: sensor.fusion_solar_ne_xxxxx_pv_forecasted_today
        name: Forecast
        type: line
        unit: kWh
        data_generator: |
          return entity.attributes.forecast_cumulative_chart || [];
  - type: heading
    icon: mdi:chart-areaspline-variant
    heading: Forecast
    heading_style: title
  - type: entities
    entities:
      - entity: sensor.fusion_solar_ne_xxxxx_pv_forecasted_today
        name: PV Forecasted Today
      - entity: sensor.fusion_solar_ne_xxxxx_pv_remaining_today
        name: PV Remaining Today
```

## FAQ

### I'm not able to login, or my sensors stop updating

This integration is based on how the FusionSolar frontend behaves, not on the official OpenAPI.

Different regions can behave differently, and the frontend login flow can change over time.

Recent versions of this integration include improved handling for:

- region-specific login patterns
- normalized host input
- session refresh and stalled session recovery
- login / API behaviour inferred from HAR captures and real frontend traffic

If you still have trouble, the best way to help is to provide a browser HAR capture or detailed network trace.

### My website login works, but Home Assistant login does not

This can happen when the FusionSolar frontend in your region uses a slightly different login or redirect flow than the one currently implemented in the integration.

Recent versions include improved compatibility for EU5 and related frontend login patterns, including service-aware login handling and fallback logic, but frontend behaviour can still vary between regions and over time.

If your credentials work in the FusionSolar website but Home Assistant reports invalid authentication or missing redirect information, please capture a HAR file and open an issue.

### How can I help troubleshoot login or region issues?

You can use your browser's Developer Tools:

- open your FusionSolar web URL
- press `F12`
- go to the **Network** tab
- enable **Preserve log**
- clear the log
- perform the login sequence
- export the network log as **HAR**

That information is often enough to infer the frontend flow and update the integration for additional regions or login patterns.

### How do I use Solcast as the forecast provider?

Install and configure a Solcast integration in Home Assistant first.

Then open the FusionSolar App integration options:

**Settings → Devices & Services → FusionSolar App Integration → Configure**

Select:

```text
Forecast provider: Solcast
```

Then select the Solcast sensor that exposes `detailedHourly`, for example:

```text
sensor.solcast_pv_forecast_forecast_today
```

After saving the options, the existing FusionSolar forecast sensors will use Solcast data.

### Do I need to change my dashboard when switching between native and Solcast forecast?

No.

The FusionSolar forecast sensor exposes the same ApexCharts-ready attributes for both providers:

```yaml
forecast_power_chart
forecast_cumulative_chart
```

So a dashboard using this continues to work:

```yaml
data_generator: |
  return entity.attributes.forecast_power_chart || [];
```

### Why does the Solcast forecast look smoother than the raw Solcast sensor?

The raw Solcast `detailedHourly` data is hourly. This integration converts it into a 5-minute curve and smooths the transition between hourly values.

This makes it more suitable for live power dashboards where it is displayed alongside real-time FusionSolar production data.

### Does the Solcast provider replace historical chart data?

No.

The Solcast provider only generates forecast points from the current moment forward.

Past chart data should continue to come from the real FusionSolar sensors. The forecast curve starts at `now` and then follows the Solcast-based projection for the rest of the day.

## Credits

A big thank you to Mark Parker ([msp1974](https://github.com/msp1974)) for providing the Community with a set of [Home Assistant Integration Templates](https://github.com/msp1974/HAIntegrationExamples) from which I started to create this integration.

Another big thank you to Tijs Verkoyen for his [FusionSolar integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar), which was also an inspiration.

Additional thanks to the community members who shared browser traces, HAR files and real-world frontend behaviour, which helped improve:

- regional login compatibility
- session handling
- inverter PV string discovery
- battery metadata coverage
- battery module and pack coverage
- power sensor / power meter coverage
- device and frontend-derived sensor coverage

Also thanks to [FusionSolarPlus](https://github.com/JortvanSchijndel/FusionSolarPlus) for useful ideas around broader frontend coverage, device-oriented signals and regional behaviour analysis.

Additional thanks to the Solcast integration ecosystem for making local Solcast forecast sensors available in Home Assistant, which can now be used as an optional forecast source by this integration.
