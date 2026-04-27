# Home Assistant FusionSolar App Integration

[![hacs\_badge](https://img.shields.io/badge/HACS-Default-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub release](https://img.shields.io/github/release/hcraveiro/Home-Assistant-FusionSolar-App.svg)](https://github.com/hcraveiro/Home-Assistant-FusionSolar-App/releases/)

Integrate FusionSolar App into your Home Assistant. This Integration was built due to the fact that some FusionSolar users don't have access to the Kiosk mode or the Northbound API / OpenAPI. If you happen to have access to any of those, please use [Tijs Verkoyen's Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar)

* [Home Assistant FusionSolar App Integration](#home-assistant-fusionsolar-app-integration)

  * [Installation](#installation)
  * [Configuration](#configuration)
  * [Card configuration](#card-configuration)
  * [Optional: Home Assistant package example (extra sensors)](#optional-home-assistant-package-example-extra-sensors)
  * [Example Lovelace cards (using the extra sensors)](#example-lovelace-cards-using-the-extra-sensors)
  * [Solar Production Forecast](#solar-production-forecast)
  * [Dashboard example](#dashboard-example)
  * [FAQ](#faq)
  * [Credits](#credits)

## Installation

This integration can be added as a custom repository in HACS and from there you can install it.

When the integration is installed in HACS, you need to add it in Home Assistant: Settings → Devices & Services → Add Integration → Search for FusionSolar App Integration.

The configuration happens in the configuration flow when you add the integration.

## Configuration

To access FusionSolar App you'll need an App account first. When you get it from your installer you'll have an Username and Password. That account is used on this integration. You will need also to provide the Fusion Solar host you use to log in to Fusion Solar App, as you will only be able to log in to your specific region.

The default sensor's update frequency is 60 seconds, although the FusionSolar App only gets data every 5 minutes. It is just to make sure that as soon as the data can be retrieved from the API the sensors will be updated as soon as possible. After configuring the integration, you can open the config entry and press Configure to change the default update frequency in seconds. Bear in mind that setting it too low will not make the API return data more often than every 5 minutes, and may put unnecessary pressure on the API.

### Device Data

After setting up the Integration you will get a Device which will have the following sensors:

* Panels Production (kW)
* Panels Production Today (kWh)
* Panels Production Week (kWh)
* Panels Production Month (kWh)
* Panels Production Year (kWh)
* Panels Production Lifetime (kWh)
* Panels Production Consumption Today (kWh)
* Panels Production Consumption Week (kWh)
* Panels Production Consumption Month (kWh)
* Panels Production Consumption Year (kWh)
* Panels Production Consumption Lifetime (kWh)
* House Load (kW)
* House Load Today (kWh)
* House Load Week (kWh)
* House Load Month (kWh)
* House Load Year (kWh)
* House Load Lifetime (kWh)
* Battery Consumption (kW)
* Battery Consumption Today (kWh)
* Battery Consumption Week (kWh)
* Battery Consumption Month (kWh)
* Battery Consumption Year (kWh)
* Battery Consumption Lifetime (kWh)
* Battery Injection (kW)
* Battery Injection Today (kWh)
* Battery Injection Week (kWh)
* Battery Injection Month (kWh)
* Battery Injection Year (kWh)
* Battery Injection Lifetime (kWh)
* Grid Consumption (kW)
* Grid Consumption Today (kWh)
* Grid Consumption Week (kWh)
* Grid Consumption Month (kWh)
* Grid Consumption Year (kWh)
* Grid Consumption Lifetime (kWh)
* Grid Injection (kW)
* Grid Injection Today (kWh)
* Grid Injection Week (kWh)
* Grid Injection Month (kWh)
* Grid Injection Year (kWh)
* Grid Injection Lifetime (kWh)
* Battery Percentage (%)
* Battery Capacity
* Last Authentication Time
* Panel Production Forecasted Today (kWh)
* Panel Production Remaining Today (kWh)

#### Inverter Real-Time Sensors

The following sensors are fetched directly from the inverter device and require the inverter to be reachable via the API:

* Inverter Grid Voltage (V)
* Inverter Grid Current (A, phase A on 3-phase systems)
* Inverter Phase A Voltage (V)
* Inverter Phase B Voltage (V)
* Inverter Phase C Voltage (V)
* Inverter Phase B Current (A)
* Inverter Phase C Current (A)
* Inverter Grid Frequency (Hz)
* Inverter Internal Temperature (°C)
* Inverter Insulation Resistance (MΩ)
* Inverter Power Factor
* Inverter Status
* Inverter Startup Time
* Inverter PV1 Voltage (V)
* Inverter PV1 Current (A)
* Inverter PV2 Voltage (V)
* Inverter PV2 Current (A)
* Inverter PV3 Voltage (V)
* Inverter PV3 Current (A)

## Card configuration

I have configured a card using [flixlix](https://github.com/flixlix)'s [power-flow-card-plus](https://github.com/flixlix/power-flow-card-plus) that looks something like this: <a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card.png"></a>

You can see my configuration here:

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

You can find the fusionsolar.png in assets folder. You need to put it in 'www' folder (inside /config).

## Optional: Home Assistant package example (extra sensors)

If you want some **extra calculated sensors** (net battery power, grid net power, PV self-consumption, etc.) you can add them using a **Home Assistant package**.

### How to use this (Packages)

1. **Enable packages** in your `/config/configuration.yaml` (if you don't already use packages):

```yaml
homeassistant:
  packages: !include_dir_named packages
```

2. Create a new file, for example:

`/config/packages/fusionsolar_app_extra_sensors.yaml`

3. Paste the YAML below into that file.

4. **Restart Home Assistant**.

> Notes:
>
> * This is optional and does not affect the integration itself.
> * Make sure the entity IDs match your setup.
> * Packages merge configuration, so this won’t overwrite your existing `template:` or `sensor:` sections.

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
      # Net to grid: + = export, - = import
      - name: "Grid net power"
        unique_id: grid_net_power
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set imp = states('sensor.grid_consumption_power')|float(0) %}
          {% set exp = states('sensor.grid_injection_power')|float(0) %}
          {{ (exp - imp) | round(0) }}

      # PV self-consumption (approx): production - export
      - name: "PV self-consumed power"
        unique_id: pv_self_consumed_power
        unit_of_measurement: "W"
        device_class: power
        state_class: measurement
        state: >
          {% set pv = states('sensor.panel_production_power')|float(0) %}
          {% set exp = states('sensor.grid_injection_power')|float(0) %}
          {{ max(0, pv - exp) | round(0) }}

      # Share of current house load covered by PV (0-100%)
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

      # Instant self-sufficiency: 100% if you're not importing
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

Below are a couple of simple Lovelace examples that use the optional sensors above.

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
That looks something like this: <a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card2.PNG"></a>

## Solar Production Forecast

This integration exposes two additional forecast sensors for the current day panel production:

| Sensor | Description |
|---|---|
| `Panel Production Forecasted Today` | Estimated total panel production for the current day, in kWh |
| `Panel Production Remaining Today` | Estimated remaining panel production for the current day, in kWh |

The forecast is built from the historical values of the `Panel Production Today` sensor stored in Home Assistant Recorder.

> This is not a weather-based forecast. It is a local statistical forecast based on your own recent production history.

### How it works

The forecast model uses the last 7 days of panel production history and applies weighted averages to estimate the expected production curve for the current day.

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

To reduce the impact of this, the forecast uses a robust average for each interval. Very low or very high outliers are filtered out before calculating the weighted average. This helps avoid cases where missing data produces false zero values or delayed API updates produce unrealistic power spikes.

The resulting delta curve is then smoothed while preserving the expected total energy.

### Forecast calculation

During the day, the forecast combines:

- the real production already measured today;
- the remaining forecasted production based on the historical pattern.

In simplified terms:

```text
forecasted total today = current actual production + remaining forecasted production
```

The `Panel Production Remaining Today` sensor represents only the estimated production still expected for the rest of the current day.

### Forecast attributes

The forecast sensor exposes a raw `curve` attribute. Each point in the curve contains:

| Attribute | Description |
|---|---|
| `time` | Timestamp of the curve point |
| `value` | Cumulative production at that time, in kWh |
| `delta_kwh` | Production during that interval, in kWh |
| `power_w` | Estimated power for that interval, in W |
| `source` | Either `actual`, `actual_now` or `forecast` |

The sensor also exposes ApexCharts-ready attributes:

| Attribute | Description |
|---|---|
| `forecast_power_chart` | Forecasted instant power series, ready to be used by ApexCharts |
| `forecast_cumulative_chart` | Forecasted cumulative production series, ready to be used by ApexCharts |

### Forecast cache

The forecast uses a persistent daily cache.

The historical forecast curve is built once per day and reused during the day. If Home Assistant restarts, the cache is restored when possible. If the cache is missing, outdated or incompatible, it is rebuilt automatically.

The cache may also be rebuilt automatically when the forecast algorithm changes between integration versions.

### Forecast smoothing and outlier filtering

Historical solar production can contain short spikes caused by clouds, shading, API update delays, sensor updates or Recorder sampling intervals.

To make the forecast more useful for dashboards, the integration applies:

- weighted historical averaging;
- robust outlier filtering;
- delta-curve smoothing.

This avoids unrealistic instant power spikes without losing the expected daily production shape.

### Recorder and database usage

The forecast sensors expose large attributes such as `curve`, `forecast_power_chart` and `forecast_cumulative_chart`.

These attributes are useful for dashboards, but they should not be stored repeatedly in the Recorder database.

To avoid unnecessary database growth, the integration marks forecast sensor attributes as unrecorded. The current state of the sensors can still be stored by Recorder, but the large attributes are not stored historically.

The forecast sensors intentionally do not expose a `state_class`. This prevents Home Assistant from generating long-term statistics for forecast values, which are not real measurements and can change throughout the day.

This means:

- the current forecast value is still available as the sensor state;
- the current forecast attributes are still available for dashboards;
- large forecast attributes are not stored in Recorder;
- long-term statistics are not generated for forecast sensors.

### Notes and limitations

The forecast depends on Home Assistant Recorder history. For best results, make sure the source sensor `Panel Production Today` has at least a few days of history available.

The first forecast days may be less accurate until enough historical data exists.

FusionSolar App data is usually updated every few minutes, not continuously. Depending on your region, account and API behaviour, updates may arrive roughly every 5 minutes or sometimes slightly later. This can create visible jumps in charts based on cumulative production sensors.

The forecast is designed to reduce the impact of those jumps, but the real-time production chart may still show short spikes if it is derived from cumulative energy values instead of using a direct instant power sensor.

## Dashboard example

The following dashboard section shows:

- realtime panel production;
- realtime forecasted production;
- cumulative panel production;
- cumulative forecasted production;
- forecasted and remaining production sensors.

> Replace the entity IDs with your own entities if needed.

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
The dashboard example below uses the ApexCharts-ready attributes exposed by the forecast sensor, so the chart configuration can stay simple.

For the instant power forecast series:

```yaml
data_generator: |
  return entity.attributes.forecast_power_chart || [];
```

For the cumulative forecast series:

```yaml
data_generator: |
  return entity.attributes.forecast_cumulative_chart || [];
```

In the example below, replace `sensor.fusion_solar_ne_xxxxx_panel_production_forecasted_today` and `sensor.fusion_solar_ne_xxxxx_panel_production_remaining_today` with the actual entity IDs created in your Home Assistant instance.

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
        - entity: sensor.fusion_solar_ne_xxxxx_panel_production_forecasted_today
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
      - entity: sensor.fusion_solar_ne_xxxxx_panel_production_forecasted_today
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
      - entity: sensor.fusion_solar_ne_xxxxx_panel_production_forecasted_today
        name: Panel Production Forecasted Today
      - entity: sensor.fusion_solar_ne_xxxxx_panel_production_remaining_today
        name: Panel Production Remaining Today
```

## FAQ

### I'm not able to login, I'm getting error messages

I built this integration figuring out, with Developer Tools from my browser, how the Frontend of Fusion Solar App calls the API (not the OpenAPI, a specific one for Fusion Solar App).

Unfortunately the way the login is done might differ drastically from region to region. Unless I have accounts credentials for each case, I can't reproduce the behaviour for each scenario.

If you want to help me solve that, either you provide me with credentials to simulate the authentication flow, or you can help me by using your browser's Developer Tools (usually by pressing F12):

* Go to your Fusion Solar App URL on the browser (mine is [https://eu5.fusionsolar.huawei.com](https://eu5.fusionsolar.huawei.com)) but don't login yet
* Go to Network tab (in Developer Tools), have the 'Preserve log' checkbox ticked and then click the 'Clear network log'
* Press Login button and take a screenshot of the sequence and order of requests on Network tab
* Forward that to me through email; I will ask for more data, like what is on the Request Headers and Response Headers for each request, what is on the payload, etc.
* I will try to infer the neccessary logic with that info and the Javascript used by the Frontend to make it work

## Credits

A big thank you to Mark Parker ([msp1974](https://github.com/msp1974)) for providing the Community with a set of [Home Assistant Integration Templates](https://github.com/msp1974/HAIntegrationExamples) from which I started to create this Integration.
Another big thank you to Tijs Verkoyen for his [Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar) as I also took inspiration from there.
