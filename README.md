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
  * [FAQ](#faq)
  * [Credits](#credits)

## Installation

This integration can be added as a custom repository in HACS and from there you can install it.

When the integration is installed in HACS, you need to add it in Home Assistant: Settings → Devices & Services → Add Integration → Search for FusionSolar App Integration.

The configuration happens in the configuration flow when you add the integration.

## Configuration

To access FusionSolar App you'll need an App account first. When you get it from your installer you'll have an Username and Password. That account is used on this integration. You will need also to provide the Fusion Solar Host you use to login on Fusion Solar App, as you will only be ablet o login on your specific region.

The default sensor's update frequency is 60 seconds, although the FusionSolar App only gets data every 5 minutes. It is just to make sure that as soon as the data can be retrieved from the API the sensors will be updated as soon as possible. After configuring the Integration you can go on the Config Entry and press configure where you'll have the opportunity to change de default update frequency (in seconds). Bare in mind that too frequent will not get data more frequent than 5 minutes and may push the API too much.

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
That looks something like this: <a href="#"><img src="https://raw.githubusercontent.com/hcraveiro/Home-Assistant-FusionSolar-App/main/assets/card2.png"></a>

## Solar Production Forecast

This integration exposes two additional forecast sensors for the current day panel production:

| Sensor | Description |
|---|---|
| `Panel Production Forecasted Today` | Estimated total panel production for the current day, in kWh |
| `Panel Production Remaining Today` | Estimated remaining panel production for the current day, in kWh |

The forecast is built from the historical values of the `Panel Production Today` sensor stored in Home Assistant Recorder.

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

The forecast is generated as a daily cumulative curve. Each point contains:

| Attribute | Description |
|---|---|
| `time` | Timestamp of the curve point |
| `value` | Cumulative forecasted production at that time, in kWh |
| `delta_kwh` | Expected production during that interval |
| `power_w` | Estimated power for that interval, in W |
| `source` | Either `actual`, `actual_now` or `forecast` |

The forecast uses a persistent daily cache. The historical forecast curve is built once per day and reused during the day. If Home Assistant restarts, the cache is restored when possible. If the cache is missing, outdated or incompatible, it is rebuilt automatically.

The forecasted total is calculated as:

```text
current actual production + remaining forecasted deltas
```

This allows the forecast to follow the real production already measured today while still using the historical production pattern for the remaining hours.

### Forecast smoothing

Historical solar production can contain short spikes caused by clouds, shading, sensor updates or recorder sampling intervals.

To make the forecast more useful for dashboards, the integration smooths the forecast delta curve while preserving the total expected daily energy. This avoids unrealistic instant power spikes without changing the forecasted total production.

### Recorder and database usage

The forecast sensors expose a large `curve` attribute used by dashboard cards such as ApexCharts.

To avoid unnecessary database growth, the integration marks forecast sensor attributes as unrecorded. The current state of the sensors is still recorded, but large attributes such as the forecast curve are not stored historically.

This means:

- the forecast sensor values can still have history;
- the current `curve` attribute is still available for dashboards;
- the Recorder database is not filled with repeated large forecast attributes.

### Notes

The forecast depends on Home Assistant Recorder history. For best results, make sure the source sensor `Panel Production Today` has at least a few days of history available.

The first forecast days may be less accurate until enough historical data exists.

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

A big thank you to Mark Parker ([msp1974](https://github.com/msp1974)) for providing the Community with a set of [Home Assistant Integration Templates](https://github.com/msp1974/HAIntegrationExamples) from which I started to create this Integration-
Another big thank you to Tijs Verkoyen for his [Integration](https://github.com/tijsverkoyen/HomeAssistant-FusionSolar) as I also took inspiration from there.
