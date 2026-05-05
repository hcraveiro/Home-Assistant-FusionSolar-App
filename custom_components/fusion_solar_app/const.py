"""Constants for the Integration Fusion Solar App."""

DOMAIN = "fusion_solar_app"

DEFAULT_SCAN_INTERVAL = 60
MIN_SCAN_INTERVAL = 10
FUSION_SOLAR_HOST = "fusion_solar_host"
CONF_STATION_DN = "station_dn"
CAPTCHA_INPUT = "captcha_input"
PUBKEY_URL = "/unisso/pubkey"
CAPTCHA_URL = "/unisso/verifycode"
LOGIN_FORM_URL = "/unisso/login.action"
LOGIN_VALIDATE_USER_URL = "/unisso/v3/validateUser.action"
LOGIN_VALIDATE_USER_URL_LA5 = "/rest/dp/uidm/unisso/v1/validate-user"
LOGIN_DEFAULT_REDIRECT_URL = "/rest/dp/web/v1/auth/on-sso-credential-ready"
LOGIN_HEADERS_1_STEP_REFERER = "/unisso/login.action"
LOGIN_HEADERS_2_STEP_REFERER = "/pvmswebsite/loginCustomize.html"
DATA_REFERER_URL = "/uniportal/pvmswebsite/assets/build/cloud.html"
DATA_URL = "/rest/pvms/web/station/v2/overview/energy-flow"
STATION_LIST_URL = "/rest/pvms/web/station/v1/station/station-list"
ENERGY_BALANCE_URL = "/rest/pvms/web/station/v2/overview/energy-balance"
KEEP_ALIVE_URL = "/rest/dpcloud/auth/v1/keep-alive"
FINAL_AUTH_URL_LA5 = "/rest/pvms/web/login/v1/redirecturl?isFirst=false"
DEVICE_REALTIME_DATA_URL = "/rest/pvms/web/device/v1/device-realtime-data"
DEVICE_REAL_KPI_URL = "/rest/pvms/web/device/v1/device-real-kpi"
SOCIAL_CONTRIBUTION_URL = "/rest/pvms/web/station/v1/station/social-contribution"
BATTERY_TYPE_URL = "/rest/pvms/web/device/v1/get-battery-type"
BATTERY_DC_URL = "/rest/pvms/web/device/v1/query-battery-dc"
INVERTER_CONFIG_SIGNAL_URL = "/rest/neteco/web/config/device/v1/config/query-moc-config-signal"

CONF_FORECAST_PROVIDER = "forecast_provider"
CONF_SOLCAST_FORECAST_TODAY_ENTITY = "solcast_forecast_today_entity"

FORECAST_PROVIDER_NATIVE = "native"
FORECAST_PROVIDER_SOLCAST = "solcast"
DEFAULT_FORECAST_PROVIDER = FORECAST_PROVIDER_NATIVE