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
LOGIN_DEFAULT_REDIRECT_URL = "/rest/dp/web/v1/auth/on-sso-credential-ready"
LOGIN_HEADERS_1_STEP_REFERER = "/unisso/login.action"
LOGIN_HEADERS_2_STEP_REFERER = "/pvmswebsite/loginCustomize.html"
DATA_REFERER_URL = "/uniportal/pvmswebsite/assets/build/cloud.html"
DATA_URL = "/rest/pvms/web/station/v2/overview/energy-flow"
STATION_LIST_URL = "/rest/pvms/web/station/v1/station/station-list"
ENERGY_BALANCE_URL = "/rest/pvms/web/station/v2/overview/energy-balance"
KEEP_ALIVE_URL = "/rest/dpcloud/auth/v1/keep-alive"
