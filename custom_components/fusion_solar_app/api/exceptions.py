class APIAuthError(Exception):
    """Authentication/session or login-protocol failure; not necessarily permanent."""


class APIAuthRejectedError(APIAuthError):
    """Affirmative credential or required-endpoint authorization rejection."""


class APIAuthCaptchaError(Exception):
    """Exception class for auth captcha error."""


class APIConnectionError(Exception):
    """Exception class for connection error."""


class APIDataStructureError(Exception):
    """Exception class for data error."""