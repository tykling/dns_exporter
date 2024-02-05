class ConfigError(Exception):
    """Exception class used when invalid config values are encountered."""

    pass


class ValidationError(Exception):
    """Exception class used when response validation fails."""

    pass
