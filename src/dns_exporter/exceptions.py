"""This module contains the custom exceptions used in dns_exporter."""


class ConfigError(Exception):
    """Exception class used when invalid config values are encountered."""


class ValidationError(Exception):
    """Exception class used when response validation fails."""

    def __init__(self, validator: str, reason: str) -> None:
        """Take validator and reason as arguments and raise the exception."""
        super().__init__(f"Response validator {validator} failed with reason {reason}", reason)
