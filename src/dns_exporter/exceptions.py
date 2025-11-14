"""This module contains the custom exceptions used in dns_exporter."""


class ConfigError(Exception):
    """Exception class used when invalid config values are encountered."""


class ValidationError(Exception):
    """Exception class used when response validation fails."""

    def __init__(self, validator: str, reason: str) -> None:
        """Take validator and reason as arguments and raise the exception."""
        super().__init__(f"Response validator {validator} failed with reason {reason}", reason)


class UnknownFailureReasonError(RuntimeError):
    """Exception raised if an unknown failure reason is used (this is always a bug)."""

    def __init__(self, failure_reason: str) -> None:
        """Raise with failure reason."""
        super().__init__(f"Unknown failure_reason {failure_reason} - please file a bug!")


class ProtocolSpecificError(Exception):
    """Exception class used when DNS lookup fails with a protocol specific exception."""


class ConfigTypeError(TypeError):
    """Exception used when DNSCollector is initialised with a config that is not a dns_exporter.config.Config object."""


class QueryTypeError(TypeError):
    """Exception used when DNSCollector is initialised with a query that is not a dns.query.QueryMessage object."""


class LabelsTypeError(TypeError):
    """Exception used when DNSCollector is initialised with a labels arg that is not a list."""
