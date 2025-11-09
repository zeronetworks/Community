"""
Custom exception classes for Zero Threat Hunt operations.
"""

import json
from typing import Any, Optional


class ZeroThreatHuntError(Exception):
    """
    Base exception class for all Zero Threat Hunt errors.

    This exception is raised when an error occurs during threat hunting operations.
    It provides a base class for more specific threat hunting exceptions.

    :param message: Human-readable error message describing what went wrong
    :type message: str
    :param details: Optional additional details about the error (e.g., invalid values, context)
    :type details: Optional[dict[str, Any]]
    """

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        """Return a formatted string representation of the error."""
        base_msg = f"Zero Threat Hunt Error: {self.message}"
        if self.details:
            return f"{base_msg}\nDetails: {json.dumps(self.details, indent=2)}"
        return base_msg


class ZeroThreatHuntInvalidValues(ZeroThreatHuntError):
    """
    Exception raised when invalid values are provided to threat hunting operations.

    This exception is raised when input values don't meet the expected format,
    type, or validation requirements for threat hunting methods.

    :param message: Human-readable error message describing the validation failure
    :type message: str
    :param invalid_values: Optional dictionary containing the invalid values and their context
    :type invalid_values: Optional[dict[str, Any]]
    :param expected_format: Optional description of the expected format or values
    :type expected_format: Optional[str]

    Example:
        .. code-block:: python

            raise ZeroThreatHuntInvalidValues(
                "Empty domains list provided",
                invalid_values={"domains": []},
                expected_format="Non-empty list of domain strings"
            )
    """

    def __init__(
        self,
        message: str,
        invalid_values: Optional[dict[str, Any]] = None,
        expected_format: Optional[str] = None,
    ) -> None:
        details = {}
        if invalid_values:
            details["invalid_values"] = invalid_values
        if expected_format:
            details["expected_format"] = expected_format

        super().__init__(message, details if details else None)
        self.invalid_values = invalid_values
        self.expected_format = expected_format
