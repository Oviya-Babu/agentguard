"""
Logging PII filter module.

This module provides a logging filter that removes personally identifiable
information (PII) from log records before they are emitted.

Filtered fields:
- Email addresses
- Phone numbers
- API keys
- Passwords
- Agent credentials
"""

import logging
import re
from typing import Pattern


class PIIFilter(logging.Filter):
    """
    Logging filter that sanitizes personally identifiable information.

    This filter redacts sensitive data from log records to prevent accidental
    exposure of credentials, agent details, or personal information in logs.

    Patterns filtered:
    - Email addresses
    - Phone numbers (10+ digits)
    - API keys
    - Password fields
    - Bearer tokens
    - Agent secrets
    """

    def __init__(self) -> None:
        """Initialize the PII filter with compiled regex patterns."""
        super().__init__()

        # Compiled patterns for common PII types
        self.patterns: dict[str, Pattern] = {
            "email": re.compile(r"[\w\.-]+@[\w\.-]+\.\w+"),
            "phone": re.compile(r"\b\d{10,}\b"),
            "api_key": re.compile(
                r"(?:api[_-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"]?[\w\-]+['\"]?",
                re.IGNORECASE,
            ),
            "password": re.compile(
                r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^'\"\s]+['\"]?",
                re.IGNORECASE,
            ),
            "bearer_token": re.compile(r"Bearer\s+[\w\-\.]+", re.IGNORECASE),
            "agent_secret": re.compile(r"(?:agent_secret|secret)['\"]?\s*[:=]\s*['\"]?[\w\-\.]+['\"]?"),
        }

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter a log record by sanitizing PII.

        Args:
            record: The log record to filter.

        Returns:
            True (always passes the record through after sanitization).
        """
        # Sanitize the log message
        if record.msg:
            record.msg = self._sanitize(str(record.msg))

        # Sanitize any exception information
        if record.exc_text:
            record.exc_text = self._sanitize(record.exc_text)

        # Sanitize formatted message
        if hasattr(record, "getMessage"):
            try:
                record.getMessage = lambda: self._sanitize(record.getMessage())
            except Exception:
                pass

        return True

    def _sanitize(self, text: str) -> str:
        """
        Remove PII from text.

        Args:
            text: The text to sanitize.

        Returns:
            The sanitized text with PII redacted.
        """
        if not text:
            return text

        sanitized = text

        # Apply each pattern filter
        for pattern_type, pattern in self.patterns.items():
            sanitized = pattern.sub("[REDACTED]", sanitized)

        return sanitized


def get_pii_filter() -> PIIFilter:
    """
    Create and return a PII filter instance.

    Returns:
        A PIIFilter instance ready to be attached to loggers.
    """
    return PIIFilter()
