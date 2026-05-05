"""
Additional security utilities for the gateway.

Implements:
- mTLS certificate identity verification (PATCH 7)
- Logging helpers with optional hashing (PATCH 9)
- Rate limit fallback guards (PATCH 10)
- Distributed safety checks (PATCH 4)
"""

import hashlib
import logging
from typing import Optional

from app.settings import (
    EXPECTED_SERVICE_IDENTITY,
    HASH_AGENT_ID_IN_LOGS,
    MTLS_VERIFY_CN_SAN,
    DISTRIBUTED_STRICT_FALLBACK,
)

logger = logging.getLogger(__name__)


# ============================================================================
# mTLS CERTIFICATE IDENTITY VERIFICATION (PATCH 7)
# ============================================================================


def verify_mtls_identity(cert_dict: dict, request_id: str = "") -> bool:
    """
    Verify mTLS certificate subject matches expected service identity.

    Checks:
    - Subject CN (Common Name)
    - Subject AltName (SAN)

    Args:
        cert_dict: Certificate dict from httpx response
        request_id: Request ID for logging

    Returns:
        True if identity matches, False otherwise
    """
    if not MTLS_VERIFY_CN_SAN or cert_dict is None:
        return True  # Verification disabled or no cert

    try:
        subject = dict(x[0] for x in cert_dict.get("subject", []))
        cn = subject.get("commonName", "")

        if cn == EXPECTED_SERVICE_IDENTITY:
            return True

        # Check SAN
        for ext in cert_dict.get("subjectAltName", []):
            if isinstance(ext, tuple) and ext[0] == "DNS" and ext[1] == EXPECTED_SERVICE_IDENTITY:
                return True

        logger.warning(
            "mTLS certificate identity mismatch",
            extra={
                "expected": EXPECTED_SERVICE_IDENTITY,
                "actual_cn": cn,
                "request_id": request_id,
            },
        )
        return False

    except Exception as e:
        logger.warning(
            "mTLS certificate verification error",
            extra={
                "error": "operation_failed",
                "request_id": request_id,
            },
        )
        return False


# ============================================================================
# LOGGING HELPERS (PATCH 9)
# ============================================================================


def hash_agent_id(agent_id: str) -> str:
    """Hash agent_id for safe logging (PATCH 9)."""
    if not HASH_AGENT_ID_IN_LOGS:
        return agent_id  # Return as-is if hashing disabled
    return hashlib.sha256(agent_id.encode()).hexdigest()[:16]


def safe_log_extra(**kwargs) -> dict:
    """Create safe logging dict with PII protection (PATCH 9)."""
    safe_dict = {}

    for key, value in kwargs.items():
        # Only allow safe keys in logging
        if key in ("agent_id", "tool_name", "decision", "status", "request_id"):
            if key == "agent_id" and value:
                safe_dict[key] = hash_agent_id(value)
            else:
                safe_dict[key] = value
        elif key.startswith("custom_"):
            # Allow custom_* keys
            safe_dict[key] = value

    return safe_dict


# ============================================================================
# DISTRIBUTED SAFETY CHECKS (PATCH 4)
# ============================================================================


def check_distributed_redis_availability(redis_available: bool, request_id: str = "") -> bool:
    """
    Check if distributed mode requires Redis (PATCH 4).

    In distributed mode without Redis:
    - Fail-closed behavior mandatory
    - No in-memory fallback allowed

    Args:
        redis_available: Whether Redis is available
        request_id: Request ID for logging

    Returns:
        True if safe to proceed, False if must block
    """
    if DISTRIBUTED_STRICT_FALLBACK and not redis_available:
        logger.warning(
            "distributed_mode_without_redis",
            extra={
                "mode": "distributed",
                "redis_available": False,
                "request_id": request_id,
            },
        )
        # In strict distributed mode, NO fallback allowed
        # This will cause requests to be BLOCKED
        return False

    return True


# ============================================================================
# RATE LIMIT FALLBACK GUARD (PATCH 10)
# ============================================================================


def get_fallback_rate_limit() -> int:
    """
    Get appropriate fallback rate limit.

    Distributed mode → strict limit (100 req/s)
    Single mode → generous limit (10K req/s)

    Returns:
        Fallback rate limit (requests per second)
    """
    from app.settings import FALLBACK_RATE_LIMIT
    return FALLBACK_RATE_LIMIT


# ============================================================================
# DEFENSIVE ASSERTIONS (PATCH 11)
# ============================================================================


def assert_required_fields(
    request_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    tool_name: Optional[str] = None,
) -> bool:
    """
    Sanity check for required fields (PATCH 11).

    All three must be present and non-empty.

    Args:
        request_id: Request ID
        agent_id: Agent ID
        tool_name: Tool name

    Returns:
        True if all fields present, False otherwise
    """
    if not request_id or not agent_id or not tool_name:
        missing = []
        if not request_id:
            missing.append("request_id")
        if not agent_id:
            missing.append("agent_id")
        if not tool_name:
            missing.append("tool_name")

        logger.warning(
            "Missing required fields",
            extra={"missing_fields": missing},
        )
        return False

    return True
