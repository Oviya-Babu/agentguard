"""
Configuration and settings for the gateway.

Controls deployment mode, distributed safety guards, and operational parameters.
"""

import os
from enum import Enum

# Deployment mode: "single" or "distributed"
INSTANCE_MODE = os.getenv("INSTANCE_MODE", "single").lower()

# Circuit breaker settings
REDIS_CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("REDIS_CB_THRESHOLD", "5"))
REDIS_CIRCUIT_BREAKER_TIMEOUT = float(os.getenv("REDIS_CB_TIMEOUT", "10.0"))
TRIAGE_CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("TRIAGE_CB_THRESHOLD", "3"))
TRIAGE_CIRCUIT_BREAKER_TIMEOUT = float(os.getenv("TRIAGE_CB_TIMEOUT", "10.0"))

# Distributed safety (PATCH 4)
# If in distributed mode without Redis, enforce strict guards
DISTRIBUTED_STRICT_FALLBACK = INSTANCE_MODE == "distributed"

# Rate limiting (PATCH 10)
# Fallback rate limit when Redis unavailable (stricter in distributed mode)
FALLBACK_RATE_LIMIT_DEFAULT = 10000  # 10K req/s in single mode
FALLBACK_RATE_LIMIT_DISTRIBUTED = 100  # 100 req/s in distributed mode (strict)

FALLBACK_RATE_LIMIT = (
    FALLBACK_RATE_LIMIT_DISTRIBUTED
    if DISTRIBUTED_STRICT_FALLBACK
    else FALLBACK_RATE_LIMIT_DEFAULT
)

# mTLS (PATCH 7)
MTLS_VERIFY_CN_SAN = os.getenv("MTLS_VERIFY_CN_SAN", "true").lower() == "true"
EXPECTED_SERVICE_IDENTITY = os.getenv("EXPECTED_SERVICE_IDENTITY", "agentguard-triage")

# Logging (PATCH 9)
HASH_AGENT_ID_IN_LOGS = os.getenv("HASH_AGENT_ID_IN_LOGS", "false").lower() == "true"

# Request timeout (PATCH 6)
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30.0"))

# Timing normalization (PATCH 8)
MIN_RESPONSE_TIME = float(os.getenv("MIN_RESPONSE_TIME", "0.015"))  # 15ms


class DeploymentMode(str, Enum):
    """Deployment mode enum."""

    SINGLE = "single"
    DISTRIBUTED = "distributed"
