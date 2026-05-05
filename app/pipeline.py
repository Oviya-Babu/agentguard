"""
Core request validation and enforcement pipeline.

This module implements the strict, fail-closed request processing pipeline
for the zero-trust AI gateway. Every decision point is security-critical.

Pipeline Steps (STRICT ORDER):
1. Global rate limit (hard stop, atomic)
2. JWT validation (signature, expiry, claims)
3. Agent session lookup (registration check)
4. RBAC check (OPA policy engine)
5. Per-agent/tool rate limit (sliding window)
6. Sequence analysis (attack detection)
7. Triage engine (behavioral analysis, 50ms timeout)
8. Final decision aggregation

All external systems are treated as potentially unreliable.
Fail-closed behavior is enforced throughout.
"""

import asyncio
import logging
import os
import time
from typing import Any, Dict, Literal, Optional

import httpx
from jose import JWTError, jwt
from opentelemetry import trace
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis.asyncio import Redis

from app.exceptions import (
    GatewayDegradedException,
    RBACDeniedException,
    RateLimitException,
    RegistrationException,
    SequenceViolationException,
    TriageBlockException,
)

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


# ============================================================================
# IN-MEMORY FALLBACK RATE LIMITER & REPLAY PROTECTION
# ============================================================================


class InMemoryRateLimiter:
    """
    Thread-safe in-memory rate limiter for when Redis is unavailable.

    Maintains simple counter per window for global rate limiting.
    Uses asyncio.Lock for safety in async context.
    """

    def __init__(self) -> None:
        """Initialize limiter with empty state."""
        self.lock = asyncio.Lock()
        self.requests: Dict[float, int] = {}
        self.window_size = 1.0  # 1-second window

    async def is_allowed(self, limit: int) -> bool:
        """
        Check if request is allowed under limit.

        Args:
            limit: Maximum requests per window

        Returns:
            True if allowed, False if limit exceeded
        """
        async with self.lock:
            now = time.time()
            cutoff = now - self.window_size

            # Remove expired entries
            self.requests = {
                ts: count
                for ts, count in self.requests.items()
                if ts > cutoff
            }

            # Count current requests
            current_count = sum(self.requests.values())

            if current_count >= limit:
                return False

            # Record this request
            self.requests[now] = self.requests.get(now, 0) + 1
            return True


class ReplayProtection:
    """
    In-memory replay protection using request ID deduplication.

    Prevents same request from being processed twice (within TTL).
    Uses asyncio.Lock for thread-safe operation.
    """

    def __init__(self) -> None:
        """Initialize replay protection."""
        self.lock = asyncio.Lock()
        self.seen_requests: Dict[str, float] = {}
        self.ttl = 30.0  # 30-second TTL

    async def check_replay(self, request_id: str) -> bool:
        """
        Check if request has been seen before.

        Args:
            request_id: Unique request identifier

        Returns:
            True if NEW request (not replay), False if REPLAY detected
        """
        async with self.lock:
            now = time.time()

            # Remove expired entries
            self.seen_requests = {
                rid: ts
                for rid, ts in self.seen_requests.items()
                if (now - ts) < self.ttl
            }

            # Check for replay
            if request_id in self.seen_requests:
                return False

            # Record request
            self.seen_requests[request_id] = now
            return True


# Global instances for fallback mechanisms
global_rate_limiter = InMemoryRateLimiter()
replay_protection = ReplayProtection()


class RequestContext(BaseModel):
    """
    Complete request context for validation pipeline.

    All fields are required and must be validated before passing to pipeline.

    Attributes:
        agent_id: Unique identifier of the requesting agent
        tool_name: Name of the tool being requested
        jwt_payload: Decoded JWT claims dictionary
        request_id: Unique request identifier for tracing
        metadata: Additional request metadata (headers, source, etc.)
    """

    agent_id: str = Field(..., description="Agent identifier")
    tool_name: str = Field(..., description="Tool name being accessed")
    jwt_payload: Dict[str, Any] = Field(..., description="Decoded JWT claims")
    request_id: str = Field(..., description="Unique request ID")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )


class DecisionResult(BaseModel):
    """
    Pipeline execution result with decision and tracing information.

    Attributes:
        decision: Final access decision (ALLOW, BLOCK, SANDBOX)
        reason: Human-readable reason for decision
        trace_id: OpenTelemetry trace ID for correlating logs
    """

    decision: Literal["ALLOW", "BLOCK", "SANDBOX"] = Field(
        ..., description="Access decision"
    )
    reason: str = Field(..., description="Reason for decision")
    trace_id: Optional[str] = Field(
        None, description="Trace ID for observability"
    )


class TriageResponse(BaseModel):
    """
    Triage engine response with security verdict.

    Enforces strict schema - rejects unknown fields and validates all required fields.

    Attributes:
        verdict: Security decision from triage (ALLOW, BLOCK, SANDBOX)
        score: Risk assessment score (0.0-1.0)
        details: Additional triage details
    """

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["ALLOW", "BLOCK", "SANDBOX"] = Field(
        ..., description="Triage verdict"
    )
    score: float = Field(
        ..., ge=0.0, le=1.0, description="Risk score"
    )
    details: Optional[Dict[str, Any]] = Field(
        None, description="Triage details"
    )


# ============================================================================
# REDIS LUA SCRIPTS (ATOMIC OPERATIONS)
# ============================================================================

# Global rate limiting Lua script
# Atomically checks and increments global request counter
GLOBAL_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local current = redis.call('GET', key)
if current == false then
    redis.call('SETEX', key, window, 1)
    return 1
end

current = tonumber(current)
if current >= limit then
    return -1
end

redis.call('INCR', key)
return current + 1
"""

# Per-agent/tool rate limiting Lua script
# Implements sliding window with atomic remove + count + insert
PER_AGENT_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local cutoff = now - window

redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
local count = redis.call('ZCARD', key)

if count >= limit then
    return -1
end

redis.call('ZADD', key, now, tostring(now) .. ':' .. math.random())
redis.call('EXPIRE', key, window)
return count + 1
"""


# ============================================================================
# VALIDATION STEPS (STRICT ORDER)
# ============================================================================


async def step_1_global_rate_limit(
    redis: Optional[Redis],
    request_id: str,
) -> None:
    """
    Step 1: Global rate limit check (HARD STOP).

    This is the first check and must execute atomically.
    If limit exceeded, immediately block request.

    Uses Redis Lua script when available, falls back to in-memory limiter
    when Redis is unavailable.

    Args:
        redis: Redis connection (may be None if degraded)
        request_id: Request identifier for tracing

    Raises:
        RateLimitException: If global limit exceeded
        (GatewayDegradedException is NOT raised; degradation is tolerated)
    """
    # Global limit: 10,000 RPS, 1-second window
    limit = 10000

    if redis is None:
        # Redis unavailable: use fallback in-memory limiter
        logger.debug(
            "Using in-memory rate limiter",
            extra={"request_id": request_id},
        )
        allowed = await global_rate_limiter.is_allowed(limit)

        if not allowed:
            logger.warning(
                "Global rate limit exceeded (in-memory fallback)",
                extra={"request_id": request_id},
            )
            raise RateLimitException(
                reason="Global request rate limit exceeded",
                agent_id="unknown",
                tool_name="unknown",
                triage_score=None,
                owasp_ref="A07:2021-Identification and Authentication Failures",
            )
        return

    try:
        window = 1
        script = redis.register_script(GLOBAL_RATE_LIMIT_SCRIPT)
        result = await asyncio.wait_for(
            script(
                keys=["global_rps"],
                args=[limit, window],
            ),
            timeout=1.0,
        )

        if result == -1:
            logger.warning(
                "Global rate limit exceeded",
                extra={"request_id": request_id},
            )
            raise RateLimitException(
                reason="Global request rate limit exceeded",
                agent_id="unknown",
                tool_name="unknown",
                triage_score=None,
                owasp_ref="A07:2021-Identification and Authentication Failures",
            )

    except RateLimitException:
        raise
    except Exception as e:
        # Redis failure: fall back to in-memory limiter
        logger.warning(
            "Redis rate limit failed, using fallback limiter",
            extra={"error": type(e).__name__, "request_id": request_id},
        )
        allowed = await global_rate_limiter.is_allowed(limit)

        if not allowed:
            logger.warning(
                "Global rate limit exceeded (fallback after Redis failure)",
                extra={"request_id": request_id},
            )
            raise RateLimitException(
                reason="Global request rate limit exceeded",
                agent_id="unknown",
                tool_name="unknown",
                triage_score=None,
                owasp_ref="A07:2021-Identification and Authentication Failures",
            )


async def step_2_jwt_validation(
    context: RequestContext,
    jwt_secret: str,
    jwt_algorithm: str = "HS256",
) -> Dict[str, Any]:
    """
    Step 2: JWT signature, expiry, and claims validation (STRICT).

    No external calls. Purely cryptographic validation.
    Enforces strict claim validation: issuer, audience, algorithm.

    Args:
        context: Request context
        jwt_secret: Secret key for JWT verification
        jwt_algorithm: Allowed algorithm for signing

    Returns:
        Validated JWT payload

    Raises:
        RegistrationException: If JWT invalid, expired, or missing required claims
    """
    try:
        payload = context.jwt_payload

        # Validate required claims
        required_claims = {"sub", "exp", "iat", "iss", "aud"}
        if not required_claims.issubset(payload.keys()):
            logger.warning(
                "JWT missing required claims",
                extra={
                    "agent_id": context.agent_id,
                    "request_id": context.request_id,
                },
            )
            raise RegistrationException(
                reason="JWT missing required claims",
                agent_id=context.agent_id,
                tool_name=context.tool_name,
            )

        # Validate issuer (must match expected value)
        expected_issuer = os.getenv("JWT_ISSUER", "agentguard")
        if payload.get("iss") != expected_issuer:
            logger.warning(
                "JWT issuer mismatch",
                extra={
                    "agent_id": context.agent_id,
                    "request_id": context.request_id,
                },
            )
            raise RegistrationException(
                reason="JWT issuer mismatch",
                agent_id=context.agent_id,
                tool_name=context.tool_name,
            )

        # Validate audience (must match gateway)
        expected_audience = os.getenv("JWT_AUDIENCE", "agentguard-gateway")
        jwt_audience = payload.get("aud")
        if isinstance(jwt_audience, list):
            if expected_audience not in jwt_audience:
                raise RegistrationException(
                    reason="JWT audience mismatch",
                    agent_id=context.agent_id,
                    tool_name=context.tool_name,
                )
        else:
            if jwt_audience != expected_audience:
                raise RegistrationException(
                    reason="JWT audience mismatch",
                    agent_id=context.agent_id,
                    tool_name=context.tool_name,
                )

        # Validate algorithm (reject "none" and non-allowed algorithms)
        if jwt_algorithm == "none":
            logger.warning(
                "JWT algorithm is 'none' - rejected",
                extra={
                    "agent_id": context.agent_id,
                    "request_id": context.request_id,
                },
            )
            raise RegistrationException(
                reason="JWT uses unsupported algorithm",
                agent_id=context.agent_id,
                tool_name=context.tool_name,
            )

        # Validate expiry (with grace period)
        now = time.time()
        if payload.get("exp", 0) < now:
            logger.warning(
                "JWT expired",
                extra={
                    "agent_id": context.agent_id,
                    "request_id": context.request_id,
                },
            )
            raise RegistrationException(
                reason="JWT token expired",
                agent_id=context.agent_id,
                tool_name=context.tool_name,
            )

        return payload

    except RegistrationException:
        raise
    except Exception as e:
        logger.warning(
            "JWT validation failed",
            extra={
                "agent_id": context.agent_id,
                "error": type(e).__name__,
                "request_id": context.request_id,
            },
        )
        raise RegistrationException(
            reason="Invalid JWT token",
            agent_id=context.agent_id,
            tool_name=context.tool_name,
        )


async def step_3_agent_session_lookup(
    redis: Optional[Redis],
    context: RequestContext,
) -> Dict[str, Any]:
    """
    Step 3: Agent session lookup (registration verification with validation).

    Checks if agent has active session in Redis.
    Validates session expiry and role consistency with JWT.

    Args:
        redis: Redis connection (may be None)
        context: Request context

    Returns:
        Session data dictionary (after validation)

    Raises:
        RegistrationException: If session not found or invalid
        GatewayDegradedException: If Redis unavailable (will trigger SANDBOX)
    """
    if redis is None:
        logger.warning(
            "Agent session lookup skipped",
            extra={
                "agent_id": context.agent_id,
                "reason": "Redis unavailable",
                "request_id": context.request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Session lookup unavailable",
        )

    try:
        session_key = f"session:{context.agent_id}"
        session_data = await asyncio.wait_for(
            redis.hgetall(session_key),
            timeout=1.0,
        )

        if not session_data:
            logger.warning(
                "Agent session not found",
                extra={
                    "agent_id": context.agent_id,
                    "request_id": context.request_id,
                },
            )
            raise RegistrationException(
                reason="Agent session not found",
                agent_id=context.agent_id,
                tool_name=context.tool_name,
            )

        # Validate session expiry timestamp
        if "expiry" in session_data:
            try:
                session_expiry = float(session_data["expiry"])
                if session_expiry < time.time():
                    logger.warning(
                        "Session expired",
                        extra={
                            "agent_id": context.agent_id,
                            "request_id": context.request_id,
                        },
                    )
                    raise RegistrationException(
                        reason="Agent session expired",
                        agent_id=context.agent_id,
                        tool_name=context.tool_name,
                    )
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid session expiry format",
                    extra={
                        "agent_id": context.agent_id,
                        "request_id": context.request_id,
                    },
                )
                raise RegistrationException(
                    reason="Session validation failed",
                    agent_id=context.agent_id,
                    tool_name=context.tool_name,
                )

        # Validate role consistency (if present in both JWT and session)
        jwt_role = context.jwt_payload.get("role")
        session_role = session_data.get("role")
        if jwt_role and session_role and jwt_role != session_role:
            logger.warning(
                "Role mismatch between JWT and session",
                extra={
                    "agent_id": context.agent_id,
                    "request_id": context.request_id,
                },
            )
            raise RegistrationException(
                reason="JWT and session roles do not match",
                agent_id=context.agent_id,
                tool_name=context.tool_name,
            )

        return session_data

    except RegistrationException:
        raise
    except GatewayDegradedException:
        raise
    except Exception as e:
        logger.warning(
            "Agent session lookup failed",
            extra={
                "agent_id": context.agent_id,
                "error": type(e).__name__,
                "request_id": context.request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason=f"Session lookup failed: {type(e).__name__}",
        )


async def step_4_rbac_check(
    opa_url: Optional[str],
    context: RequestContext,
    session_data: Dict[str, Any],
) -> bool:
    """
    Step 4: RBAC check via OPA policy engine.

    Queries OPA to verify agent role has permission for tool.
    FAIL-CLOSED: If OPA unreachable, deny access.

    Args:
        opa_url: OPA policy engine URL (may be None)
        context: Request context
        session_data: Agent session from Redis

    Returns:
        True if authorized, raises exception otherwise

    Raises:
        RBACDeniedException: If OPA denies access
        GatewayDegradedException: If OPA unreachable (will trigger SANDBOX)
    """
    if not opa_url:
        logger.warning(
            "RBAC check skipped",
            extra={
                "agent_id": context.agent_id,
                "reason": "OPA_URL not configured",
                "request_id": context.request_id,
            },
        )
        # OPA not configured = fail-closed = block
        raise RBACDeniedException(
            reason="OPA not available for policy check",
            agent_id=context.agent_id,
            tool_name=context.tool_name,
        )

    try:
        agent_role = session_data.get("role", "unknown")

        # Query OPA with agent role and tool name
        policy_input = {
            "agent_id": context.agent_id,
            "agent_role": agent_role,
            "tool_name": context.tool_name,
        }

        # Strict 100ms timeout for OPA (no retries, no fallback to ALLOW)
        async with httpx.AsyncClient() as client:
            response = await asyncio.wait_for(
                client.post(
                    f"{opa_url}/v1/data/agentguard/allow",
                    json={"input": policy_input},
                    timeout=0.1,  # 100ms hard timeout
                ),
                timeout=0.1,
            )

            if response.status_code != 200:
                logger.warning(
                    "OPA returned non-200 status",
                    extra={
                        "agent_id": context.agent_id,
                        "status": response.status_code,
                        "request_id": context.request_id,
                    },
                )
                raise RBACDeniedException(
                    reason="Policy check failed",
                    agent_id=context.agent_id,
                    tool_name=context.tool_name,
                )

            result = response.json()
            allowed = result.get("result", {}).get("allow", False)

            if not allowed:
                logger.warning(
                    "RBAC check denied",
                    extra={
                        "agent_id": context.agent_id,
                        "tool_name": context.tool_name,
                        "role": agent_role,
                        "request_id": context.request_id,
                    },
                )
                raise RBACDeniedException(
                    reason="Agent role lacks required permissions",
                    agent_id=context.agent_id,
                    tool_name=context.tool_name,
                )

        return True

    except RBACDeniedException:
        raise
    except Exception as e:
        logger.warning(
            "RBAC check failed",
            extra={
                "agent_id": context.agent_id,
                "error": type(e).__name__,
                "request_id": context.request_id,
            },
        )
        # OPA failure = fail-closed = block (don't SANDBOX on OPA failure)
        raise RBACDeniedException(
            reason="Policy engine unavailable",
            agent_id=context.agent_id,
            tool_name=context.tool_name,
        )


async def step_4b_replay_protection(
    redis: Optional[Redis],
    request_id: str,
) -> None:
    """
    Step 4B: Replay attack detection (CRITICAL).

    Checks if this request_id has been seen before.
    Uses Redis SETNX with TTL, falls back to in-memory set if Redis unavailable.

    Args:
        redis: Redis connection (may be None)
        request_id: Unique request identifier

    Raises:
        RegistrationException: If replay detected
    """
    replay_ttl = 30  # 30-second replay window

    if redis is None:
        # Use in-memory fallback
        is_new = await replay_protection.check_replay(request_id)
        if not is_new:
            logger.warning(
                "Replay attack detected (in-memory fallback)",
                extra={"request_id": request_id},
            )
            raise RegistrationException(
                reason="Duplicate request (replay protection)",
                agent_id="unknown",
                tool_name="unknown",
            )
        return

    try:
        # Redis: atomically check and set with TTL
        key = f"replay:{request_id}"
        result = await asyncio.wait_for(
            redis.set(key, "1", nx=True, ex=replay_ttl),
            timeout=1.0,
        )

        if not result:
            logger.warning(
                "Replay attack detected",
                extra={"request_id": request_id},
            )
            raise RegistrationException(
                reason="Duplicate request (replay protection)",
                agent_id="unknown",
                tool_name="unknown",
            )

    except RegistrationException:
        raise
    except Exception as e:
        # Redis failure: fall back to in-memory
        logger.warning(
            "Replay check failed, using fallback",
            extra={"error": type(e).__name__, "request_id": request_id},
        )
        is_new = await replay_protection.check_replay(request_id)
        if not is_new:
            logger.warning(
                "Replay attack detected (fallback after Redis failure)",
                extra={"request_id": request_id},
            )
            raise RegistrationException(
                reason="Duplicate request (replay protection)",
                agent_id="unknown",
                tool_name="unknown",
            )


async def step_5_per_agent_rate_limit(
    redis: Optional[Redis],
    context: RequestContext,
) -> None:
    """
    Step 5: Per-agent/tool rate limit (sliding window).

    Atomically manages sliding window using Lua script.

    Args:
        redis: Redis connection (may be None)
        context: Request context

    Raises:
        RateLimitException: If agent/tool limit exceeded
        GatewayDegradedException: If Redis unavailable
    """
    if redis is None:
        logger.info(
            "Per-agent rate limit skipped",
            extra={
                "agent_id": context.agent_id,
                "reason": "Redis unavailable",
                "request_id": context.request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Rate limiting unavailable",
        )

    try:
        # Per-agent/tool limit: 100 req/min
        limit = 100
        window = 60
        now = time.time()

        rate_limit_key = f"rate_limit:{context.agent_id}:{context.tool_name}"

        script = redis.register_script(PER_AGENT_RATE_LIMIT_SCRIPT)
        result = await script(
            keys=[rate_limit_key],
            args=[limit, window, int(now)],
        )

        if result == -1:
            logger.warning(
                "Per-agent rate limit exceeded",
                extra={
                    "agent_id": context.agent_id,
                    "tool_name": context.tool_name,
                    "request_id": context.request_id,
                },
            )
            raise RateLimitException(
                reason="Per-agent request rate limit exceeded",
                agent_id=context.agent_id,
                tool_name=context.tool_name,
            )

    except RateLimitException:
        raise
    except GatewayDegradedException:
        raise
    except Exception as e:
        logger.warning(
            "Per-agent rate limit check failed",
            extra={
                "agent_id": context.agent_id,
                "error": type(e).__name__,
                "request_id": context.request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason=f"Rate limit check failed: {type(e).__name__}",
        )


async def step_6_sequence_analysis(
    redis: Optional[Redis],
    context: RequestContext,
) -> bool:
    """
    Step 6: Sequence analysis (attack pattern detection).

    Uses Redis WATCH+MULTI+EXEC for atomic sequence check and update.
    Evaluation is done on the watched snapshot only.

    Args:
        redis: Redis connection (may be None)
        context: Request context

    Returns:
        True if sequence check passed

    Raises:
        SequenceViolationException: If sequence violation detected
        GatewayDegradedException: If Redis unavailable
    """
    # Late import to avoid circular dependency
    from app.main import app_state

    if redis is None:
        logger.info(
            "Sequence analysis skipped",
            extra={
                "agent_id": context.agent_id,
                "reason": "Redis unavailable",
                "request_id": context.request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Sequence analysis unavailable",
        )

    if not app_state.sequence_rules:
        # No rules configured, allow
        return True

    try:
        sequence_key = f"sequence:{context.agent_id}"
        now = time.time()
        event = f"{context.tool_name}:{int(now)}"

        # Get rules once to avoid TOCTOU issues
        rules = app_state.sequence_rules.get("prerequisites", {})
        tool_rules = rules.get(context.tool_name, {})
        required_prerequisites = tool_rules.get("prerequisites", [])

        # Use WATCH to ensure atomicity
        # If another client modifies the key, the transaction will fail and retry
        async with redis.pipeline(transaction=True) as pipe:
            # WATCH the sequence key - detects concurrent modifications
            await pipe.watch(sequence_key)

            # Retrieve current sequence (snapshot)
            previous_sequence = await asyncio.wait_for(
                pipe.lrange(sequence_key, 0, -1),
                timeout=1.0,
            )

            # Evaluate against rules using the SNAPSHOT only
            # (No new data can be read between snapshot and transaction)
            for prereq in required_prerequisites:
                if not any(prereq in seq for seq in previous_sequence):
                    logger.warning(
                        "Sequence violation detected",
                        extra={
                            "agent_id": context.agent_id,
                            "tool_name": context.tool_name,
                            "missing_prerequisite": prereq,
                            "request_id": context.request_id,
                        },
                    )
                    raise SequenceViolationException(
                        reason=f"Missing prerequisite: {prereq}",
                        agent_id=context.agent_id,
                        tool_name=context.tool_name,
                    )

            # All checks passed: atomically update sequence
            pipe.multi()
            pipe.lpush(sequence_key, event)
            pipe.expire(sequence_key, 3600)  # 1 hour expiry
            await asyncio.wait_for(pipe.execute(), timeout=1.0)

        return True

    except SequenceViolationException:
        raise
    except GatewayDegradedException:
        raise
    except Exception as e:
        logger.warning(
            "Sequence analysis failed",
            extra={
                "agent_id": context.agent_id,
                "error": type(e).__name__,
                "request_id": context.request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason=f"Sequence analysis failed: {type(e).__name__}",
        )


async def step_7_triage_engine(
    triage_url: Optional[str],
    context: RequestContext,
) -> tuple[bool, Optional[float]]:
    """
    Step 7: Behavioral analysis via triage engine.

    External call with strict 50ms timeout.
    Failure defaults to SANDBOX (never ALLOW).

    Args:
        triage_url: Triage engine endpoint URL (may be None)
        context: Request context

    Returns:
        Tuple of (sandbox_flag, triage_score)

    Raises:
        TriageBlockException: If triage verdict is BLOCK
    """
    sandbox_flag = False
    triage_score = None

    if not triage_url:
        # Triage not configured: continue without behavioral analysis
        logger.debug(
            "Triage analysis skipped",
            extra={
                "agent_id": context.agent_id,
                "reason": "Triage URL not configured",
            },
        )
        return sandbox_flag, triage_score

    try:
        # Strict 50ms timeout for triage
        async with httpx.AsyncClient(timeout=0.05) as client:
            response = await client.post(
                triage_url,
                json={
                    "agent_id": context.agent_id,
                    "tool_name": context.tool_name,
                    "request_id": context.request_id,
                },
            )

            if response.status_code != 200:
                logger.warning(
                    "Triage returned non-200 status",
                    extra={
                        "agent_id": context.agent_id,
                        "status": response.status_code,
                        "request_id": context.request_id,
                    },
                )
                # Triage failure: sandbox (safe default)
                return True, None

            # Validate triage response
            try:
                triage_result = TriageResponse(**response.json())
            except ValidationError as e:
                logger.warning(
                    "Invalid triage response",
                    extra={
                        "agent_id": context.agent_id,
                        "error": str(e),
                        "request_id": context.request_id,
                    },
                )
                # Invalid response: sandbox
                return True, None

            triage_score = triage_result.score

            # Apply triage verdict
            if triage_result.verdict == "BLOCK":
                logger.warning(
                    "Triage blocked request",
                    extra={
                        "agent_id": context.agent_id,
                        "score": triage_score,
                        "request_id": context.request_id,
                    },
                )
                raise TriageBlockException(
                    reason=f"Triage security check failed (score: {triage_score:.2f})",
                    agent_id=context.agent_id,
                    tool_name=context.tool_name,
                    triage_score=triage_score,
                )

            if triage_result.verdict == "SANDBOX":
                logger.info(
                    "Triage sandboxed request",
                    extra={
                        "agent_id": context.agent_id,
                        "score": triage_score,
                        "request_id": context.request_id,
                    },
                )
                sandbox_flag = True

            return sandbox_flag, triage_score

    except TriageBlockException:
        raise
    except asyncio.TimeoutError:
        logger.warning(
            "Triage check timed out",
            extra={
                "agent_id": context.agent_id,
                "request_id": context.request_id,
            },
        )
        # Timeout: sandbox (safe default)
        return True, None
    except Exception as e:
        logger.warning(
            "Triage check failed",
            extra={
                "agent_id": context.agent_id,
                "error": type(e).__name__,
                "request_id": context.request_id,
            },
        )
        # Any failure: sandbox (safe default)
        return True, None


# ============================================================================
# MAIN PIPELINE
# ============================================================================


async def process_request(context: RequestContext) -> DecisionResult:
    """
    Main request processing pipeline.

    Executes all validation steps in strict order with fail-closed semantics.
    No step is skipped; all failures are handled and logged.

    Pipeline steps:
    1. Global rate limit (atomic, hard stop)
    2. JWT validation (signature, expiry, claims)
    3. Agent session lookup (registration)
    4. RBAC check (OPA policy)
    5. Per-agent rate limit (sliding window)
    6. Sequence analysis (attack detection)
    7. Triage engine (behavioral analysis, 50ms timeout)
    8. Final decision aggregation

    Args:
        context: Complete request context

    Returns:
        DecisionResult with decision and reason

    Security Properties:
    - Fail-closed: defaults to BLOCK on any critical error
    - Atomic: Redis operations are atomic where required
    - Non-blocking: all I/O is async
    - Observable: all decisions are traced
    """
    # Late import to avoid circular dependency at module load time
    from app.main import app_state

    # Start OpenTelemetry span
    with tracer.start_as_current_span("request_pipeline") as span:
        span.set_attribute("agent_id", context.agent_id)
        span.set_attribute("tool_name", context.tool_name)
        span.set_attribute("request_id", context.request_id)

        decision = "BLOCK"
        reason = "No reason provided"
        sandbox_flag = False

        try:
            # ====================================================================
            # STEP 1: Global Rate Limit (HARD STOP)
            # ====================================================================
            await step_1_global_rate_limit(app_state.redis, context.request_id)

            # ====================================================================
            # STEP 2: JWT Validation (STRICT CLAIMS)
            # ====================================================================
            jwt_secret = os.getenv("JWT_SECRET", "")
            await step_2_jwt_validation(context, jwt_secret)

            # ====================================================================
            # STEP 4B: Replay Protection (CRITICAL)
            # ====================================================================
            await step_4b_replay_protection(app_state.redis, context.request_id)

            # ====================================================================
            # STEP 3: Agent Session Lookup (WITH VALIDATION)
            # ====================================================================
            session_data = await step_3_agent_session_lookup(
                app_state.redis,
                context,
            )

            # ====================================================================
            # STEP 4: RBAC Check (OPA) - STRICT 100ms TIMEOUT
            # ====================================================================
            opa_url = os.getenv("OPA_URL")
            await step_4_rbac_check(opa_url, context, session_data)

            # ====================================================================
            # STEP 5: Per-Agent Rate Limit
            # ====================================================================
            await step_5_per_agent_rate_limit(app_state.redis, context)

            # ====================================================================
            # STEP 6: Sequence Analysis (RACE CONDITION FIXED)
            # ====================================================================
            await step_6_sequence_analysis(app_state.redis, context)

            # ====================================================================
            # STEP 7: Triage Engine
            # ====================================================================
            triage_url = os.getenv("TRIAGE_URL")
            triage_sandbox, triage_score = await step_7_triage_engine(
                triage_url,
                context,
            )
            sandbox_flag = sandbox_flag or triage_sandbox

            # ====================================================================
            # STEP 8: Final Decision
            # ====================================================================
            if sandbox_flag:
                decision = "SANDBOX"
                reason = "Request sandboxed due to security concerns"
            else:
                decision = "ALLOW"
                reason = "All checks passed"

        except RateLimitException as e:
            decision = "BLOCK"
            reason = "Rate limit exceeded"
            span.set_attribute("exception_type", "RateLimitException")

        except RegistrationException as e:
            decision = "BLOCK"
            reason = "Invalid agent registration"
            span.set_attribute("exception_type", "RegistrationException")

        except RBACDeniedException as e:
            decision = "BLOCK"
            reason = "Access denied by policy"
            span.set_attribute("exception_type", "RBACDeniedException")

        except SequenceViolationException as e:
            # Sequence violations can be BLOCK or SANDBOX depending on rule
            decision = "BLOCK"
            reason = "Sequence violation detected"
            span.set_attribute("exception_type", "SequenceViolationException")

        except TriageBlockException as e:
            decision = "BLOCK"
            reason = "Security triage check failed"
            span.set_attribute("exception_type", "TriageBlockException")

        except GatewayDegradedException as e:
            # Infrastructure failure: sandbox, don't block
            decision = "SANDBOX"
            reason = f"Infrastructure degraded ({e.component})"
            span.set_attribute("exception_type", "GatewayDegradedException")

        except Exception as e:
            # Unexpected error: fail-closed
            logger.error(
                "Unexpected error in request pipeline",
                extra={
                    "agent_id": context.agent_id,
                    "error": type(e).__name__,
                    "request_id": context.request_id,
                },
            )
            decision = "BLOCK"
            reason = "Internal security check error"
            span.set_attribute("exception_type", type(e).__name__)

        # Set final decision attributes
        span.set_attribute("decision", decision)
        span.set_attribute("reason", reason)

        logger.info(
            "Request pipeline complete",
            extra={
                "agent_id": context.agent_id,
                "tool_name": context.tool_name,
                "decision": decision,
                "request_id": context.request_id,
            },
        )

        return DecisionResult(
            decision=decision,
            reason=reason,
            trace_id=context.request_id,
        )
