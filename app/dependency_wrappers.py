"""
Defensive isolation wrappers for external dependencies.

This module provides isolated wrapper functions for all external system
interactions (Redis, OPA). These wrappers catch ALL failures and convert
them to appropriate security exceptions, ensuring no raw exceptions escape
to the pipeline and that fail-closed behavior is maintained.

Design principle: Catch early, translate to security exceptions, log
structured events, and maintain system resilience.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional

import httpx
import redis.asyncio as redis_async
from redis.exceptions import (
    ConnectionError,
    RedisError,
    ResponseError,
    TimeoutError,
)

from app.exceptions import (
    GatewayDegradedException,
    RBACDeniedException,
)

logger = logging.getLogger(__name__)

# Global OPA client (connection pooling, avoid per-request creation)
opa_client: Optional[httpx.AsyncClient] = None


# ============================================================================
# CLIENT LIFECYCLE MANAGEMENT (PATCH 1)
# ============================================================================


async def init_clients() -> None:
    """Initialize all global HTTP clients. Call during app startup."""
    global opa_client
    logger.info("Initializing HTTP clients...")
    opa_client = httpx.AsyncClient(timeout=0.1)
    logger.info("✓ HTTP clients initialized")


async def close_clients() -> None:
    """Close all global HTTP clients. Call during app shutdown."""
    global opa_client
    logger.info("Closing HTTP clients...")
    if opa_client is not None:
        try:
            await opa_client.aclose()
            logger.info("✓ HTTP clients closed")
        except Exception as e:
            logger.warning(
                "Error closing HTTP client",
                extra={"error": "operation_failed"},
            )


async def get_opa_client() -> httpx.AsyncClient:
    """Get shared OPA client (must call init_clients first)."""
    global opa_client
    if opa_client is None:
        raise RuntimeError("HTTP clients not initialized. Call init_clients() first.")
    return opa_client


# ============================================================================
# LIGHTWEIGHT CIRCUIT BREAKER (PATCH 2 - REDIS + TRIAGE RESILIENCE)
# ============================================================================


class CircuitBreaker:
    """Lightweight circuit breaker for external services.
    
    Behavior:
    - CLOSED: Normal operation
    - OPEN: Skip calls, return safe default
    - HALF_OPEN: Allow single test call
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 10.0,
        half_open_max_calls: int = 1,
    ) -> None:
        """Initialize circuit breaker."""
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "closed"
        self.half_open_calls = 0
        self.lock = asyncio.Lock()

    async def call(self, func, *args, **kwargs):
        """Execute function if circuit allows."""
        async with self.lock:
            if self.state == "open":
                if (
                    self.last_failure_time is not None
                    and time.time() - self.last_failure_time >= self.recovery_timeout
                ):
                    self.state = "half_open"
                    self.half_open_calls = 0
                    logger.info(
                        "Circuit breaker HALF_OPEN (recovery attempt)",
                        extra={"service": getattr(func, "__name__", "unknown")},
                    )
                else:
                    raise GatewayDegradedException(
                        component="circuit_breaker",
                        reason="Service temporarily unavailable",
                    )

            if self.state == "half_open":
                if self.half_open_calls >= self.half_open_max_calls:
                    raise GatewayDegradedException(
                        component="circuit_breaker",
                        reason="Service recovery failed",
                    )
                self.half_open_calls += 1

        try:
            result = await func(*args, **kwargs)
            async with self.lock:
                if self.state == "half_open":
                    self.state = "closed"
                    self.failure_count = 0
                    logger.info(
                        "Circuit breaker CLOSED (recovered)",
                        extra={"service": getattr(func, "__name__", "unknown")},
                    )
            return result
        except Exception as e:
            async with self.lock:
                self.failure_count += 1
                self.last_failure_time = time.time()
                if self.failure_count >= self.failure_threshold and self.state != "open":
                    self.state = "open"
                    logger.warning(
                        "Circuit breaker OPEN (too many failures)",
                        extra={
                            "service": getattr(func, "__name__", "unknown"),
                            "failures": self.failure_count,
                        },
                    )
            raise


# Circuit breaker instances
redis_circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=10.0)
triage_circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)


# ============================================================================
# REDIS WRAPPERS (ISOLATED FAILURE HANDLING)
# ============================================================================


async def redis_hgetall(
    redis_client: Optional[redis_async.Redis],
    key: str,
    request_id: str,
) -> Dict[str, Any]:
    """
    Safely retrieve hash data from Redis.

    Wraps HGETALL operation with error handling and conversion to
    GatewayDegradedException on failure.

    Args:
        redis_client: Redis async client (may be None)
        key: Hash key to retrieve
        request_id: Request ID for tracing

    Returns:
        Dictionary of hash fields and values (empty dict if key not found)

    Raises:
        GatewayDegradedException: If Redis operation fails
    """
    if redis_client is None:
        raise GatewayDegradedException(
            component="redis",
            reason="Redis client unavailable",
        )

    try:
        result = await asyncio.wait_for(
            redis_client.hgetall(key), timeout=0.2
        )
        return result or {}

    except asyncio.TimeoutError:
        logger.warning(
            "Redis HGETALL timeout",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="HGETALL operation timeout",
        )

    except TimeoutError:
        logger.warning(
            "Redis HGETALL timeout",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="HGETALL operation timeout",
        )

    except ConnectionError:
        logger.warning(
            "Redis HGETALL connection error",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis connection failed",
        )

    except ResponseError:
        logger.warning(
            "Redis HGETALL response error",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis returned error response",
        )

    except RedisError as e:
        logger.warning(
            "Redis HGETALL failed",
            extra={
                "error": "operation_failed",
                "key": key,
                "request_id": request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis operation failed",
        )


async def redis_set(
    redis_client: Optional[redis_async.Redis],
    key: str,
    value: str,
    ex: Optional[int] = None,
    nx: bool = False,
    request_id: str = "",
) -> bool:
    """
    Safely set a key in Redis (with optional NX and EX).

    Wraps SET operation for atomic checks (replay protection, etc).

    Args:
        redis_client: Redis async client (may be None)
        key: Key to set
        value: Value to set
        ex: Expiration time in seconds (optional)
        nx: Only set if key doesn't exist (optional)
        request_id: Request ID for tracing

    Returns:
        True if key was set, False if NX prevented it

    Raises:
        GatewayDegradedException: If Redis operation fails
    """
    if redis_client is None:
        raise GatewayDegradedException(
            component="redis",
            reason="Redis client unavailable",
        )

    try:
        result = await asyncio.wait_for(
            redis_client.set(key, value, ex=ex, nx=nx), timeout=0.2
        )
        return bool(result)

    except asyncio.TimeoutError:
        logger.warning(
            "Redis SET timeout",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="SET operation timeout",
        )

    except TimeoutError:
        logger.warning(
            "Redis SET timeout",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="SET operation timeout",
        )

    except ConnectionError:
        logger.warning(
            "Redis SET connection error",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis connection failed",
        )

    except ResponseError:
        logger.warning(
            "Redis SET response error",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis returned error response",
        )

    except RedisError as e:
        logger.warning(
            "Redis SET failed",
            extra={
                "error": "operation_failed",
                "key": key,
                "request_id": request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis operation failed",
        )


async def redis_lrange(
    redis_client: Optional[redis_async.Redis],
    key: str,
    start: int = 0,
    end: int = -1,
    request_id: str = "",
) -> list:
    """
    Safely retrieve a range of elements from a Redis list.

    Wraps LRANGE operation for sequence tracking.

    Args:
        redis_client: Redis async client (may be None)
        key: List key to retrieve
        start: Start index (default 0)
        end: End index (default -1 for all)
        request_id: Request ID for tracing

    Returns:
        List of elements (empty if key doesn't exist)

    Raises:
        GatewayDegradedException: If Redis operation fails
    """
    if redis_client is None:
        raise GatewayDegradedException(
            component="redis",
            reason="Redis client unavailable",
        )

    try:
        result = await asyncio.wait_for(
            redis_client.lrange(key, start, end), timeout=0.2
        )
        return result or []

    except asyncio.TimeoutError:
        logger.warning(
            "Redis LRANGE timeout",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="LRANGE operation timeout",
        )

    except TimeoutError:
        logger.warning(
            "Redis LRANGE timeout",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="LRANGE operation timeout",
        )

    except ConnectionError:
        logger.warning(
            "Redis LRANGE connection error",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis connection failed",
        )

    except ResponseError:
        logger.warning(
            "Redis LRANGE response error",
            extra={"key": key, "request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis returned error response",
        )

    except RedisError as e:
        logger.warning(
            "Redis LRANGE failed",
            extra={
                "error": "operation_failed",
                "key": key,
                "request_id": request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis operation failed",
        )


async def redis_lua_script(
    redis_client: Optional[redis_async.Redis],
    script: str,
    keys: list,
    args: list,
    request_id: str = "",
) -> Any:
    """
    Safely execute a Lua script in Redis.

    Wraps Redis Lua script execution with error handling.

    Args:
        redis_client: Redis async client (may be None)
        script: Lua script code
        keys: Script keys
        args: Script arguments
        request_id: Request ID for tracing

    Returns:
        Script execution result

    Raises:
        GatewayDegradedException: If Redis operation fails
    """
    if redis_client is None:
        raise GatewayDegradedException(
            component="redis",
            reason="Redis client unavailable",
        )

    try:
        script_obj = redis_client.register_script(script)
        result = await asyncio.wait_for(
            script_obj(keys=keys, args=args), timeout=0.2
        )
        return result

    except asyncio.TimeoutError:
        logger.warning(
            "Redis Lua script timeout",
            extra={"request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Lua script execution timeout",
        )

    except TimeoutError:
        logger.warning(
            "Redis Lua script timeout",
            extra={"request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Lua script execution timeout",
        )

    except ConnectionError:
        logger.warning(
            "Redis Lua script connection error",
            extra={"request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis connection failed",
        )

    except ResponseError:
        logger.warning(
            "Redis Lua script response error",
            extra={"request_id": request_id},
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Redis returned error response",
        )

    except RedisError as e:
        logger.warning(
            "Redis Lua script failed",
            extra={
                "error": "operation_failed",
                "request_id": request_id,
            },
        )
        raise GatewayDegradedException(
            component="redis",
            reason="Lua script failed",
        )


# ============================================================================
# OPA WRAPPERS (FAIL-CLOSED)
# ============================================================================


async def opa_policy_check(
    opa_url: str,
    policy_input: Dict[str, Any],
    request_id: str = "",
) -> bool:
    """
    Safely check authorization policy against OPA (fail-closed).

    OPA failures result in DENY (not ALLOW). This wrapper ensures
    that any connection error, timeout, or invalid response results
    in access denial.

    Args:
        opa_url: OPA policy engine URL
        policy_input: Input to policy check (agent_id, tool_name, role)
        request_id: Request ID for tracing

    Returns:
        True if OPA allows, raises RBACDeniedException otherwise

    Raises:
        RBACDeniedException: If OPA denies, unavailable, or times out
    """
    if not opa_url:
        logger.warning(
            "OPA URL not configured",
            extra={"request_id": request_id},
        )
        raise RBACDeniedException(
            reason="OPA not configured",
            agent_id=policy_input.get("agent_id", "unknown"),
            tool_name=policy_input.get("tool_name", "unknown"),
        )

    try:
        client = await get_opa_client()
        response = await asyncio.wait_for(
            client.post(
                f"{opa_url}/v1/data/agentguard/allow",
                json={"input": policy_input},
            ),
            timeout=0.1,
        )

        if response.status_code != 200:
            logger.warning(
                "OPA returned non-200 status",
                extra={
                    "status": response.status_code,
                    "request_id": request_id,
                },
            )
            raise RBACDeniedException(
                reason="Policy check returned error",
                agent_id=policy_input.get("agent_id", "unknown"),
                tool_name=policy_input.get("tool_name", "unknown"),
            )

        # Parse response
        try:
            result = response.json()
        except Exception as e:
            logger.warning(
                "OPA returned invalid JSON",
                extra={
                    "error": "operation_failed",
                    "request_id": request_id,
                },
            )
            raise RBACDeniedException(
                reason="Policy response invalid",
                agent_id=policy_input.get("agent_id", "unknown"),
                tool_name=policy_input.get("tool_name", "unknown"),
            )

        # Strict schema validation
        if not isinstance(result, dict):
            logger.warning(
                "OPA response not a dict",
                extra={"request_id": request_id},
            )
            raise RBACDeniedException(
                reason="Policy response invalid",
                agent_id=policy_input.get("agent_id", "unknown"),
                tool_name=policy_input.get("tool_name", "unknown"),
            )

        if "result" not in result or not isinstance(result["result"], dict):
            logger.warning(
                "OPA response missing result field",
                extra={"request_id": request_id},
            )
            raise RBACDeniedException(
                reason="Policy response invalid",
                agent_id=policy_input.get("agent_id", "unknown"),
                tool_name=policy_input.get("tool_name", "unknown"),
            )

        if "allow" not in result["result"]:
            logger.warning(
                "OPA response missing allow field",
                extra={"request_id": request_id},
            )
            raise RBACDeniedException(
                reason="Policy response invalid",
                agent_id=policy_input.get("agent_id", "unknown"),
                tool_name=policy_input.get("tool_name", "unknown"),
            )

        # Extract allow decision
        allowed = result["result"]["allow"]

        if not allowed:
            logger.warning(
                "OPA policy denied access",
                extra={
                    "agent_id": policy_input.get("agent_id"),
                    "tool_name": policy_input.get("tool_name"),
                    "request_id": request_id,
                },
            )
            raise RBACDeniedException(
                reason="Policy denies access",
                agent_id=policy_input.get("agent_id", "unknown"),
                tool_name=policy_input.get("tool_name", "unknown"),
            )

        return True

    except RBACDeniedException:
        raise

    except asyncio.TimeoutError:
        logger.warning(
            "OPA policy check timeout",
            extra={"request_id": request_id},
        )
        raise RBACDeniedException(
            reason="Policy engine timeout",
            agent_id=policy_input.get("agent_id", "unknown"),
            tool_name=policy_input.get("tool_name", "unknown"),
        )

    except httpx.TimeoutException:
        logger.warning(
            "OPA policy check timeout",
            extra={"request_id": request_id},
        )
        raise RBACDeniedException(
            reason="Policy engine timeout",
            agent_id=policy_input.get("agent_id", "unknown"),
            tool_name=policy_input.get("tool_name", "unknown"),
        )

    except httpx.RequestError as e:
        logger.warning(
            "OPA policy check request failed",
            extra={
                "error": "operation_failed",
                "request_id": request_id,
            },
        )
        raise RBACDeniedException(
            reason="Policy engine unavailable",
            agent_id=policy_input.get("agent_id", "unknown"),
            tool_name=policy_input.get("tool_name", "unknown"),
        )

    except Exception as e:
        logger.warning(
            "Unexpected error checking OPA policy",
            extra={
                "error": "operation_failed",
                "request_id": request_id,
            },
        )
        raise RBACDeniedException(
            reason="Policy check failed",
            agent_id=policy_input.get("agent_id", "unknown"),
            tool_name=policy_input.get("tool_name", "unknown"),
        )
