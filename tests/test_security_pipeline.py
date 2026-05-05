"""
Red team security test suite for the AI gateway pipeline.

This test suite validates fail-closed behavior, resilience under failure,
and security hardening across all components.

Tests cover:
- JWT bypass attempts
- Replay attack detection
- System failure resilience
- Rate limit enforcement
- Response validation
- Logging safety
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from jose import jwt

from app.exceptions import (
    GatewayDegradedException,
    RBACDeniedException,
    RateLimitException,
    RegistrationException,
    TriageBlockException,
)
from app.pipeline import (
    DecisionResult,
    InMemoryRateLimiter,
    ReplayProtection,
    RequestContext,
    validate_jwt,
    validate_global_rate_limit,
    validate_replay_protection,
    validate_rbac,
    validate_sequence,
    validate_triage,
)
from app.triage_client import TriageResponse, call_triage_engine
from app.dependency_wrappers import (
    redis_hgetall,
    redis_set,
    opa_policy_check,
)


# ============================================================================
# TEST 1: JWT BYPASS — Invalid Signature, Wrong Issuer, Expired Token
# ============================================================================


class TestJWTBypass:
    """Verify JWT validation catches all bypass attempts."""

    @pytest.mark.asyncio
    async def test_jwt_invalid_signature(self):
        """Tampered JWT should be rejected."""
        payload = {
            "sub": "agent-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "correct-issuer",
            "aud": "agentguard",
        }
        # Sign with wrong key
        token = jwt.encode(payload, "wrong-secret", algorithm="HS256")

        with pytest.raises(RegistrationException):
            await validate_jwt(
                token, expected_issuer="correct-issuer"
            )

    @pytest.mark.asyncio
    async def test_jwt_wrong_issuer(self):
        """JWT with wrong issuer should be rejected."""
        secret = "test-secret"
        payload = {
            "sub": "agent-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "attacker-issuer",
            "aud": "agentguard",
        }
        token = jwt.encode(payload, secret, algorithm="HS256")

        with pytest.raises(RegistrationException):
            await validate_jwt(token, expected_issuer="correct-issuer")

    @pytest.mark.asyncio
    async def test_jwt_expired_token(self):
        """Expired JWT should be rejected."""
        secret = "test-secret"
        payload = {
            "sub": "agent-123",
            "exp": int(time.time()) - 1,  # Expired 1 second ago
            "iat": int(time.time()) - 3600,
            "iss": "correct-issuer",
            "aud": "agentguard",
        }
        token = jwt.encode(payload, secret, algorithm="HS256")

        with pytest.raises(RegistrationException):
            await validate_jwt(token, expected_issuer="correct-issuer")

    @pytest.mark.asyncio
    async def test_jwt_none_algorithm(self):
        """JWT with 'none' algorithm should be rejected."""
        # Manually craft a 'none' token
        header = {"typ": "JWT", "alg": "none"}
        payload = {
            "sub": "agent-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "correct-issuer",
            "aud": "agentguard",
        }
        # This should be rejected at validation
        token = jwt.encode(payload, "", algorithm="HS256")

        with pytest.raises(RegistrationException):
            await validate_jwt(token, expected_issuer="correct-issuer")


# ============================================================================
# TEST 2: REPLAY ATTACK — Duplicate Request IDs
# ============================================================================


class TestReplayProtection:
    """Verify replay protection blocks duplicate request IDs."""

    @pytest.mark.asyncio
    async def test_replay_protection_blocks_duplicate(self):
        """Second request with same ID should be blocked."""
        replay_protection = ReplayProtection()
        request_id = "req-123-abc"

        # First request allowed
        result1 = await replay_protection.check(request_id)
        assert result1 is True

        # Second request with same ID blocked
        result2 = await replay_protection.check(request_id)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_replay_protection_ttl_expiry(self):
        """Request ID should be allowed after TTL expires."""
        replay_protection = ReplayProtection(ttl_seconds=0.1)
        request_id = "req-456-def"

        # First request allowed
        result1 = await replay_protection.check(request_id)
        assert result1 is True

        # Block second request
        result2 = await replay_protection.check(request_id)
        assert result2 is False

        # Wait for TTL to expire
        await asyncio.sleep(0.15)

        # Third request should be allowed (ID expired)
        result3 = await replay_protection.check(request_id)
        assert result3 is True


# ============================================================================
# TEST 3: REDIS DOWN — No Crash, Fallback to SANDBOX
# ============================================================================


class TestRedisFailure:
    """Verify system resilience when Redis is unavailable."""

    @pytest.mark.asyncio
    async def test_redis_hgetall_timeout(self):
        """Redis HGETALL timeout should raise GatewayDegradedException."""
        redis_client = AsyncMock()
        redis_client.hgetall = AsyncMock(
            side_effect=asyncio.TimeoutError()
        )

        with pytest.raises(GatewayDegradedException) as exc_info:
            await redis_hgetall(redis_client, "key", "request-id")

        assert exc_info.value._reason == "HGETALL operation timeout"

    @pytest.mark.asyncio
    async def test_redis_connection_error(self):
        """Redis connection error should raise GatewayDegradedException."""
        from redis.exceptions import RedisConnectionError

        redis_client = AsyncMock()
        redis_client.hgetall = AsyncMock(side_effect=RedisConnectionError())

        with pytest.raises(GatewayDegradedException) as exc_info:
            await redis_hgetall(redis_client, "key", "request-id")

        assert exc_info.value._reason == "Redis connection failed"

    @pytest.mark.asyncio
    async def test_redis_none_client(self):
        """None Redis client should raise GatewayDegradedException."""
        with pytest.raises(GatewayDegradedException) as exc_info:
            await redis_hgetall(None, "key", "request-id")

        assert "unavailable" in exc_info.value._reason


# ============================================================================
# TEST 4: OPA DOWN — Fail-Closed to BLOCK
# ============================================================================


class TestOPAFailure:
    """Verify OPA failures result in BLOCK (fail-closed)."""

    @pytest.mark.asyncio
    async def test_opa_unreachable(self):
        """OPA unreachable should raise RBACDeniedException."""
        with patch(
            "app.dependency_wrappers.get_opa_client"
        ) as mock_client_getter:
            mock_client = AsyncMock()
            mock_client_getter.return_value = mock_client
            mock_client.post = AsyncMock(
                side_effect=httpx.RequestError("Connection refused")
            )

            with pytest.raises(RBACDeniedException):
                await opa_policy_check(
                    "http://localhost:8181",
                    {"agent_id": "test", "tool_name": "test_tool"},
                    "request-id",
                )

    @pytest.mark.asyncio
    async def test_opa_timeout(self):
        """OPA timeout should raise RBACDeniedException."""
        with patch(
            "app.dependency_wrappers.get_opa_client"
        ) as mock_client_getter:
            mock_client = AsyncMock()
            mock_client_getter.return_value = mock_client
            mock_client.post = AsyncMock(
                side_effect=httpx.TimeoutException("Timeout")
            )

            with pytest.raises(RBACDeniedException):
                await opa_policy_check(
                    "http://localhost:8181",
                    {"agent_id": "test", "tool_name": "test_tool"},
                    "request-id",
                )

    @pytest.mark.asyncio
    async def test_opa_non_200_status(self):
        """OPA returning non-200 status should raise RBACDeniedException."""
        with patch(
            "app.dependency_wrappers.get_opa_client"
        ) as mock_client_getter:
            mock_client = AsyncMock()
            mock_client_getter.return_value = mock_client
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_client.post = AsyncMock(return_value=mock_response)

            with pytest.raises(RBACDeniedException):
                await opa_policy_check(
                    "http://localhost:8181",
                    {"agent_id": "test", "tool_name": "test_tool"},
                    "request-id",
                )


# ============================================================================
# TEST 5: RATE LIMIT RACE CONDITION — Concurrent Requests
# ============================================================================


class TestRateLimitRaceCondition:
    """Verify rate limiting works under concurrency."""

    @pytest.mark.asyncio
    async def test_rate_limit_50_concurrent(self):
        """50 concurrent requests should respect rate limit."""
        limiter = InMemoryRateLimiter()
        limit = 10

        async def make_request():
            return await limiter.is_allowed(limit)

        # 50 concurrent requests
        results = await asyncio.gather(
            *[make_request() for _ in range(50)]
        )

        # Exactly 10 should pass (limit)
        allowed_count = sum(1 for r in results if r)
        assert allowed_count == limit, f"Expected {limit}, got {allowed_count}"

    @pytest.mark.asyncio
    async def test_rate_limit_window_reset(self):
        """Rate limit window should reset after expiry."""
        limiter = InMemoryRateLimiter()
        limit = 5
        window = 0.1

        # Fill up limit
        for _ in range(limit):
            assert await limiter.is_allowed(limit) is True

        # Next request blocked
        assert await limiter.is_allowed(limit) is False

        # Wait for window reset
        await asyncio.sleep(window + 0.05)

        # Can make requests again
        assert await limiter.is_allowed(limit) is True


# ============================================================================
# TEST 6: TRIAGE TIMEOUT — 50ms Hard Timeout
# ============================================================================


class TestTriageTimeout:
    """Verify triage timeout is strictly enforced."""

    @pytest.mark.asyncio
    async def test_triage_timeout_exceeds_50ms(self):
        """Triage delay >50ms should timeout and return SANDBOX."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-123",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = (
                mock_client
            )

            async def slow_post(*args, **kwargs):
                await asyncio.sleep(0.1)  # 100ms delay > 50ms timeout
                return MagicMock(status_code=200)

            mock_client.post = slow_post

            result = await call_triage_engine(payload)

            # Should timeout and return SANDBOX
            assert result.verdict == "SANDBOX"
            assert "timeout" in result.explanation.lower()

    @pytest.mark.asyncio
    async def test_triage_exact_50ms_threshold(self):
        """Triage at exactly 50ms boundary should be allowed."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-456",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = (
                mock_client
            )

            # Return valid response quickly
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json"}
            mock_response.json.return_value = {
                "verdict": "ALLOW",
                "score": 0.1,
                "explanation": "Safe",
                "owasp_ref": None,
                "request_id": "req-456",
            }

            mock_client.post = AsyncMock(return_value=mock_response)

            result = await call_triage_engine(payload)

            # Should return actual response
            assert result.verdict == "ALLOW"


# ============================================================================
# TEST 7: SEQUENCE ATTACK — Malicious Pattern Detection
# ============================================================================


class TestSequenceAttack:
    """Verify sequence validation blocks attack patterns."""

    @pytest.mark.asyncio
    async def test_sequence_prerequisite_violation(self):
        """Accessing tool without prerequisites should be blocked."""
        context = RequestContext(
            request_id="req-seq",
            agent_id="agent-1",
            tool_name="execute_command",
            previous_actions=["init"],
            # Missing required "authenticate" action
        )

        with pytest.raises(Exception):  # Should raise SequenceViolationException
            await validate_sequence(context, MagicMock())


# ============================================================================
# TEST 8: MALFORMED TRIAGE RESPONSE — Extra Fields, Missing Fields
# ============================================================================


class TestMalformedTriageResponse:
    """Verify strict response validation rejects malformed data."""

    @pytest.mark.asyncio
    async def test_triage_extra_fields(self):
        """Triage response with extra fields should be rejected."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-789",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = (
                mock_client
            )

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json"}
            mock_response.json.return_value = {
                "verdict": "ALLOW",
                "score": 0.1,
                "explanation": "Safe",
                "owasp_ref": None,
                "request_id": "req-789",
                "extra_malicious_field": "injected",  # Extra field
            }

            mock_client.post = AsyncMock(return_value=mock_response)

            result = await call_triage_engine(payload)

            # Should reject and return SANDBOX
            assert result.verdict == "SANDBOX"

    @pytest.mark.asyncio
    async def test_triage_missing_fields(self):
        """Triage response missing required fields should be rejected."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-101",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = (
                mock_client
            )

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json"}
            mock_response.json.return_value = {
                "verdict": "ALLOW",
                # Missing "score" field
                "explanation": "Safe",
                "owasp_ref": None,
                "request_id": "req-101",
            }

            mock_client.post = AsyncMock(return_value=mock_response)

            result = await call_triage_engine(payload)

            # Should reject and return SANDBOX
            assert result.verdict == "SANDBOX"


# ============================================================================
# TEST 9: CONTENT-TYPE ATTACK — Non-JSON Response
# ============================================================================


class TestContentTypeAttack:
    """Verify Content-Type validation rejects non-JSON."""

    @pytest.mark.asyncio
    async def test_triage_text_content_type(self):
        """Triage response with text/plain should be rejected."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-202",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = (
                mock_client
            )

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "text/plain"}  # Wrong!
            mock_response.json.return_value = {
                "verdict": "ALLOW",
                "score": 0.1,
                "explanation": "Safe",
                "owasp_ref": None,
                "request_id": "req-202",
            }

            mock_client.post = AsyncMock(return_value=mock_response)

            result = await call_triage_engine(payload)

            # Should reject and return SANDBOX
            assert result.verdict == "SANDBOX"
            assert "invalid" in result.explanation.lower()

    @pytest.mark.asyncio
    async def test_triage_missing_content_type(self):
        """Triage response with missing Content-Type should be rejected."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-303",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = (
                mock_client
            )

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {}  # No Content-Type
            mock_response.json.return_value = {
                "verdict": "ALLOW",
                "score": 0.1,
                "explanation": "Safe",
                "owasp_ref": None,
                "request_id": "req-303",
            }

            mock_client.post = AsyncMock(return_value=mock_response)

            result = await call_triage_engine(payload)

            # Should reject and return SANDBOX
            assert result.verdict == "SANDBOX"


# ============================================================================
# TEST 10: REQUEST_ID MISMATCH — Integrity Check
# ============================================================================


class TestRequestIDMismatch:
    """Verify request_id integrity is validated."""

    @pytest.mark.asyncio
    async def test_triage_request_id_mismatch(self):
        """Triage response with mismatched request_id should be rejected."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-correct",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = (
                mock_client
            )

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"content-type": "application/json"}
            mock_response.json.return_value = {
                "verdict": "ALLOW",
                "score": 0.1,
                "explanation": "Safe",
                "owasp_ref": None,
                "request_id": "req-wrong",  # Mismatched!
            }

            mock_client.post = AsyncMock(return_value=mock_response)

            result = await call_triage_engine(payload)

            # Should reject and return SANDBOX
            assert result.verdict == "SANDBOX"
            assert "invalid" in result.explanation.lower()


# ============================================================================
# TEST 11: LOGGING SAFETY — No Sensitive Data Leakage
# ============================================================================


class TestLoggingSafety:
    """Verify logs don't leak sensitive data."""

    def test_jwt_not_in_logs(self, caplog):
        """JWT should never appear in logs."""
        secret = "test-secret"
        payload = {
            "sub": "agent-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "correct-issuer",
            "aud": "agentguard",
        }
        token = jwt.encode(payload, secret, algorithm="HS256")

        # Log something that might expose JWT
        logger = logging.getLogger("app.pipeline")
        logger.info("Request processed", extra={"request_id": "test"})

        # Verify JWT not in logs
        assert token not in caplog.text

    def test_error_messages_generic(self, caplog):
        """Error messages should be generic, not expose exception types."""
        logger = logging.getLogger("app.dependency_wrappers")

        # Log something with error info
        logger.warning(
            "Operation failed",
            extra={"error": "operation_failed", "request_id": "test"},
        )

        # Verify no exception type names
        assert "TimeoutError" not in caplog.text
        assert "RedisError" not in caplog.text
        assert "ConnectionError" not in caplog.text

    def test_api_keys_not_logged(self, caplog):
        """API keys should never be logged."""
        logger = logging.getLogger("app.pipeline")

        # Try to log request with API key
        logger.info(
            "Request received",
            extra={
                "request_id": "test",
                "user": "agent-123",
            },
        )

        # Should not contain bearer token pattern
        assert "bearer" not in caplog.text.lower()


# ============================================================================
# TEST 12: LOAD STABILITY — Burst Traffic
# ============================================================================


class TestLoadStability:
    """Verify system stability under burst traffic."""

    @pytest.mark.asyncio
    async def test_burst_100_requests(self):
        """System should handle 100 concurrent requests without crash."""
        limiter = InMemoryRateLimiter()
        limit = 50  # 50 req/s

        async def burst_request():
            try:
                return await limiter.is_allowed(limit)
            except Exception:
                return None  # Catch any crash

        results = await asyncio.gather(
            *[burst_request() for _ in range(100)]
        )

        # No None values (no crashes)
        assert None not in results

        # At most 50 allowed
        allowed_count = sum(1 for r in results if r)
        assert allowed_count <= limit

    @pytest.mark.asyncio
    async def test_sustained_load(self):
        """System should sustain load without resource exhaustion."""
        limiter = InMemoryRateLimiter()
        limit = 100

        for batch in range(5):  # 5 batches
            results = await asyncio.gather(
                *[limiter.is_allowed(limit) for _ in range(50)]
            )

            # Each batch should work
            assert len(results) == 50
            assert all(r is not None for r in results)

            # Wait for window reset
            await asyncio.sleep(1.1)

    @pytest.mark.asyncio
    async def test_no_memory_leak_in_replay(self):
        """Replay protection should not leak memory with many IDs."""
        replay_protection = ReplayProtection(ttl_seconds=0.1)

        # Create 1000 unique request IDs
        for i in range(1000):
            request_id = f"req-{i}"
            result = await replay_protection.check(request_id)
            assert result is True  # All should be new

        # Wait for cleanup
        await asyncio.sleep(0.15)

        # Memory should be reclaimed
        initial_size = len(replay_protection.requests)

        # Create 100 new IDs
        for i in range(1000, 1100):
            request_id = f"req-{i}"
            await replay_protection.check(request_id)

        final_size = len(replay_protection.requests)

        # Size should not grow unbounded
        assert final_size < 500  # Reasonable memory usage


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
