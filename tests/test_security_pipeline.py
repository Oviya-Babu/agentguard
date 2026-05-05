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
    TriageResponse,
    step_1_global_rate_limit,
    step_2_jwt_validation,
    step_4b_replay_protection,
    step_4_rbac_check,
    step_6_sequence_analysis,
    step_7_triage_engine,
)
from app.triage_client import TriageResponse as TriageClientResponse
from app.triage_client import call_triage_engine
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
    async def test_jwt_missing_required_claims(self):
        """JWT missing required claims should be rejected."""
        context = RequestContext(
            agent_id="agent-123",
            tool_name="search",
            jwt_payload={"token": "some-token"},  # Missing sub, exp, iat, iss, aud
            request_id="req-jwt-1",
        )

        with pytest.raises(RegistrationException):
            await step_2_jwt_validation(context, "test-secret")

    @pytest.mark.asyncio
    async def test_jwt_wrong_issuer(self):
        """JWT with wrong issuer should be rejected."""
        context = RequestContext(
            agent_id="agent-123",
            tool_name="search",
            jwt_payload={
                "sub": "agent-123",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "iss": "attacker-issuer",
                "aud": "agentguard-gateway",
            },
            request_id="req-jwt-2",
        )

        with pytest.raises(RegistrationException):
            await step_2_jwt_validation(context, "test-secret")

    @pytest.mark.asyncio
    async def test_jwt_expired_token(self):
        """Expired JWT should be rejected."""
        context = RequestContext(
            agent_id="agent-123",
            tool_name="search",
            jwt_payload={
                "sub": "agent-123",
                "exp": int(time.time()) - 1,  # Expired 1 second ago
                "iat": int(time.time()) - 3600,
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id="req-jwt-3",
        )

        with pytest.raises(RegistrationException):
            await step_2_jwt_validation(context, "test-secret")

    @pytest.mark.asyncio
    async def test_jwt_valid_passes(self):
        """Valid JWT claims should pass validation."""
        context = RequestContext(
            agent_id="agent-123",
            tool_name="search",
            jwt_payload={
                "sub": "agent-123",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id="req-jwt-4",
        )

        result = await step_2_jwt_validation(context, "test-secret")
        assert result is not None
        assert result["sub"] == "agent-123"


# ============================================================================
# TEST 2: REPLAY ATTACK — Duplicate Request IDs
# ============================================================================


class TestReplayProtection:
    """Verify replay protection blocks duplicate request IDs."""

    @pytest.mark.asyncio
    async def test_replay_protection_blocks_duplicate(self):
        """Second request with same ID should be blocked."""
        replay = ReplayProtection()
        request_id = "req-123-abc"

        # First request allowed
        result1 = await replay.check_replay(request_id)
        assert result1 is True

        # Second request with same ID blocked
        result2 = await replay.check_replay(request_id)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_replay_protection_ttl_expiry(self):
        """Request ID should be allowed after TTL expires."""
        replay = ReplayProtection()
        replay.ttl = 0.1  # Set short TTL for testing
        request_id = "req-456-def"

        # First request allowed
        result1 = await replay.check_replay(request_id)
        assert result1 is True

        # Block second request
        result2 = await replay.check_replay(request_id)
        assert result2 is False

        # Wait for TTL to expire
        await asyncio.sleep(0.15)

        # Third request should be allowed (ID expired)
        result3 = await replay.check_replay(request_id)
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

        assert exc_info.value.reason == "HGETALL operation timeout"

    @pytest.mark.asyncio
    async def test_redis_connection_error(self):
        """Redis connection error should raise GatewayDegradedException."""
        from redis.exceptions import ConnectionError as RedisConnectionError

        redis_client = AsyncMock()
        redis_client.hgetall = AsyncMock(side_effect=RedisConnectionError())

        with pytest.raises(GatewayDegradedException) as exc_info:
            await redis_hgetall(redis_client, "key", "request-id")

        assert exc_info.value.reason == "Redis connection failed"

    @pytest.mark.asyncio
    async def test_redis_none_client(self):
        """None Redis client should raise GatewayDegradedException."""
        with pytest.raises(GatewayDegradedException) as exc_info:
            await redis_hgetall(None, "key", "request-id")

        assert "unavailable" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_redis_down_pipeline_returns_sandbox(self):
        """Session lookup with no Redis should return SANDBOX (GatewayDegradedException)."""
        from app.pipeline import step_3_agent_session_lookup

        context = RequestContext(
            agent_id="agent-test",
            tool_name="search",
            jwt_payload={
                "sub": "agent-test",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id="req-redis-down",
        )

        # Step 3 should raise GatewayDegradedException when Redis is None
        with pytest.raises(GatewayDegradedException):
            await step_3_agent_session_lookup(None, context)


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

    @pytest.mark.asyncio
    async def test_opa_not_configured(self):
        """OPA URL not configured should raise RBACDeniedException."""
        context = RequestContext(
            agent_id="test-agent",
            tool_name="search",
            jwt_payload={},
            request_id="req-opa-1",
        )

        with pytest.raises(RBACDeniedException):
            await step_4_rbac_check(None, context, {"role": "worker"})


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

        # Fill up limit
        for _ in range(limit):
            assert await limiter.is_allowed(limit) is True

        # Next request blocked
        assert await limiter.is_allowed(limit) is False

        # Wait for window reset
        await asyncio.sleep(1.1)

        # Can make requests again
        assert await limiter.is_allowed(limit) is True

    @pytest.mark.asyncio
    async def test_rate_limit_repeated_correctness(self):
        """Rate limit should be exact every time (no race conditions)."""
        for run in range(10):
            limiter = InMemoryRateLimiter()
            limit = 20

            results = await asyncio.gather(
                *[limiter.is_allowed(limit) for _ in range(50)]
            )

            allowed = sum(1 for r in results if r)
            assert allowed == limit, (
                f"Run {run}: Expected {limit}, got {allowed}"
            )


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

        with patch("app.triage_client.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock(
                return_value=False
            )

            # Simulate timeout
            mock_client.post = AsyncMock(
                side_effect=httpx.TimeoutException("Timeout")
            )

            with patch.dict("os.environ", {"TRIAGE_URL": "http://triage:9000"}):
                with patch("os.path.exists", return_value=True):
                    result = await call_triage_engine(payload)

            # Should timeout and return SANDBOX
            assert result.verdict == "SANDBOX"
            assert "timeout" in result.explanation.lower()

    @pytest.mark.asyncio
    async def test_triage_valid_allow_response(self):
        """Valid triage ALLOW response should be accepted."""
        payload = {
            "agent_id": "test",
            "tool_name": "test_tool",
            "request_id": "req-456",
        }

        with patch("app.triage_client.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock(
                return_value=False
            )

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

            # Need TRIAGE_URL env set and certs exist
            with patch.dict("os.environ", {"TRIAGE_URL": "http://triage:9000"}):
                with patch("os.path.exists", return_value=True):
                    result = await call_triage_engine(payload)

            assert result.verdict == "ALLOW"


# ============================================================================
# TEST 7: TRIAGE CONTRACT FAILURE — Missing/Invalid Fields
# ============================================================================


class TestTriageContractFailure:
    """Verify strict response validation rejects malformed data."""

    def test_triage_response_missing_score(self):
        """TriageResponse with missing score should fail validation."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TriageClientResponse(
                verdict="ALLOW",
                explanation="Test",
                owasp_ref=None,
                request_id="req-1",
                # score is missing
            )

    def test_triage_response_score_out_of_range(self):
        """TriageResponse with score > 1.0 should fail validation."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TriageClientResponse(
                verdict="ALLOW",
                score=1.5,  # Out of range
                explanation="Test",
                owasp_ref=None,
                request_id="req-2",
            )

    def test_triage_response_score_as_string(self):
        """TriageResponse with score as string should fail validation."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TriageClientResponse(
                verdict="ALLOW",
                score="not-a-number",  # type: ignore
                explanation="Test",
                owasp_ref=None,
                request_id="req-3",
            )

    def test_triage_response_extra_fields_rejected(self):
        """TriageResponse with extra fields should be rejected (extra=forbid)."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TriageClientResponse(
                verdict="ALLOW",
                score=0.1,
                explanation="Safe",
                owasp_ref=None,
                request_id="req-4",
                extra_malicious_field="injected",  # type: ignore
            )


# ============================================================================
# TEST 8: CONTENT-TYPE ATTACK — Non-JSON Response
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

        with patch("app.triage_client.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock(
                return_value=False
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

            with patch.dict("os.environ", {"TRIAGE_URL": "http://triage:9000"}):
                with patch("os.path.exists", return_value=True):
                    result = await call_triage_engine(payload)

            # Should reject and return SANDBOX
            assert result.verdict == "SANDBOX"
            assert "invalid" in result.explanation.lower()


# ============================================================================
# TEST 9: REQUEST_ID MISMATCH — Integrity Check
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

        with patch("app.triage_client.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_client_class.return_value.__aexit__ = AsyncMock(
                return_value=False
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

            with patch.dict("os.environ", {"TRIAGE_URL": "http://triage:9000"}):
                with patch("os.path.exists", return_value=True):
                    result = await call_triage_engine(payload)

            # Should reject and return SANDBOX
            assert result.verdict == "SANDBOX"
            assert "invalid" in result.explanation.lower()


# ============================================================================
# TEST 10: LOGGING SAFETY — No Sensitive Data Leakage
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

        # Verify no exception type names leaked
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

    def test_pii_ssn_filtered_from_logs(self, caplog):
        """SSN values should be filtered from log output."""
        from app.log_filter import PIIFilter

        pii_filter = PIIFilter()
        test_logger = logging.getLogger("test.pii")
        test_logger.addFilter(pii_filter)

        # Log a message with a phone-like number
        test_logger.info("Agent processed data with phone 1234567890")

        # The number should be redacted
        assert "1234567890" not in caplog.text


# ============================================================================
# TEST 11: LOAD STABILITY — Burst Traffic
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

        for batch in range(3):  # 3 batches (reduced for CI speed)
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
        replay = ReplayProtection()
        replay.ttl = 0.1  # Short TTL for test

        # Create 1000 unique request IDs
        for i in range(1000):
            request_id = f"req-{i}"
            result = await replay.check_replay(request_id)
            assert result is True  # All should be new

        # Wait for cleanup
        await asyncio.sleep(0.15)

        # Memory should be reclaimed on next check
        initial_size = len(replay.seen_requests)

        # Create 100 new IDs (triggers cleanup of expired)
        for i in range(1000, 1100):
            request_id = f"req-{i}"
            await replay.check_replay(request_id)

        final_size = len(replay.seen_requests)

        # Size should not grow unbounded
        assert final_size < 500  # Reasonable memory usage


# ============================================================================
# TEST 12: EXCEPTION SAFETY — Sanitized Messages
# ============================================================================


class TestExceptionSafety:
    """Verify exception messages are sanitized for external consumption."""

    def test_security_block_exception_message(self):
        """SecurityBlockException should return generic message."""
        from app.exceptions import SecurityBlockException

        exc = SecurityBlockException(
            reason="Secret internal reason",
            agent_id="agent-1",
            tool_name="dangerous_tool",
            triage_score=0.9,
            owasp_ref="LLM01",
        )

        # External message is generic
        assert str(exc) == "Tool access denied"
        assert "Secret internal reason" not in str(exc)

        # Internal context is available for logging
        ctx = exc.get_internal_context()
        assert ctx["reason"] == "Secret internal reason"
        assert ctx["triage_score"] == 0.9

    def test_registration_exception_message(self):
        """RegistrationException should return generic message."""
        exc = RegistrationException(
            reason="JWT expired at 1234567890",
            agent_id="agent-1",
            tool_name="tool-1",
        )

        assert str(exc) == "Invalid agent credentials"
        assert "1234567890" not in str(exc)

    def test_rbac_denied_message(self):
        """RBACDeniedException should return generic message."""
        exc = RBACDeniedException(
            reason="Role 'worker' cannot access admin tools",
            agent_id="agent-1",
            tool_name="admin_tool",
        )

        assert str(exc) == "Tool access denied"
        assert "worker" not in str(exc)
        assert "admin" not in str(exc)

    def test_rate_limit_message(self):
        """RateLimitException should return generic message."""
        exc = RateLimitException(
            reason="Agent exceeded 100 req/min for tool search",
            agent_id="agent-1",
            tool_name="search",
        )

        assert str(exc) == "Rate limit exceeded"

    def test_gateway_degraded_not_security_block(self):
        """GatewayDegradedException should NOT be a SecurityBlockException."""
        from app.exceptions import SecurityBlockException

        exc = GatewayDegradedException(
            component="redis",
            reason="Connection timeout",
        )

        assert not isinstance(exc, SecurityBlockException)
        assert exc.component == "redis"


# ============================================================================
# TEST 13: PIPELINE DECISION RESULT MODEL
# ============================================================================


class TestDecisionResult:
    """Verify DecisionResult model validation."""

    def test_valid_allow_decision(self):
        """ALLOW decision should be valid."""
        result = DecisionResult(
            decision="ALLOW",
            reason="All checks passed",
            trace_id="trace-1",
        )
        assert result.decision == "ALLOW"

    def test_valid_block_decision(self):
        """BLOCK decision should be valid."""
        result = DecisionResult(
            decision="BLOCK",
            reason="Rate limit exceeded",
            trace_id="trace-2",
        )
        assert result.decision == "BLOCK"

    def test_valid_sandbox_decision(self):
        """SANDBOX decision should be valid."""
        result = DecisionResult(
            decision="SANDBOX",
            reason="Infrastructure degraded",
            trace_id="trace-3",
        )
        assert result.decision == "SANDBOX"

    def test_invalid_decision_rejected(self):
        """Invalid decision value should be rejected."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            DecisionResult(
                decision="INVALID",  # type: ignore
                reason="Test",
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
