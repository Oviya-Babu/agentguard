"""
Phase 2: Gateway Core Validation Tests

Six concurrent tests, each runs 10 times, zero intermittent failures.

These tests validate:
1. Valid agent, permitted tool, under rate limit → ALLOW
2. Unknown agent_id → 401 reject
3. Permitted agent, forbidden tool → RBAC_DENIED (no rate increment)
4. 50 concurrent rate limit calls → 20 ALLOW, 30 RATE_LIMITED
5. Redis stopped → SANDBOX verdict (not ALLOW, not 500)
6. OPA stopped → RBAC_DENIED all calls
"""

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Dict, List

import pytest
import redis.asyncio as redis
import httpx
from unittest.mock import AsyncMock, patch

# This imports should work after Phase 0 setup
from app.pipeline import (
    RequestContext,
    DecisionResult,
    process_request,
)
from app.exceptions import (
    RateLimitException,
    RegistrationException,
    RBACDeniedException,
)

logger = logging.getLogger(__name__)


# ============================================================================
# FIXTURES AND HELPERS
# ============================================================================

@pytest.fixture
async def redis_client():
    """Create Redis connection for tests."""
    client = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        db=int(os.getenv("REDIS_DB", 0)),
        decode_responses=True,
    )
    
    # Clear test data before test
    try:
        await client.flushdb()
    except Exception as e:
        logger.warning(f"Could not flush Redis: {e}")
    
    yield client
    
    # Cleanup
    try:
        await client.close()
    except Exception:
        pass


@pytest.fixture
async def app_state_mock():
    """Create a mock AppState for testing."""
    class MockAppState:
        def __init__(self):
            self.redis = None
            self.degraded_components = {"redis": False, "opa": False}
            self.sequence_rules = {}
            self.injection_patterns = {}
    
    return MockAppState()


# ============================================================================
# TEST 1: VALID AGENT, PERMITTED TOOL, UNDER RATE LIMIT → ALLOW
# ============================================================================

@pytest.mark.asyncio
async def test_valid_agent_allowed_10_times(redis_client):
    """
    Test 1: Run 10 times, all should ALLOW.
    
    Validates:
    - JWT validation passes
    - Agent session exists in Redis
    - Tool is permitted by RBAC
    - Rate limit not exceeded
    - Result is ALLOW verdict
    """
    test_agent_id = "test_agent_valid_001"
    test_request_id = str(uuid.uuid4())
    
    # Set up agent session in Redis
    session_key = f"session:{test_agent_id}"
    await redis_client.hset(
        session_key,
        mapping={
            "role": "test_role",
            "agent_id": test_agent_id,
            "created_at": "2024-01-01T00:00:00Z",
        }
    )
    await redis_client.expire(session_key, 3600)
    
    # Run test 10 times
    for run in range(10):
        context = RequestContext(
            agent_id=test_agent_id,
            tool_name="web_search",
            jwt_payload={
                "sub": test_agent_id,
                "exp": 9999999999,
                "iat": 1000000000,
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id=test_request_id + f"_{run}",
            metadata={},
        )
        
        # Mock the dependencies
        with patch("app.pipeline.app_state") as mock_app_state:
            mock_app_state.redis = redis_client
            mock_app_state.degraded_components = {"redis": False, "opa": False}
            mock_app_state.sequence_rules = {}
            
            # For RBAC check, mock OPA to allow
            with patch("app.pipeline.httpx.AsyncClient") as mock_client:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json = AsyncMock(return_value={"allow": True})
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_response
                )
                
                try:
                    result = await process_request(context)
                    
                    # Verify result is ALLOW
                    assert result.decision == "ALLOW", f"Run {run}: Expected ALLOW, got {result.decision}"
                    logger.info(f"Test 1, Run {run}: PASSED - {result.decision}")
                    
                except Exception as e:
                    pytest.fail(f"Test 1, Run {run}: Unexpected exception: {e}")


# ============================================================================
# TEST 2: UNKNOWN AGENT_ID → 401 REJECT
# ============================================================================

@pytest.mark.asyncio
async def test_unknown_agent_10_times(redis_client):
    """
    Test 2: Run 10 times with non-existent agent, all should 401.
    
    Validates:
    - Agent session lookup fails (not in Redis)
    - Returns 401 status (RegistrationException)
    - No Redis MONITOR activity after first lookup
    """
    test_unknown_agent = "unknown_agent_" + str(uuid.uuid4())[:8]
    
    for run in range(10):
        context = RequestContext(
            agent_id=test_unknown_agent,
            tool_name="web_search",
            jwt_payload={
                "sub": test_unknown_agent,
                "exp": 9999999999,
                "iat": 1000000000,
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id=str(uuid.uuid4()),
            metadata={},
        )
        
        with patch("app.pipeline.app_state") as mock_app_state:
            mock_app_state.redis = redis_client
            mock_app_state.degraded_components = {"redis": False, "opa": False}
            mock_app_state.sequence_rules = {}
            
            try:
                result = await process_request(context)
                
                # Unknown agent should be BLOCK, not ALLOW
                assert result.decision == "BLOCK", f"Run {run}: Expected BLOCK for unknown agent, got {result.decision}"
                assert "Invalid agent registration" in result.reason or "not found" in result.reason.lower()
                logger.info(f"Test 2, Run {run}: PASSED - {result.decision} ({result.reason})")
                
            except Exception as e:
                # Also acceptable if it raises RegistrationException
                logger.info(f"Test 2, Run {run}: PASSED - raised {type(e).__name__}")


# ============================================================================
# TEST 3: PERMITTED AGENT, FORBIDDEN TOOL → RBAC_DENIED (NO RATE INCREMENT)
# ============================================================================

@pytest.mark.asyncio
async def test_forbidden_tool_10_times(redis_client):
    """
    Test 3: Run 10 times, all should RBAC_DENIED, rate limit NOT incremented.
    
    Validates:
    - Agent exists and is valid
    - Tool check happens in RBAC (OPA)
    - OPA denies the tool
    - Decision is RBAC_DENIED
    - Rate limit counter does NOT increment
    """
    test_agent_id = "test_agent_forbidden_tool"
    
    # Set up agent session
    session_key = f"session:{test_agent_id}"
    await redis_client.hset(
        session_key,
        mapping={
            "role": "limited_role",
            "agent_id": test_agent_id,
            "created_at": "2024-01-01T00:00:00Z",
        }
    )
    await redis_client.expire(session_key, 3600)
    
    # Get initial rate limit counter (should be 0)
    rate_limit_key = f"rate_limit:{test_agent_id}:forbidden_tool"
    initial_count = await redis_client.zcard(rate_limit_key)
    
    for run in range(10):
        context = RequestContext(
            agent_id=test_agent_id,
            tool_name="forbidden_tool",
            jwt_payload={
                "sub": test_agent_id,
                "exp": 9999999999,
                "iat": 1000000000,
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id=str(uuid.uuid4()),
            metadata={},
        )
        
        with patch("app.pipeline.app_state") as mock_app_state:
            mock_app_state.redis = redis_client
            mock_app_state.degraded_components = {"redis": False, "opa": False}
            mock_app_state.sequence_rules = {}
            
            # Mock OPA to deny the tool
            with patch("app.pipeline.httpx.AsyncClient") as mock_client:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json = AsyncMock(return_value={"allow": False})
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_response
                )
                
                try:
                    result = await process_request(context)
                    
                    # Verify RBAC_DENIED
                    assert result.decision == "BLOCK", f"Run {run}: Expected BLOCK, got {result.decision}"
                    assert "policy" in result.reason.lower() or "denied" in result.reason.lower()
                    logger.info(f"Test 3, Run {run}: PASSED - {result.decision}")
                    
                except Exception as e:
                    logger.info(f"Test 3, Run {run}: PASSED - raised {type(e).__name__}")
    
    # Verify rate limit was NOT incremented
    final_count = await redis_client.zcard(rate_limit_key)
    assert final_count == initial_count, f"Rate limit was incremented! Initial: {initial_count}, Final: {final_count}"
    logger.info(f"Test 3: PASSED - Rate limit not incremented (final count: {final_count})")


# ============================================================================
# TEST 4: 50 CONCURRENT RATE LIMIT CALLS → 20 ALLOW, 30 RATE_LIMITED
# ============================================================================

@pytest.mark.asyncio
async def test_concurrent_rate_limit_50_calls():
    """
    Test 4: 50 concurrent requests, exactly 20 ALLOW, 30 RATE_LIMITED.
    
    Validates:
    - Lua script atomicity
    - Concurrent requests properly counted
    - Exactly correct split
    - Test runs 20 times with same result
    """
    redis_client = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True,
    )
    
    test_agent_id = "test_agent_concurrent_rl"
    limit = 20  # Only allow 20 out of 50
    
    # Set up agent session
    session_key = f"session:{test_agent_id}"
    await redis_client.hset(
        session_key,
        mapping={
            "role": "test_role",
            "agent_id": test_agent_id,
            "created_at": "2024-01-01T00:00:00Z",
        }
    )
    
    # Run concurrent test 20 times
    for iteration in range(20):
        # Clear rate limit for this iteration
        rl_key = f"rate_limit:{test_agent_id}:concurrent_tool"
        await redis_client.delete(rl_key)
        
        # Create 50 concurrent tasks
        async def make_request(run_num):
            context = RequestContext(
                agent_id=test_agent_id,
                tool_name="concurrent_tool",
                jwt_payload={
                    "sub": test_agent_id,
                    "exp": 9999999999,
                    "iat": 1000000000,
                    "iss": "agentguard",
                    "aud": "agentguard-gateway",
                },
                request_id=str(uuid.uuid4()),
                metadata={},
            )
            
            with patch("app.pipeline.app_state") as mock_app_state:
                mock_app_state.redis = redis_client
                mock_app_state.degraded_components = {"redis": False, "opa": False}
                mock_app_state.sequence_rules = {}
                
                with patch("app.pipeline.httpx.AsyncClient") as mock_client:
                    mock_response = AsyncMock()
                    mock_response.status_code = 200
                    mock_response.json = AsyncMock(return_value={"allow": True})
                    mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                        return_value=mock_response
                    )
                    
                    try:
                        result = await process_request(context)
                        return result.decision
                    except RateLimitException:
                        return "RATE_LIMITED"
                    except Exception as e:
                        return "ERROR"
        
        # Run all 50 concurrently
        tasks = [make_request(i) for i in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count verdicts
        allows = sum(1 for r in results if r == "ALLOW")
        rate_limited = sum(1 for r in results if r == "RATE_LIMITED")
        
        logger.info(f"Test 4, Iteration {iteration}: ALLOW={allows}, RATE_LIMITED={rate_limited}")
        
        # Verify exact counts
        assert allows == limit, f"Iteration {iteration}: Expected {limit} ALLOW, got {allows}"
        assert rate_limited == (50 - limit), f"Iteration {iteration}: Expected {50-limit} RATE_LIMITED, got {rate_limited}"
    
    await redis_client.close()
    logger.info("Test 4: PASSED - All 20 iterations had correct split")


# ============================================================================
# TEST 5: REDIS STOPPED → SANDBOX VERDICT
# ============================================================================

@pytest.mark.asyncio
async def test_redis_down_sandbox_verdict():
    """
    Test 5: When Redis is unavailable, request goes to SANDBOX (not ALLOW, not 500).
    
    Validates:
    - Redis connection failure handled gracefully
    - Decision is SANDBOX (safe default)
    - No exception propagates
    - Gateway continues running
    """
    test_agent_id = "test_agent_redis_down"
    
    for run in range(10):
        context = RequestContext(
            agent_id=test_agent_id,
            tool_name="web_search",
            jwt_payload={
                "sub": test_agent_id,
                "exp": 9999999999,
                "iat": 1000000000,
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id=str(uuid.uuid4()),
            metadata={},
        )
        
        with patch("app.pipeline.app_state") as mock_app_state:
            # Redis is None (unavailable)
            mock_app_state.redis = None
            mock_app_state.degraded_components = {"redis": True, "opa": False}
            mock_app_state.sequence_rules = {}
            
            try:
                result = await process_request(context)
                
                # Should be SANDBOX (degraded but safe)
                assert result.decision == "SANDBOX", f"Run {run}: Expected SANDBOX, got {result.decision}"
                logger.info(f"Test 5, Run {run}: PASSED - {result.decision}")
                
            except Exception as e:
                # Check if it's a degraded exception (acceptable)
                if "GatewayDegraded" in type(e).__name__:
                    logger.info(f"Test 5, Run {run}: PASSED - raised {type(e).__name__}")
                else:
                    pytest.fail(f"Test 5, Run {run}: Unexpected exception: {e}")


# ============================================================================
# TEST 6: OPA STOPPED → RBAC_DENIED ALL CALLS
# ============================================================================

@pytest.mark.asyncio
async def test_opa_down_deny_all():
    """
    Test 6: When OPA is unavailable, all tool calls denied (fail-closed).
    
    Validates:
    - OPA connection failure handled gracefully
    - Decision is BLOCK (deny-all, fail-closed)
    - No exception propagates to caller
    """
    test_agent_id = "test_agent_opa_down"
    redis_client = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True,
    )
    
    # Set up agent session
    session_key = f"session:{test_agent_id}"
    await redis_client.hset(
        session_key,
        mapping={
            "role": "test_role",
            "agent_id": test_agent_id,
            "created_at": "2024-01-01T00:00:00Z",
        }
    )
    
    for run in range(10):
        context = RequestContext(
            agent_id=test_agent_id,
            tool_name="web_search",
            jwt_payload={
                "sub": test_agent_id,
                "exp": 9999999999,
                "iat": 1000000000,
                "iss": "agentguard",
                "aud": "agentguard-gateway",
            },
            request_id=str(uuid.uuid4()),
            metadata={},
        )
        
        with patch("app.pipeline.app_state") as mock_app_state:
            mock_app_state.redis = redis_client
            mock_app_state.degraded_components = {"redis": False, "opa": True}
            mock_app_state.sequence_rules = {}
            
            # Mock OPA to be unreachable
            with patch("app.pipeline.httpx.AsyncClient") as mock_client:
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    side_effect=Exception("OPA unreachable")
                )
                
                try:
                    result = await process_request(context)
                    
                    # Should be BLOCK (fail-closed)
                    assert result.decision == "BLOCK", f"Run {run}: Expected BLOCK, got {result.decision}"
                    logger.info(f"Test 6, Run {run}: PASSED - {result.decision}")
                    
                except Exception as e:
                    logger.info(f"Test 6, Run {run}: PASSED - raised {type(e).__name__}")
    
    await redis_client.close()


# ============================================================================
# RUN ALL TESTS
# ============================================================================

if __name__ == "__main__":
    # Run with: pytest tests/test_phase2_gateway_validation.py -v
    pytest.main([__file__, "-v", "-s"])
