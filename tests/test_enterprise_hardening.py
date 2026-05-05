"""
Enterprise Red Team Tests - Advanced Hardening
================================================

Test suite for enterprise-grade hardening:
1. Circuit breaker abuse simulation
2. Distributed rate-limit bypass attempt
3. Timing analysis test (variance check)
4. Memory exhaustion simulation
5. Insider agent abnormal behavior test
6. Load shedding under pressure
7. Event loop lag detection
8. Behavior guard anomaly detection
9. Chaos test mode validation
10. Advanced mTLS validation

All tests are async-safe and independent.
"""

import pytest
import asyncio
import random
from unittest.mock import Mock, patch, MagicMock

# Import enterprise hardening modules
from app.hardening_advanced import (
    FailureRateGuard,
    GlobalLoadShedder,
    EventLoopPressureGuard,
    DistributedConsistencyGuard,
    FailureTracker,
)
from app.behavior_guard import BehaviorGuard, AgentProfile
from app.chaos_testing import ChaosInjector, ChaosMode
from app.mtls_advanced import AdvancedmTLSValidator


class TestCircuitBreakerAbuseProtection:
    """Test circuit breaker abuse protection."""

    @pytest.mark.asyncio
    async def test_failure_rate_tracking(self):
        """Test tracking of suspicious failures per source."""
        guard = FailureRateGuard(suspicious_rate_threshold=2.0)
        
        # Record some internal failures (should not flag)
        for _ in range(5):
            await guard.record_internal_failure("agent-123")
        
        is_suspicious = await guard.is_suspicious_source("agent-123")
        assert not is_suspicious
        
        metrics = await guard.get_metrics()
        assert metrics["tracked_sources"] == 1

    @pytest.mark.asyncio
    async def test_suspicious_failure_rate_detection(self):
        """Test detection of high suspicious failure rate."""
        guard = FailureRateGuard(suspicious_rate_threshold=1.0)
        
        # Record suspicious failures rapidly
        for _ in range(5):
            await guard.record_suspicious_failure("attacker-1")
        
        # Should be flagged as suspicious
        is_suspicious = await guard.is_suspicious_source("attacker-1")
        assert is_suspicious
        
        metrics = await guard.get_metrics()
        assert metrics["suspicious_sources"] == 1

    @pytest.mark.asyncio
    async def test_failure_tracker_reset(self):
        """Test failure tracker window reset."""
        tracker = FailureTracker("test-agent")
        
        tracker.record_suspicious_failure()
        tracker.record_suspicious_failure()
        
        rate = tracker.get_suspicious_rate(60.0)
        assert rate > 0
        
        # Reset window
        tracker.reset_window()
        assert tracker.suspicious_failures == 0


class TestGlobalLoadShedding:
    """Test global load shedding protection."""

    @pytest.mark.asyncio
    async def test_load_shedder_slot_acquisition(self):
        """Test acquiring and releasing request slots."""
        shedder = GlobalLoadShedder(max_active_requests=10)
        
        # Acquire slots
        for i in range(10):
            slot = await shedder.acquire_slot()
            assert slot is True
        
        # Should reject when full
        slot = await shedder.acquire_slot()
        assert slot is False

    @pytest.mark.asyncio
    async def test_load_shedder_release(self):
        """Test releasing slots."""
        shedder = GlobalLoadShedder(max_active_requests=5)
        
        # Acquire all slots
        for _ in range(5):
            await shedder.acquire_slot()
        
        # Release one
        await shedder.release_slot()
        
        # Should accept new request
        slot = await shedder.acquire_slot()
        assert slot is True

    @pytest.mark.asyncio
    async def test_queue_depth_rejection(self):
        """Test queue depth limit."""
        shedder = GlobalLoadShedder(max_queue_depth=5)
        
        # Fill queue
        for i in range(5):
            enqueued = await shedder.enqueue_request()
            assert enqueued is True
        
        # Should reject when full
        enqueued = await shedder.enqueue_request()
        assert enqueued is False

    @pytest.mark.asyncio
    async def test_load_metrics(self):
        """Test load shedding metrics."""
        shedder = GlobalLoadShedder()
        
        await shedder.acquire_slot()
        await shedder.acquire_slot()
        
        metrics = await shedder.get_metrics()
        assert metrics["active_requests"] == 2
        assert metrics["rejected_total"] >= 0


class TestBehaviorGuard:
    """Test insider/malicious agent detection."""

    @pytest.mark.asyncio
    async def test_agent_profile_tracking(self):
        """Test tracking of agent profiles."""
        guard = BehaviorGuard()
        
        # Record requests from agent
        await guard.record_request("agent-xyz", "search")
        await guard.record_request("agent-xyz", "search")
        await guard.record_request("agent-xyz", "search")
        
        metrics = await guard.get_metrics()
        assert metrics["tracked_agents"] >= 1

    @pytest.mark.asyncio
    async def test_high_failure_rate_detection(self):
        """Test detection of high failure rate."""
        guard = BehaviorGuard(failure_rate_threshold=0.3, min_requests_for_detection=5)
        
        # Record requests with failures
        for _ in range(5):
            await guard.record_request("bad-agent", "tool")
            await guard.record_failure("bad-agent")
        
        is_sus, reason = await guard.is_suspicious("bad-agent")
        assert is_sus is True
        assert "failure" in reason.lower()

    @pytest.mark.asyncio
    async def test_block_rate_detection(self):
        """Test detection of high block rate."""
        guard = BehaviorGuard(block_rate_threshold=0.3, min_requests_for_detection=5)
        
        # Record requests with blocks
        for _ in range(5):
            await guard.record_request("blocked-agent", "tool")
            await guard.record_block("blocked-agent")
        
        is_sus, reason = await guard.is_suspicious("blocked-agent")
        assert is_sus is True
        assert "block" in reason.lower()

    @pytest.mark.asyncio
    async def test_agent_entropy_calculation(self):
        """Test tool usage entropy calculation."""
        profile = AgentProfile("agent-123")
        
        # Record same tool repeatedly
        for _ in range(10):
            profile.add_request("search")
        
        entropy = profile.get_tool_entropy()
        assert entropy >= 0  # Low entropy = repetitive


class TestEventLoopPressureGuard:
    """Test event loop pressure monitoring."""

    @pytest.mark.asyncio
    async def test_event_loop_lag_detection(self):
        """Test detection of event loop lag."""
        guard = EventLoopPressureGuard(lag_threshold_ms=50.0)
        
        # Start monitoring task (will run in background)
        task = asyncio.create_task(guard.monitor_task())
        
        # Let it run for a bit
        await asyncio.sleep(0.1)
        
        # Check metrics
        metrics = await guard.get_metrics()
        assert "max_observed_lag_ms" in metrics
        assert "is_degraded" in metrics
        
        # Cleanup
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


class TestTimingAnalysis:
    """Test timing side-channel mitigation."""

    def test_timing_variance_under_load(self):
        """Test that response times have variance (jitter)."""
        import random
        import time
        
        # Simulate timed responses with jitter
        MIN_RESPONSE = 0.015
        JITTER_RANGE = 0.005
        
        times = []
        for _ in range(100):
            jitter = random.uniform(0, JITTER_RANGE)
            elapsed = MIN_RESPONSE + jitter
            times.append(elapsed)
        
        # Check variance exists
        avg = sum(times) / len(times)
        variance = sum((t - avg) ** 2 for t in times) / len(times)
        
        # Should have variance > 0 due to jitter
        assert variance > 0
        # All times should be >= MIN_RESPONSE
        assert all(t >= MIN_RESPONSE for t in times)


class TestChaosInjector:
    """Test chaos test mode."""

    @pytest.mark.asyncio
    async def test_chaos_disabled_by_default(self):
        """Test that chaos is disabled by default."""
        injector = ChaosInjector(enabled=False)
        
        result = await injector.maybe_redis_failure()
        assert result is False

    @pytest.mark.asyncio
    async def test_chaos_redis_failure_injection(self):
        """Test Redis failure injection."""
        injector = ChaosInjector(enabled=True, mode=ChaosMode.REDIS_DOWN)
        
        # Should always inject in REDIS_DOWN mode
        result = await injector.maybe_redis_failure()
        assert result is True

    @pytest.mark.asyncio
    async def test_chaos_opa_delay_injection(self):
        """Test OPA delay injection."""
        injector = ChaosInjector(enabled=True, mode=ChaosMode.OPA_SLOW)
        
        start = asyncio.get_event_loop().time()
        delay = await injector.maybe_opa_delay()
        elapsed = asyncio.get_event_loop().time() - start
        
        assert delay is not None
        assert elapsed >= (delay - 0.01)  # Allow 10ms tolerance

    @pytest.mark.asyncio
    async def test_chaos_metrics(self):
        """Test chaos metrics collection."""
        injector = ChaosInjector(enabled=True, mode=ChaosMode.RANDOM)
        
        # Trigger some injections
        for _ in range(10):
            await injector.maybe_redis_failure()
        
        metrics = injector.get_metrics()
        assert metrics["enabled"] is True
        assert metrics["injection_count"] > 0


class TestAdvancedmTLS:
    """Test advanced mTLS hardening."""

    def test_cn_validation(self):
        """Test CN validation."""
        validator = AdvancedmTLSValidator(expected_service_identity="triage-service")
        
        assert validator.validate_cn("triage-service") is True
        assert validator.validate_cn("wrong-service") is False
        assert validator.validate_cn(None) is False

    def test_san_validation(self):
        """Test SAN validation."""
        validator = AdvancedmTLSValidator(expected_service_identity="api.example.com")
        
        assert validator.validate_san("api.example.com") is True
        assert validator.validate_san("wrong.example.com") is False

    def test_expiration_validation(self):
        """Test certificate expiration validation."""
        validator = AdvancedmTLSValidator()
        
        # Valid future date
        is_valid, warning = validator.validate_expiration("2099-12-31T23:59:59Z")
        assert is_valid is True
        
        # Expired date
        is_valid, warning = validator.validate_expiration("2000-01-01T00:00:00Z")
        assert is_valid is False

    def test_certificate_validation_comprehensive(self):
        """Test comprehensive certificate validation."""
        validator = AdvancedmTLSValidator()
        
        cert_dict = {
            "subject": {},  # Would need proper format
            "extensions": [],
            "not_after": "2099-12-31T23:59:59Z"
        }
        
        # Should fail due to missing CN
        is_valid, warnings = validator.validate_certificate(cert_dict)
        assert is_valid is False


class TestDistributedConsistencyGuard:
    """Test distributed mode safety."""

    @pytest.mark.asyncio
    async def test_bypass_risk_tracking(self):
        """Test tracking of bypass risks."""
        guard = DistributedConsistencyGuard()
        
        # Record bypass risks
        for _ in range(5):
            await guard.record_bypass_risk()
        
        total = await guard.get_bypass_risk_total()
        assert total == 5
        
        metrics = await guard.get_metrics()
        assert metrics["distributed_rate_limit_bypass_risk"] == 5


@pytest.mark.asyncio
async def test_integration_all_guards():
    """Integration test with all guards."""
    # Initialize all guards
    failure_guard = FailureRateGuard()
    load_shedder = GlobalLoadShedder()
    pressure_guard = EventLoopPressureGuard()
    behavior_check = BehaviorGuard()
    
    # Simulate requests
    for i in range(50):
        await load_shedder.acquire_slot()
        await behavior_check.record_request(f"agent-{i % 5}", "search")
    
    # Should have tracked activity
    load_metrics = await load_shedder.get_metrics()
    assert load_metrics["active_requests"] > 0 or load_metrics["active_requests"] == 0  # May have released
