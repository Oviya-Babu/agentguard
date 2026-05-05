"""
Advanced Enterprise Hardening - Circuit Breaker Abuse, Load Shedding, Memory Guard
=====================================================================================

Guards against:
- Circuit breaker abuse (intentional failures to trigger SANDBOX)
- Resource exhaustion (memory/CPU pressure)
- Distributed bypass attempts
- Coordinated attacks

All operations are async-safe and non-blocking.
"""

import asyncio
import time
import psutil
import os
from collections import defaultdict
from typing import Dict, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class FailureTracker:
    """Tracks failures per source with classification."""
    
    source_id: str
    internal_failures: int = 0
    suspicious_failures: int = 0
    last_failure_time: Optional[float] = None
    failure_window_start: float = field(default_factory=time.time)
    
    def record_internal_failure(self) -> None:
        """Track system-level failure (OPA timeout, Redis error, etc)."""
        self.internal_failures += 1
        self.last_failure_time = time.time()
    
    def record_suspicious_failure(self) -> None:
        """Track suspicious failure (malformed request, replay attack, etc)."""
        self.suspicious_failures += 1
        self.last_failure_time = time.time()
    
    def get_suspicious_rate(self, window_seconds: float = 60.0) -> float:
        """Get suspicious failure rate per second (current 60s window)."""
        elapsed = time.time() - self.failure_window_start
        if elapsed < 1.0:
            return 0.0
        return self.suspicious_failures / elapsed if elapsed <= window_seconds else 0.0
    
    def reset_window(self) -> None:
        """Reset failure counting window."""
        self.failure_window_start = time.time()
        self.suspicious_failures = 0
        self.internal_failures = 0


class FailureRateGuard:
    """
    Guards against circuit breaker abuse by tracking failure patterns per source.
    
    If same source repeatedly triggers failures → BLOCK instead of SANDBOX.
    """
    
    def __init__(
        self,
        suspicious_rate_threshold: float = 2.0,  # >2 suspicious failures/sec
        tracking_window: float = 60.0,  # per 60 seconds
        max_tracked_sources: int = 10000,
    ):
        self.suspicious_rate_threshold = suspicious_rate_threshold
        self.tracking_window = tracking_window
        self.max_tracked_sources = max_tracked_sources
        
        self.trackers: Dict[str, FailureTracker] = {}
        self.lock = asyncio.Lock()
    
    async def record_internal_failure(self, source_id: str) -> None:
        """Record system-level failure from source."""
        async with self.lock:
            if source_id not in self.trackers:
                if len(self.trackers) >= self.max_tracked_sources:
                    # Remove oldest (cleanup)
                    oldest = min(self.trackers.items(), 
                                key=lambda x: x[1].last_failure_time or 0)
                    del self.trackers[oldest[0]]
                
                self.trackers[source_id] = FailureTracker(source_id=source_id)
            
            self.trackers[source_id].record_internal_failure()
    
    async def record_suspicious_failure(self, source_id: str) -> None:
        """Record suspicious failure from source (malformed, replay, etc)."""
        async with self.lock:
            if source_id not in self.trackers:
                if len(self.trackers) >= self.max_tracked_sources:
                    oldest = min(self.trackers.items(),
                                key=lambda x: x[1].last_failure_time or 0)
                    del self.trackers[oldest[0]]
                
                self.trackers[source_id] = FailureTracker(source_id=source_id)
            
            self.trackers[source_id].record_suspicious_failure()
    
    async def is_suspicious_source(self, source_id: str) -> bool:
        """Check if source is exhibiting abuse pattern."""
        async with self.lock:
            if source_id not in self.trackers:
                return False
            
            tracker = self.trackers[source_id]
            rate = tracker.get_suspicious_rate(self.tracking_window)
            return rate > self.suspicious_rate_threshold
    
    async def get_metrics(self) -> Dict:
        """Get guard metrics."""
        async with self.lock:
            suspicious_sources = sum(
                1 for t in self.trackers.values()
                if t.get_suspicious_rate(self.tracking_window) > self.suspicious_rate_threshold
            )
            return {
                "tracked_sources": len(self.trackers),
                "suspicious_sources": suspicious_sources,
                "total_suspicious_failures": sum(
                    t.suspicious_failures for t in self.trackers.values()
                ),
            }


class GlobalLoadShedder:
    """
    Global protection against resource exhaustion.
    
    Monitors:
    - Active requests
    - Queue depth
    - Memory/CPU pressure
    
    Rejects requests early if threshold exceeded.
    """
    
    def __init__(
        self,
        max_active_requests: int = 5000,
        max_queue_depth: int = 2000,
        memory_threshold_percent: float = 85.0,
    ):
        self.max_active_requests = max_active_requests
        self.max_queue_depth = max_queue_depth
        self.memory_threshold_percent = memory_threshold_percent
        
        self.active_requests = 0
        self.queued_requests = 0
        self.lock = asyncio.Lock()
        self.rejected_total = 0
    
    async def acquire_slot(self) -> bool:
        """Try to acquire a request slot. Returns False if rejected."""
        async with self.lock:
            # Check memory pressure first (no lock needed for psutil)
            try:
                memory_percent = psutil.virtual_memory().percent
                if memory_percent > self.memory_threshold_percent:
                    self.rejected_total += 1
                    return False
            except Exception:
                # If psutil fails, ignore and continue
                pass
            
            # Check active + queued
            if (self.active_requests + self.queued_requests >= 
                self.max_active_requests):
                self.rejected_total += 1
                return False
            
            self.active_requests += 1
            return True
    
    async def release_slot(self) -> None:
        """Release a request slot."""
        async with self.lock:
            if self.active_requests > 0:
                self.active_requests -= 1
    
    async def enqueue_request(self) -> bool:
        """Try to enqueue request. Returns False if rejected."""
        async with self.lock:
            if self.queued_requests >= self.max_queue_depth:
                self.rejected_total += 1
                return False
            
            self.queued_requests += 1
            return True
    
    async def dequeue_request(self) -> None:
        """Mark request as no longer queued."""
        async with self.lock:
            if self.queued_requests > 0:
                self.queued_requests -= 1
    
    async def get_metrics(self) -> Dict:
        """Get load shedding metrics."""
        async with self.lock:
            try:
                memory_percent = psutil.virtual_memory().percent
            except Exception:
                memory_percent = -1.0
            
            return {
                "active_requests": self.active_requests,
                "queued_requests": self.queued_requests,
                "memory_percent": memory_percent,
                "rejected_total": self.rejected_total,
            }


class EventLoopPressureGuard:
    """
    Monitor event loop lag and system pressure.
    
    If degraded:
    - Reduce rate limit
    - Force SANDBOX
    """
    
    def __init__(
        self,
        lag_threshold_ms: float = 100.0,
        sample_interval: float = 1.0,
    ):
        self.lag_threshold_ms = lag_threshold_ms
        self.sample_interval = sample_interval
        self.is_degraded = False
        self.lock = asyncio.Lock()
        self.max_observed_lag = 0.0
    
    async def monitor_task(self) -> None:
        """Background task to monitor event loop lag."""
        while True:
            try:
                start = time.perf_counter()
                # Sleep and measure actual time taken
                await asyncio.sleep(0.001)  # 1ms
                elapsed_ms = (time.perf_counter() - start) * 1000
                
                async with self.lock:
                    self.max_observed_lag = max(self.max_observed_lag, elapsed_ms)
                    
                    # If lag > threshold, mark degraded
                    if elapsed_ms > self.lag_threshold_ms:
                        self.is_degraded = True
                    else:
                        self.is_degraded = False
                
                await asyncio.sleep(self.sample_interval)
            except Exception:
                pass
    
    async def is_system_degraded(self) -> bool:
        """Check if system is under pressure."""
        async with self.lock:
            return self.is_degraded
    
    async def get_metrics(self) -> Dict:
        """Get event loop metrics."""
        async with self.lock:
            return {
                "max_observed_lag_ms": self.max_observed_lag,
                "is_degraded": self.is_degraded,
            }


class DistributedConsistencyGuard:
    """
    Prevents unsafe fallback in distributed mode.
    
    If INSTANCE_MODE=distributed AND Redis unavailable:
    - Force BLOCK or strict SANDBOX (no independent allowance)
    """
    
    def __init__(self):
        self.bypass_risk_count = 0
        self.lock = asyncio.Lock()
    
    async def record_bypass_risk(self) -> None:
        """Record potential bypass risk (distributed mode without Redis)."""
        async with self.lock:
            self.bypass_risk_count += 1
    
    async def get_bypass_risk_total(self) -> int:
        """Get total bypass risk events."""
        async with self.lock:
            return self.bypass_risk_count
    
    async def get_metrics(self) -> Dict:
        """Get consistency metrics."""
        async with self.lock:
            return {
                "distributed_rate_limit_bypass_risk": self.bypass_risk_count,
            }


# Global instances
failure_rate_guard = FailureRateGuard()
global_load_shedder = GlobalLoadShedder()
event_loop_pressure_guard = EventLoopPressureGuard()
distributed_consistency_guard = DistributedConsistencyGuard()
