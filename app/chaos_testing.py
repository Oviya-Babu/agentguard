"""
Chaos Test Mode
================

Randomly simulate infrastructure failures to validate resilience:
- Redis unavailable
- OPA delays
- Triage timeout
- Network latency spikes

Used only in test environments.
"""

import random
import asyncio
from typing import Dict, Optional
from enum import Enum


class ChaosMode(str, Enum):
    """Chaos injection modes."""
    OFF = "off"
    RANDOM = "random"
    REDIS_DOWN = "redis_down"
    OPA_SLOW = "opa_slow"
    TRIAGE_TIMEOUT = "triage_timeout"
    NETWORK_LATENCY = "network_latency"


class ChaosInjector:
    """
    Injects random failures for chaos testing.
    
    Should only be enabled in test environments.
    """
    
    def __init__(self, enabled: bool = False, mode: ChaosMode = ChaosMode.OFF):
        self.enabled = enabled
        self.mode = mode
        self.injection_count = 0
    
    def set_mode(self, mode: ChaosMode) -> None:
        """Set chaos injection mode."""
        self.mode = mode
    
    def enable(self) -> None:
        """Enable chaos injection."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable chaos injection."""
        self.enabled = False
    
    async def maybe_redis_failure(self) -> bool:
        """Randomly inject Redis failure."""
        if not self.enabled:
            return False
        
        if self.mode in (ChaosMode.OFF, ChaosMode.RANDOM):
            if random.random() < 0.1:  # 10% chance
                self.injection_count += 1
                return True
        elif self.mode == ChaosMode.REDIS_DOWN:
            self.injection_count += 1
            return True
        
        return False
    
    async def maybe_opa_delay(self) -> Optional[float]:
        """
        Randomly inject OPA delay.
        
        Returns: delay in seconds, or None if no injection
        """
        if not self.enabled:
            return None
        
        if self.mode in (ChaosMode.OFF, ChaosMode.RANDOM):
            if random.random() < 0.15:  # 15% chance
                delay = random.uniform(0.05, 0.5)  # 50-500ms
                self.injection_count += 1
                await asyncio.sleep(delay)
                return delay
        elif self.mode == ChaosMode.OPA_SLOW:
            delay = random.uniform(0.1, 0.3)
            self.injection_count += 1
            await asyncio.sleep(delay)
            return delay
        
        return None
    
    async def maybe_triage_timeout(self) -> bool:
        """Randomly inject Triage timeout."""
        if not self.enabled:
            return False
        
        if self.mode in (ChaosMode.OFF, ChaosMode.RANDOM):
            if random.random() < 0.05:  # 5% chance
                self.injection_count += 1
                return True
        elif self.mode == ChaosMode.TRIAGE_TIMEOUT:
            self.injection_count += 1
            return True
        
        return False
    
    async def maybe_network_latency(self) -> Optional[float]:
        """
        Randomly inject network latency.
        
        Returns: latency in seconds, or None if no injection
        """
        if not self.enabled:
            return None
        
        if self.mode in (ChaosMode.OFF, ChaosMode.RANDOM):
            if random.random() < 0.2:  # 20% chance
                latency = random.uniform(0.001, 0.1)  # 1-100ms
                self.injection_count += 1
                await asyncio.sleep(latency)
                return latency
        elif self.mode == ChaosMode.NETWORK_LATENCY:
            latency = random.uniform(0.01, 0.05)
            self.injection_count += 1
            await asyncio.sleep(latency)
            return latency
        
        return None
    
    def get_metrics(self) -> Dict:
        """Get chaos metrics."""
        return {
            "enabled": self.enabled,
            "mode": str(self.mode),
            "injection_count": self.injection_count,
        }


# Global instance (disabled by default)
chaos_injector = ChaosInjector(enabled=False, mode=ChaosMode.OFF)
