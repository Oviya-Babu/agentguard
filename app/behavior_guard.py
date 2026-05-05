"""
Behavior Guard - Insider/Malicious Agent Detection
====================================================

Tracks anomalous patterns:
- Request frequency per agent
- Unusual tool combinations
- Temporal patterns
- Correlation with failures

All operations are async-safe.
"""

import time
from typing import Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import asyncio


@dataclass
class AgentProfile:
    """Behavioral profile for an agent."""
    
    agent_id: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0
    tool_requests: Dict[str, int] = field(default_factory=dict)
    hourly_requests: Dict[int, int] = field(default_factory=dict)
    failure_count: int = 0
    block_count: int = 0
    
    def add_request(self, tool_name: str) -> None:
        """Record a request from this agent."""
        self.request_count += 1
        self.last_seen = time.time()
        
        # Track tool usage
        self.tool_requests[tool_name] = self.tool_requests.get(tool_name, 0) + 1
        
        # Track hourly usage
        hour = int(time.time() / 3600) % 24
        self.hourly_requests[hour] = self.hourly_requests.get(hour, 0) + 1
    
    def add_failure(self) -> None:
        """Record a failed request."""
        self.failure_count += 1
    
    def add_block(self) -> None:
        """Record a blocked request."""
        self.block_count += 1
    
    def get_failure_rate(self) -> float:
        """Get failure rate (0.0 to 1.0)."""
        if self.request_count == 0:
            return 0.0
        return self.failure_count / self.request_count
    
    def get_block_rate(self) -> float:
        """Get block rate (0.0 to 1.0)."""
        if self.request_count == 0:
            return 0.0
        return self.block_count / self.request_count
    
    def get_tool_entropy(self) -> float:
        """
        Calculate entropy of tool usage.
        
        High entropy = varied tools (normal)
        Low entropy = repetitive tools (suspicious)
        """
        if not self.tool_requests or sum(self.tool_requests.values()) == 0:
            return 0.0
        
        total = sum(self.tool_requests.values())
        entropy = 0.0
        
        for count in self.tool_requests.values():
            if count > 0:
                p = count / total
                entropy -= p * (p.bit_length() - 1) if p > 0 else 0
        
        return entropy


class BehaviorGuard:
    """
    Detects anomalous agent behavior.
    
    Flags for:
    - High failure rate
    - Sudden request spike
    - Unusual tool combinations
    - Repeated blocking
    """
    
    def __init__(
        self,
        failure_rate_threshold: float = 0.5,  # >50% failures
        block_rate_threshold: float = 0.3,  # >30% blocks
        spike_multiplier: float = 10.0,  # 10x average
        min_requests_for_detection: int = 5,
        max_tracked_agents: int = 50000,
    ):
        self.failure_rate_threshold = failure_rate_threshold
        self.block_rate_threshold = block_rate_threshold
        self.spike_multiplier = spike_multiplier
        self.min_requests_for_detection = min_requests_for_detection
        self.max_tracked_agents = max_tracked_agents
        
        self.profiles: Dict[str, AgentProfile] = {}
        self.suspicious_agents: Set[str] = set()
        self.lock = asyncio.Lock()
        
        # Global average for spike detection
        self.global_avg_rps = 0.0
        self.last_update = time.time()
    
    async def record_request(self, agent_id: str, tool_name: str) -> None:
        """Record a request from agent."""
        async with self.lock:
            if agent_id not in self.profiles:
                if len(self.profiles) >= self.max_tracked_agents:
                    # Remove oldest
                    oldest = min(self.profiles.items(),
                                key=lambda x: x[1].last_seen)
                    del self.profiles[oldest[0]]
                
                self.profiles[agent_id] = AgentProfile(agent_id=agent_id)
            
            self.profiles[agent_id].add_request(tool_name)
    
    async def record_failure(self, agent_id: str) -> None:
        """Record a failed request from agent."""
        async with self.lock:
            if agent_id in self.profiles:
                self.profiles[agent_id].add_failure()
    
    async def record_block(self, agent_id: str) -> None:
        """Record a blocked request from agent."""
        async with self.lock:
            if agent_id in self.profiles:
                self.profiles[agent_id].add_block()
    
    async def is_suspicious(self, agent_id: str) -> Tuple[bool, Optional[str]]:
        """
        Check if agent is exhibiting anomalous behavior.
        
        Returns: (is_suspicious, reason)
        """
        async with self.lock:
            if agent_id not in self.profiles:
                return False, None
            
            profile = self.profiles[agent_id]
            
            # Need minimum requests for reliable detection
            if profile.request_count < self.min_requests_for_detection:
                return False, None
            
            # Check failure rate
            if profile.get_failure_rate() > self.failure_rate_threshold:
                return True, "High failure rate"
            
            # Check block rate
            if profile.get_block_rate() > self.block_rate_threshold:
                return True, "High block rate"
            
            # Check for request spike (compared to global average)
            time_alive = time.time() - profile.first_seen
            if time_alive > 0:
                current_rps = profile.request_count / time_alive
                expected = self.global_avg_rps * self.spike_multiplier
                if current_rps > expected and profile.request_count > 100:
                    return True, "Request spike detected"
            
            # Check for unusual tool combination
            # (Very specific tools or extreme focus)
            if len(profile.tool_requests) == 1 and profile.request_count > 50:
                return True, "Exclusive tool focus"
            
            return False, None
    
    async def get_suspicious_agents(self) -> Set[str]:
        """Get list of currently suspicious agents."""
        async with self.lock:
            suspicious = set()
            for agent_id, profile in self.profiles.items():
                if profile.request_count >= self.min_requests_for_detection:
                    is_sus, _ = await self.is_suspicious(agent_id)
                    if is_sus:
                        suspicious.add(agent_id)
            
            self.suspicious_agents = suspicious
            return suspicious
    
    async def update_global_stats(self) -> None:
        """Update global statistics for spike detection."""
        async with self.lock:
            if not self.profiles:
                return
            
            # Calculate average RPS across all agents
            total_rps = 0.0
            count = 0
            
            for profile in self.profiles.values():
                time_alive = time.time() - profile.first_seen
                if time_alive > 0:
                    total_rps += profile.request_count / time_alive
                    count += 1
            
            if count > 0:
                self.global_avg_rps = total_rps / count
            
            self.last_update = time.time()
    
    async def get_metrics(self) -> Dict:
        """Get behavior guard metrics."""
        async with self.lock:
            suspicious = await self.get_suspicious_agents()
            return {
                "tracked_agents": len(self.profiles),
                "suspicious_agents": len(suspicious),
                "global_avg_rps": self.global_avg_rps,
                "suspicious_agents_total": len(self.suspicious_agents),
            }


# Global instance
behavior_guard = BehaviorGuard()
