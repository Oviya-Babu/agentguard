"""
Security-critical exception hierarchy for the AI gateway system.

This module defines all exceptions used to control tool execution decisions
in a zero-trust architecture. Exceptions are SIGNALS only—they communicate
blocking decisions without exposing internal system details to external agents.

Security Requirements:
- Exception messages are always generic and safe for agent consumption
- Internal reasoning (policies, scores, rules) is never exposed to clients
- All exceptions are lightweight signal-only constructs
- No logging, external imports, or complex logic in exceptions
"""

from typing import Optional


class SecurityBlockException(Exception):
    """
    Base exception for all security-related execution blocks in the gateway.

    This exception is raised when a tool execution is blocked due to security
    policy violations in a zero-trust architecture. It encapsulates blocking
    context (reason, agent_id, tool_name, triage_score, owasp_ref) but
    sanitizes all external representations to prevent information leakage.

    Why it exists in zero-trust:
    - Centralizes all security block signals for consistent handling
    - Provides structured context for logging and audit trails
    - Separates internal reasoning from external communication
    - Enables fine-grained access control decisions

    Security Note:
    This exception must never expose sensitive details such as policy rules,
    scoring algorithms, system configuration, or internal state to external
    consumers (agents). The __str__ method is sanitized; internal state
    remains accessible for logging systems only.
    """

    def __init__(
        self,
        reason: str,
        agent_id: str,
        tool_name: str,
        triage_score: Optional[float] = None,
        owasp_ref: Optional[str] = None,
    ) -> None:
        """
        Initialize a security block exception.

        Args:
            reason: Internal reason for blocking (audit/logging context only).
                Should describe the policy violation clearly for internal systems.
            agent_id: Unique identifier of the agent making the request.
                Used for audit trails and rate limiting attribution.
            tool_name: Name of the tool being accessed.
                Used to track which resources trigger blocks.
            triage_score: Optional security triage risk score (0.0-1.0).
                Populated by automated threat detection systems.
                Higher scores indicate higher risk.
            owasp_ref: Optional reference to OWASP Top 10 category.
                Examples: "A07:2021-Identification and Authentication Failures"
                Useful for categorizing security violations.

        Raises:
            None. This is a pure data container exception.
        """
        self._reason: str = reason
        self._agent_id: str = agent_id
        self._tool_name: str = tool_name
        self._triage_score: Optional[float] = triage_score
        self._owasp_ref: Optional[str] = owasp_ref
        super().__init__(self._get_safe_message())

    def __str__(self) -> str:
        """
        Return a safe, generic string representation.

        Overriding __str__ ensures that converting the exception to a string
        always produces a sanitized message suitable for external consumption.
        This prevents accidental leakage of internal details through string
        conversion, repr(), or logging that uses str().

        Returns:
            A generic message that is safe to transmit to untrusted agents.
            Contains no information about policies, configurations, or
            blocking rationale.
        """
        return self._get_safe_message()

    def _get_safe_message(self) -> str:
        """
        Generate a safe, generic message suitable for external consumption.

        This method is called during exception initialization to set the
        exception message. It ensures that str(exception) never leaks
        internal system details.

        Returns:
            A generic message that is safe to transmit to untrusted agents.
            Contains no information about policies, configurations, or
            blocking rationale.
        """
        return "Tool access denied"

    @property
    def reason(self) -> str:
        """Read-only access to the internal blocking reason."""
        return self._reason

    @property
    def agent_id(self) -> str:
        """Read-only access to the agent identifier."""
        return self._agent_id

    @property
    def tool_name(self) -> str:
        """Read-only access to the tool name."""
        return self._tool_name

    @property
    def triage_score(self) -> Optional[float]:
        """Read-only access to the security triage risk score."""
        return self._triage_score

    @property
    def owasp_ref(self) -> Optional[str]:
        """Read-only access to the OWASP reference."""
        return self._owasp_ref

    def get_internal_context(self) -> dict:
        """
        Retrieve full internal context for logging and debugging.

        This is the ONLY approved method for accessing the complete internal
        state of the exception. It provides a structured dictionary suitable
        for audit logging, error tracing, and internal system debugging.

        This method is intended for internal use only by trusted components
        (logging systems, audit trails, internal error handlers). It must
        NEVER be called from external-facing APIs or agent-accessible code.

        Returns:
            A dictionary containing all internal context fields:
            - reason: The internal reason for blocking
            - agent_id: Identifier of the blocking agent
            - tool_name: Name of the blocked tool
            - triage_score: Security risk score (if available)
            - owasp_ref: OWASP category reference (if available)
        """
        return {
            "reason": self._reason,
            "agent_id": self._agent_id,
            "tool_name": self._tool_name,
            "triage_score": self._triage_score,
            "owasp_ref": self._owasp_ref,
        }


class RegistrationException(SecurityBlockException):
    """
    Raised when an agent's identity cannot be verified or is revoked.

    This exception indicates that the agent attempting to access a tool
    does not have valid, current registration with the control plane.
    The agent's credentials are either invalid, expired, or not recognized.

    When raised:
    - Agent provides invalid or malformed credentials
    - Agent's registration has been explicitly revoked
    - Agent's identity cannot be verified against the registry
    - Agent's certificate has expired
    - Agent's API key is not recognized

    Why it exists in zero-trust:
    - Every agent must maintain continuous valid registration
    - Identity verification is the foundation of zero-trust
    - Enables rapid credential revocation and invalidation
    - Provides basis for all downstream access control decisions
    - Prevents credential reuse after revocation
    """

    def _get_safe_message(self) -> str:
        return "Invalid agent credentials"


class RBACDeniedException(SecurityBlockException):
    """
    Raised when an agent's role(s) lack required tool permissions.

    This exception indicates that the agent has been authenticated and
    registered, but their assigned roles do not grant access to the
    requested tool. In zero-trust RBAC, access is never implicit—every
    tool access requires explicit permission granted via role assignment.

    When raised:
    - Agent's role(s) do not include required permission
    - Tool requires higher privilege level than agent possesses
    - Cross-tenant access is attempted by same-tenant agent
    - Tool is restricted to specific role or role group
    - Agent's role assignment has been revoked

    Why it exists in zero-trust:
    - Enforces principle of least privilege
    - Every access requires explicit authorization
    - No implicit allows; all access must be explicitly granted
    - Enables fine-grained permission management
    - Supports role-based security policies
    """

    def _get_safe_message(self) -> str:
        return "Tool access denied"


class RateLimitException(SecurityBlockException):
    """
    Raised when an agent exceeds configured rate limits.

    Rate limiting is a critical control that protects system resources
    and prevents abuse. This exception is raised when an agent has exceeded
    their quota for a specific tool, endpoint, or time window.

    When raised:
    - Agent exceeds requests-per-minute limit
    - Agent exceeds requests-per-hour limit
    - Agent exceeds total concurrent request limit
    - Tool-specific quota for agent has been exhausted
    - Tenant-level rate limit has been exceeded

    Why it exists in zero-trust:
    - Defense against DoS attacks and resource exhaustion
    - Prevents single agent from consuming all gateway capacity
    - Enforces fair resource sharing across agents
    - Enables capacity planning and SLA enforcement
    - Slows potential attackers' ability to exploit gateway

    Implementation Note:
    Rate limit blocks are typically temporary; agents may retry after
    the time window expires. This differs from permanent blocks like
    RegistrationException.
    """

    def _get_safe_message(self) -> str:
        return "Rate limit exceeded"


class SequenceViolationException(SecurityBlockException):
    """
    Raised when an agent violates required tool execution sequences.

    Some tools have prerequisites or strict ordering constraints. For example,
    authentication must complete before resource access, or a setup/init tool
    must run before its dependent tools. This exception is raised when an
    agent attempts to violate these required sequences.

    When raised:
    - Agent attempts tool without completing required prerequisite
    - Agent attempts tool in wrong sequence (e.g., before setup)
    - Agent skips mandatory initialization step
    - Agent attempts backward tool transition in required workflow
    - Tool's dependency constraint is violated

    Why it exists in zero-trust:
    - Enforces secure workflow constraints
    - Prevents state-based security bypasses
    - Ensures audit trail completeness and traceability
    - Maintains system state consistency
    - Prevents tools from being used in unintended ways
    - Protects against workflow manipulation attacks

    Example Sequence Rule:
    ["authenticate", "setup", "execute", "cleanup"]
    Attempting "execute" without prior "setup" raises this exception.
    """

    def _get_safe_message(self) -> str:
        return "Tool access denied"


class TriageBlockException(SecurityBlockException):
    """
    Raised when automated security triage system blocks execution.

    The triage system performs real-time automated security analysis,
    behavioral assessment, and anomaly detection. If analysis determines
    high-risk behavior or suspicious patterns, this exception is raised
    to block execution and quarantine the agent.

    When raised:
    - Agent behavior exhibits statistical anomalies
    - Triage security risk score exceeds configured threshold
    - Behavioral pattern matches known attack signatures
    - Tool combination sequence suggests malicious intent
    - Agent makes unusual access patterns for their role
    - Agent attempts suspicious tool chaining
    - Automated threat detection system flags agent

    Why it exists in zero-trust:
    - Automated threat detection and response
    - Behavioral anomaly detection beyond static policies
    - Risk-based access control supplementing RBAC
    - Real-time security posture assessment
    - Prevents zero-day attacks and novel attack patterns
    - Detects compromised agent credentials in use
    - Adapts to emerging threats without policy updates

    Triage System Integration:
    The triage_score field (0.0-1.0) contains the risk assessment.
    Higher scores indicate higher confidence of malicious behavior.
    Typical threshold: score > 0.7 triggers this exception.
    """

    def _get_safe_message(self) -> str:
        return "Tool access denied"


class GatewayDegradedException(Exception):
    """
    Raised when critical gateway infrastructure is partially unavailable.

    This exception indicates OPERATIONAL DEGRADATION, not a security block.
    It is raised when external dependencies (caches, policy engines, databases)
    become unreachable or unresponsive. This is recoverable and retryable,
    unlike security block exceptions.

    This exception is NOT a subclass of SecurityBlockException because:
    - It does not represent a security policy violation
    - It is temporary and potentially recoverable
    - It should be handled differently (retry, fallback, circuit breaker)
    - It does not require agent audit logging

    When raised:
    - Redis cache becomes unreachable
    - OPA policy engine does not respond
    - Database connection pool is exhausted
    - External service circuit breaker is open
    - Health check fails for critical infrastructure component
    - Temporary network partition prevents backend access

    Why it exists in zero-trust:
    - Distinguishes infrastructure failures from security blocks
    - Enables appropriate retry and recovery strategies
    - Allows graceful degradation of non-core services
    - Prevents security decisions based on unavailable data
    - Supports circuit breaker and fallback patterns

    Recovery Strategy:
    Clients should implement exponential backoff retry logic.
    Unlike security blocks, retries may eventually succeed.
    """

    def __init__(
        self,
        component: str,
        reason: str,
    ) -> None:
        """
        Initialize a gateway degradation exception.

        Args:
            component: Name of the degraded system component.
                Examples: "redis", "opa", "database", "auth-service"
                Used to identify which system is unavailable.
            reason: Human-readable reason for degradation.
                Examples: "connection timeout", "max retries exceeded"
                Used for logging and debugging only.

        Raises:
            None. This is a pure data container exception.
        """
        self.component: str = component
        self.reason: str = reason
        super().__init__(f"Gateway service temporarily unavailable")
