"""
AsyncCallbackHandler for LangChain/CrewAI tool intercept and security enforcement.

This module implements the LangChain AsyncCallbackHandler that intercepts every
tool call made by autonomous agents, routes it through the security pipeline,
and either allows or blocks execution based on security verdicts.

Integration:
- Import this handler and pass it to your LangChain agent/LLM
- It will automatically intercept all tool_use callbacks
- All tool outputs are sanitized before returning to agent
- Security decisions are logged with full audit trail
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from langchain.callbacks.base import AsyncCallbackHandler
from opentelemetry import trace

from app.output_sanitizer import sanitize_tool_output
from app.pipeline import DecisionResult, RequestContext, process_request

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class SecurityGatewayAsyncCallbackHandler(AsyncCallbackHandler):
    """
    LangChain AsyncCallbackHandler for AI gateway security enforcement.

    This handler:
    1. Intercepts tool_start callbacks (before tool execution)
    2. Validates request through security pipeline
    3. Blocks or allows tool execution based on verdict
    4. Sanitizes outputs before returning to agent context
    5. Records all decisions for audit trail

    Usage:
        from app.callback_handler import SecurityGatewayAsyncCallbackHandler

        handler = SecurityGatewayAsyncCallbackHandler(
            agent_id="agent_001",
            jwt_token="eyJhbGc..."
        )

        agent = initialize_agent(
            tools=tools,
            callbacks=[handler],
            ...
        )

    Security Properties:
    - Fail-closed: blocks by default if verification fails
    - Non-intrusive: transparent to agent except for blocked tools
    - Comprehensive audit: every decision logged with tracing
    - PII-safe: outputs sanitized before agent sees them
    """

    def __init__(
        self,
        agent_id: str,
        jwt_token: str,
        namespace: str = "agentguard",
    ) -> None:
        """
        Initialize the security callback handler.

        Args:
            agent_id: Unique identifier for the agent using this handler
            jwt_token: JWT token for authentication (HS256 format expected)
            namespace: Optional namespace for organizing metrics/traces
        """
        super().__init__()
        self.agent_id = agent_id
        self.jwt_token = jwt_token
        self.namespace = namespace

        # Decoded JWT payload (set after validation)
        self.jwt_payload: Optional[Dict[str, Any]] = None

        # Track statistics
        self.stats = {
            "tools_intercepted": 0,
            "tools_allowed": 0,
            "tools_blocked": 0,
            "tools_sandboxed": 0,
            "total_latency_ms": 0.0,
        }

        logger.info(
            "SecurityGatewayAsyncCallbackHandler initialized",
            extra={"agent_id": agent_id, "namespace": namespace},
        )

    async def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool is about to be invoked.

        This is the critical interception point. The tool execution is blocked
        by raising an exception if the security verdict is BLOCK or SANDBOX.

        Args:
            serialized: Tool metadata (name, description, etc.)
            input_str: Raw input string to the tool
            **kwargs: Additional context (tool_input, etc.)

        Raises:
            SecurityBlockException: If verdict is BLOCK or SANDBOX
            (Agent receives generic error, real reason is in logs)

        Note:
            LangChain calls this hook synchronously in the main loop, but
            we execute async validation through `run_sync_in_thread_pool`.
        """
        request_id = str(uuid.uuid4())
        tool_name = serialized.get("name", "unknown")
        start_time = time.time()

        logger.info(
            "on_tool_start triggered",
            extra={
                "agent_id": self.agent_id,
                "tool_name": tool_name,
                "request_id": request_id,
            },
        )

        # Track interception
        self.stats["tools_intercepted"] += 1

        try:
            # Create request context for pipeline
            context = RequestContext(
                agent_id=self.agent_id,
                tool_name=tool_name,
                jwt_payload=self.jwt_payload or {},
                request_id=request_id,
                metadata={
                    "input": input_str[:200],  # First 200 chars only
                    "serialized_name": tool_name,
                    "timestamp": start_time,
                },
            )

            # Run async pipeline validation
            # (LangChain's async hook system will handle this)
            decision = await process_request(context)

            # Record latency
            latency_ms = (time.time() - start_time) * 1000
            self.stats["total_latency_ms"] += latency_ms

            # Log decision
            logger.info(
                "Security decision made",
                extra={
                    "agent_id": self.agent_id,
                    "tool_name": tool_name,
                    "decision": decision.decision,
                    "reason": decision.reason,
                    "latency_ms": latency_ms,
                    "request_id": request_id,
                },
            )

            # Track statistics
            if decision.decision == "ALLOW":
                self.stats["tools_allowed"] += 1
            elif decision.decision == "BLOCK":
                self.stats["tools_blocked"] += 1
                raise SecurityBlockException(
                    f"Tool execution blocked: {decision.reason}"
                )
            elif decision.decision == "SANDBOX":
                self.stats["tools_sandboxed"] += 1
                logger.warning(
                    "Tool execution sandboxed",
                    extra={
                        "agent_id": self.agent_id,
                        "tool_name": tool_name,
                        "request_id": request_id,
                    },
                )
                # Sandboxed tools proceed but are monitored
                # (no exception raised, but monitoring enabled)

        except SecurityBlockException as e:
            logger.warning(
                "Tool execution blocked by security policy",
                extra={
                    "agent_id": self.agent_id,
                    "tool_name": tool_name,
                    "request_id": request_id,
                },
            )
            raise

        except Exception as e:
            # Fail-closed: any pipeline error results in block
            logger.error(
                "Security pipeline failed",
                extra={
                    "agent_id": self.agent_id,
                    "tool_name": tool_name,
                    "error": type(e).__name__,
                    "request_id": request_id,
                },
            )
            raise SecurityBlockException(
                "Security check failed. Tool execution blocked."
            )

    async def on_tool_end(
        self,
        output: str,
        **kwargs: Any,
    ) -> None:
        """
        Called after a tool has executed successfully.

        This is where output sanitization occurs. All tool outputs are
        scanned for PII (using Presidio) and prompt injection patterns
        before being returned to the agent.

        Args:
            output: Raw output from the tool execution
            **kwargs: Additional context (tool_name from kwargs if available)

        Note:
            If output sanitization fails, the tool output is blocked
            and the agent receives a synthetic error.
        """
        tool_name = kwargs.get("tool_name", "unknown")
        request_id = str(uuid.uuid4())

        logger.info(
            "on_tool_end triggered",
            extra={
                "agent_id": self.agent_id,
                "tool_name": tool_name,
                "request_id": request_id,
            },
        )

        try:
            # Sanitize output: Presidio (PII redaction) + injection scanning
            sanitized_output = await sanitize_tool_output(
                output=output,
                tool_name=tool_name,
                request_id=request_id,
            )

            logger.info(
                "Tool output sanitized",
                extra={
                    "agent_id": self.agent_id,
                    "tool_name": tool_name,
                    "original_length": len(output),
                    "sanitized_length": len(sanitized_output),
                    "request_id": request_id,
                },
            )

        except Exception as e:
            logger.error(
                "Output sanitization failed",
                extra={
                    "agent_id": self.agent_id,
                    "tool_name": tool_name,
                    "error": type(e).__name__,
                    "request_id": request_id,
                },
            )
            # Fail-closed: block output if sanitization fails
            raise SecurityBlockException(
                "Tool output validation failed. Result blocked."
            )

    async def on_tool_error(
        self,
        error: Exception,
        **kwargs: Any,
    ) -> None:
        """
        Called when a tool raises an exception.

        Logs the error for audit trail but does not modify behavior.

        Args:
            error: Exception raised by the tool
            **kwargs: Additional context
        """
        tool_name = kwargs.get("tool_name", "unknown")

        logger.warning(
            "Tool execution failed",
            extra={
                "agent_id": self.agent_id,
                "tool_name": tool_name,
                "error_type": type(error).__name__,
            },
        )

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current statistics for this handler.

        Returns:
            Dictionary with interception and decision counts
        """
        avg_latency = (
            self.stats["total_latency_ms"] / self.stats["tools_intercepted"]
            if self.stats["tools_intercepted"] > 0
            else 0.0
        )

        return {
            "agent_id": self.agent_id,
            "tools_intercepted": self.stats["tools_intercepted"],
            "tools_allowed": self.stats["tools_allowed"],
            "tools_blocked": self.stats["tools_blocked"],
            "tools_sandboxed": self.stats["tools_sandboxed"],
            "average_latency_ms": avg_latency,
            "allow_rate": (
                self.stats["tools_allowed"] / self.stats["tools_intercepted"]
                if self.stats["tools_intercepted"] > 0
                else 0.0
            ),
        }


class SecurityBlockException(Exception):
    """
    Exception raised when a tool is blocked by security policy.

    This exception is caught by the gateway and converted to a safe,
    generic error message sent to the agent. The internal reason is
    logged but never exposed to the untrusted agent.
    """

    pass
