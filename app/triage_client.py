"""
Triage engine client with strict contract and failure isolation.

This module implements a secure, fail-closed client for the external
triage security engine. All responses are validated strictly, and all
failures default to SANDBOX (safe default, never ALLOW).

Triage is called AFTER authentication and RBAC but BEFORE final ALLOW decision.
It provides behavioral analysis and anomaly detection.
"""

import logging
import os
from typing import Any, Dict, Literal, Optional

import httpx
from opentelemetry import metrics
from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)

# OpenTelemetry metrics
metrics_provider = metrics.get_meter_provider()
meter = metrics_provider.get_meter(__name__)

triage_failure_counter = meter.create_counter(
    "triage_failure_total",
    description="Total number of triage failures",
)

triage_latency_histogram = meter.create_histogram(
    "triage_latency_ms",
    description="Triage call latency in milliseconds",
)


# ============================================================================
# TRIAGE RESPONSE MODEL (STRICT CONTRACT)
# ============================================================================


class TriageResponse(BaseModel):
    """
    Strict contract for triage engine response.

    Enforces:
    - All required fields must be present
    - No unknown fields allowed (extra="forbid")
    - Score strictly bounded [0.0, 1.0]
    - Verdict is restricted to allowed values

    This model is used for validation only - all fields are required.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["ALLOW", "SANDBOX", "BLOCK"] = Field(
        ..., description="Security verdict from triage"
    )
    score: float = Field(
        ..., ge=0.0, le=1.0, description="Risk score [0.0-1.0]"
    )
    explanation: str = Field(
        ..., min_length=1, description="Explanation of verdict"
    )
    owasp_ref: Optional[str] = Field(
        None, description="OWASP reference if applicable"
    )
    request_id: str = Field(..., description="Request ID for correlation")


# ============================================================================
# TRIAGE ENGINE CLIENT
# ============================================================================


async def call_triage_engine(payload: Dict[str, Any]) -> TriageResponse:
    """
    Call the external triage security engine (fail-closed).

    This function wraps the triage engine call with strict validation
    and failure handling. On ANY failure, returns a safe SANDBOX response
    rather than raising an exception or defaulting to ALLOW.

    Args:
        payload: Request payload containing:
            - agent_id: Agent identifier
            - tool_name: Tool being accessed
            - request_id: Request ID for tracing

    Returns:
        TriageResponse with verdict, score, and explanation

    Security Guarantees:
    - Never raises exceptions (fail-closed)
    - Always returns a response (synthetic if engine fails)
    - Never defaults to ALLOW on failure
    - All responses are strictly validated
    - No partial or malformed responses accepted
    """
    triage_url = os.getenv("TRIAGE_URL")
    request_id = payload.get("request_id", "unknown")

    # If triage not configured, sandbox request
    if not triage_url:
        logger.debug(
            "Triage engine not configured",
            extra={"request_id": request_id},
        )
        return TriageResponse(
            verdict="SANDBOX",
            score=0.5,
            explanation="Triage engine not configured",
            owasp_ref=None,
            request_id=request_id,
        )

    import time

    start_time = time.time()
    cert_dir = os.getenv("TRIAGE_CERT_DIR", "/etc/triage/certs")

    try:
        # Load mTLS certificates
        client_cert = None
        client_key = None
        verify_cert = None

        try:
            cert_file = os.path.join(cert_dir, "client.crt")
            key_file = os.path.join(cert_dir, "client.key")
            ca_file = os.path.join(cert_dir, "ca.crt")

            if os.path.exists(cert_file) and os.path.exists(key_file):
                client_cert = (cert_file, key_file)

            if os.path.exists(ca_file):
                verify_cert = ca_file
            else:
                # CRITICAL: No CA cert = fail-closed to SANDBOX
                logger.warning(
                    "Triage mTLS CA certificate missing",
                    extra={"request_id": request_id},
                )
                triage_failure_counter.add(1)
                return TriageResponse(
                    verdict="SANDBOX",
                    score=0.5,
                    explanation="Triage mTLS not configured",
                    owasp_ref=None,
                    request_id=request_id,
                )
        except Exception as e:
            logger.warning(
                "Failed to load triage certificates",
                extra={"error": "operation_failed", "request_id": request_id},
            )
            triage_failure_counter.add(1)
            return TriageResponse(
                verdict="SANDBOX",
                score=0.5,
                explanation="Triage mTLS unavailable",
                owasp_ref=None,
                request_id=request_id,
            )

        # Call triage engine with strict 50ms timeout
        async with httpx.AsyncClient(verify=verify_cert) as client:
            response = await client.post(
                triage_url,
                json=payload,
                cert=client_cert,
                timeout=0.05,  # 50ms hard timeout
            )

            # Record latency
            latency_ms = (time.time() - start_time) * 1000
            triage_latency_histogram.record(latency_ms)

            # Validate Content-Type header
            content_type = response.headers.get("content-type", "")
            if "application/json" not in content_type:
                logger.warning(
                    "Triage response invalid content-type",
                    extra={
                        "content_type": content_type,
                        "request_id": request_id,
                    },
                )
                triage_failure_counter.add(1)
                return TriageResponse(
                    verdict="SANDBOX",
                    score=0.5,
                    explanation="Triage response invalid",
                    owasp_ref=None,
                    request_id=request_id,
                )

            # Check HTTP status
            if response.status_code != 200:
                logger.warning(
                    "Triage engine returned non-200 status",
                    extra={
                        "request_id": request_id,
                        "status": response.status_code,
                    },
                )
                triage_failure_counter.add(1)
                return TriageResponse(
                    verdict="SANDBOX",
                    score=0.5,
                    explanation="Triage service error",
                    owasp_ref=None,
                    request_id=request_id,
                )

            # Parse JSON response
            try:
                response_json = response.json()
            except Exception as e:
                logger.warning(
                    "Triage engine returned invalid JSON",
                    extra={
                        "error": "operation_failed",
                        "request_id": request_id,
                    },
                )
                triage_failure_counter.add(1)
                return TriageResponse(
                    verdict="SANDBOX",
                    score=0.5,
                    explanation="Triage response parsing failed",
                    owasp_ref=None,
                    request_id=request_id,
                )

            # Validate response schema strictly
            try:
                triage_response = TriageResponse(**response_json)

                # Validate request_id integrity
                if triage_response.request_id != request_id:
                    logger.warning(
                        "Triage response request_id mismatch",
                        extra={"request_id": request_id},
                    )
                    triage_failure_counter.add(1)
                    return TriageResponse(
                        verdict="SANDBOX",
                        score=0.5,
                        explanation="Triage response invalid",
                        owasp_ref=None,
                        request_id=request_id,
                    )

                return triage_response
            except ValidationError as e:
                logger.warning(
                    "Triage response validation failed",
                    extra={
                        "error": "operation_failed",
                        "request_id": request_id,
                    },
                )
                triage_failure_counter.add(1)
                return TriageResponse(
                    verdict="SANDBOX",
                    score=0.5,
                    explanation="Triage response invalid",
                    owasp_ref=None,
                    request_id=request_id,
                )

    except httpx.TimeoutException:
        logger.warning(
            "Triage engine timeout",
            extra={"request_id": request_id},
        )
        triage_failure_counter.add(1)
        return TriageResponse(
            verdict="SANDBOX",
            score=0.5,
            explanation="Triage timeout (50ms exceeded)",
            owasp_ref=None,
            request_id=request_id,
        )

    except httpx.RequestError as e:
        logger.warning(
            "Triage engine request failed",
            extra={
                "error": "operation_failed",
                "request_id": request_id,
            },
        )
        triage_failure_counter.add(1)
        return TriageResponse(
            verdict="SANDBOX",
            score=0.5,
            explanation="Triage engine unavailable",
            owasp_ref=None,
            request_id=request_id,
        )

    except Exception as e:
        logger.warning(
            "Unexpected error calling triage engine",
            extra={
                "error": "operation_failed",
                "request_id": request_id,
            },
        )
        triage_failure_counter.add(1)
        return TriageResponse(
            verdict="SANDBOX",
            score=0.5,
            explanation="Triage check unavailable",
            owasp_ref=None,
            request_id=request_id,
        )
