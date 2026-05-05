"""
Security middleware for the gateway.

Implements:
- Input size limits (body, headers) (PATCH 5)
- Slowloris/connection abuse protection (PATCH 6)
- Request timeout enforcement
- Defensive assertions (PATCH 11)
- Timing randomization with jitter (ENTERPRISE HARDENING)
- Global load shedding (ENTERPRISE HARDENING)
"""

import asyncio
import logging
import time
import random
from typing import Callable, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Constants
MAX_BODY_SIZE = 1024 * 1024  # 1MB
MAX_HEADER_SIZE = 8192  # 8KB per header (reasonable limit)
REQUEST_TIMEOUT = 30.0  # 30 seconds
MIN_RESPONSE_TIME = 0.015  # 15ms minimum (timing side-channel mitigation, PATCH 8)
JITTER_RANGE = 0.005  # 0-5ms jitter range (ENTERPRISE HARDENING)

# Paths excluded from security checks (internal routes)
EXCLUDED_PATHS = {"/docs", "/openapi.json", "/redoc", "/favicon.ico"}


class InputSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforce input size limits (PATCH 5)."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Check request size before processing."""
        # Skip security checks for internal documentation routes
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)
        
        # Check content-length header
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
                if length > MAX_BODY_SIZE:
                    logger.warning(
                        "Request body exceeds size limit",
                        extra={
                            "size": length,
                            "limit": MAX_BODY_SIZE,
                            "request_id": request.headers.get("x-request-id", "unknown"),
                        },
                    )
                    return Response(
                        content="Request body too large",
                        status_code=413,
                    )
            except ValueError:
                pass  # Invalid content-length, proceed

        # Check header size (simple sum of all header sizes)
        total_header_size = sum(
            len(name) + len(value) for name, value in request.headers.items()
        )
        if total_header_size > MAX_HEADER_SIZE * 10:  # Allow multiple large headers
            logger.warning(
                "Request headers exceed size limit",
                extra={
                    "size": total_header_size,
                    "limit": MAX_HEADER_SIZE * 10,
                    "request_id": request.headers.get("x-request-id", "unknown"),
                },
            )
            return Response(
                content="Request headers too large",
                status_code=431,
            )

        # Defensive assertion: check required headers (PATCH 11)
        request_id = request.headers.get("x-request-id")
        if not request_id:
            logger.warning(
                "Request missing required x-request-id header",
                extra={"path": request.url.path},
            )
            return Response(
                content="Missing x-request-id header",
                status_code=400,
            )

        # Proceed with request
        response = await call_next(request)
        return response


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Enforce request timeout (PATCH 6)."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Enforce request timeout."""
        # Skip timeout enforcement for internal documentation routes
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)
        
        try:
            response = await asyncio.wait_for(
                call_next(request),
                timeout=REQUEST_TIMEOUT,
            )
            return response
        except asyncio.TimeoutError:
            logger.warning(
                "Request timeout",
                extra={
                    "timeout": REQUEST_TIMEOUT,
                    "request_id": request.headers.get("x-request-id", "unknown"),
                },
            )
            return Response(
                content="Request timeout",
                status_code=504,
            )


class TimingSidechannelMitigationMiddleware(BaseHTTPMiddleware):
    """Normalize response times to prevent timing side-channels (PATCH 8)."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add minimum response time padding with randomization (jitter)."""
        # Skip timing mitigation for internal documentation routes
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)
        
        start_time = time.time()

        # Process request
        response = await call_next(request)

        # Check elapsed time
        elapsed = time.time() - start_time

        # If too fast, pad with sleep + jitter (prevents timing attacks)
        if elapsed < MIN_RESPONSE_TIME:
            # Add jitter to avoid consistent timing signature
            jitter = random.uniform(0, JITTER_RANGE)
            delay = MIN_RESPONSE_TIME - elapsed + jitter
            await asyncio.sleep(delay)

        return response


class GlobalLoadSheddingMiddleware(BaseHTTPMiddleware):
    """
    Protect against resource exhaustion via load shedding.
    
    Rejects requests early if system is overloaded.
    """
    
    def __init__(self, app, load_shedder=None):
        super().__init__(app)
        # Lazy import to avoid circular dependency
        self.load_shedder = load_shedder
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Check if system can accept request."""
        # Skip load shedding checks for internal documentation routes
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)
        
        # Try to acquire a slot
        if self.load_shedder:
            if not await self.load_shedder.acquire_slot():
                logger.warning(
                    "Request rejected: system overloaded",
                    extra={
                        "request_id": request.headers.get("x-request-id", "unknown"),
                    },
                )
                return Response(
                    content="Service unavailable (overloaded)",
                    status_code=503,
                )
        
        try:
            # Process request
            response = await call_next(request)
            return response
        finally:
            # Always release slot
            if self.load_shedder:
                await self.load_shedder.release_slot()
