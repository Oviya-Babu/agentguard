import app.observability.otel_setup  # must execute before anything else

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, Any, Dict

import httpx
import redis.asyncio as redis
import yaml
from fastapi import FastAPI, Header
from pydantic import BaseModel
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

from app.log_filter import get_pii_filter
from app import precheck
from app.hardening_advanced import (
    failure_rate_guard,
    global_load_shedder,
    event_loop_pressure_guard,
    distributed_consistency_guard,
)
from app.behavior_guard import behavior_guard
from app.chaos_testing import chaos_injector
from app.mtls_advanced import advanced_mtls_validator

# Configure root logger with PII filtering (prevent duplicate handlers)
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
root_logger = logging.getLogger()
root_logger.addFilter(get_pii_filter())

logger = logging.getLogger(__name__)


# ============================================================================
# GLOBAL APPLICATION STATE (SINGLE SOURCE OF TRUTH)
# ============================================================================


class AppState:
    """
    Centralized application state container.

    This class holds all global references and degradation flags.
    It is the single source of truth for application state.

    Attributes:
        redis: Redis async client connection (or None if unavailable)
        presidio_analyzer: Presidio AnalyzerEngine instance (singleton)
        presidio_anonymizer: Presidio AnonymizerEngine instance (singleton)
        degraded_components: Dict tracking which components are unavailable
        sequence_rules: Parsed sequence rules configuration
        injection_patterns: Parsed injection patterns configuration
    """

    def __init__(self) -> None:
        """Initialize application state with all defaults."""
        self.redis: Optional[redis.Redis] = None
        self.presidio_analyzer: Optional[AnalyzerEngine] = None
        self.presidio_anonymizer: Optional[AnonymizerEngine] = None
        self.degraded_components: Dict[str, bool] = {
            "redis": False,
            "opa": False,
        }
        self.sequence_rules: Optional[Any] = None
        self.injection_patterns: Optional[Any] = None


# Single global instance
app_state = AppState()


# ============================================================================
# INITIALIZATION FUNCTIONS
# ============================================================================


async def init_redis() -> None:
    """
    Initialize Redis async connection pool.

    Creates a connection pool with resilience settings (timeouts, retries).
    Failure is graceful: logs warning and marks component as degraded.

    Redis settings:
    - max_connections: 50
    - socket_timeout: 0.2 seconds
    - socket_connect_timeout: 0.5 seconds
    - retry_on_timeout: True
    """
    try:
        logger.info("Initializing Redis connection pool...")

        app_state.redis = redis.Redis(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            db=int(os.getenv("REDIS_DB", 0)),
            max_connections=50,
            socket_timeout=0.2,
            socket_connect_timeout=0.5,
            retry_on_timeout=True,
            decode_responses=True,
        )

        # Test connection with ping (with timeout protection)
        await asyncio.wait_for(app_state.redis.ping(), timeout=1.0)
        logger.info("✓ Redis initialized successfully")

    except Exception as e:
        logger.warning(
            "Redis initialization failed",
            extra={"error": type(e).__name__}
        )
        app_state.degraded_components["redis"] = True
        app_state.redis = None


async def init_opa_health_check() -> None:
    """
    Perform OPA policy engine health check.

    Uses httpx.AsyncClient to probe OPA health endpoint.
    Failure is graceful: logs warning and marks component as degraded.

    Important: OPA failure triggers "deny-all" behavior downstream.
    """
    try:
        logger.info("Checking OPA policy engine health...")

        opa_url = os.getenv("OPA_URL")
        if not opa_url:
            logger.warning(
                "OPA_URL not set — running in degraded mode"
            )
            app_state.degraded_components["opa"] = True
            return

        timeout = float(os.getenv("OPA_HEALTH_TIMEOUT", 2.0))

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{opa_url}/health")
            response.raise_for_status()

        logger.info("✓ OPA health check passed")

    except Exception as e:
        logger.warning(
            "OPA health check failed",
            extra={"error": type(e).__name__}
        )
        app_state.degraded_components["opa"] = True


def init_presidio() -> None:
    """
    Initialize Presidio analyzer and anonymizer (singletons).

    Performs a dummy analyze call to trigger model loading.
    Measures and logs initialization time.

    Failure is logged but does not crash the application.
    """
    try:
        logger.info("Initializing Presidio engines...")
        start_time = time.time()

        # Create singleton instances
        app_state.presidio_analyzer = AnalyzerEngine()
        app_state.presidio_anonymizer = AnonymizerEngine()

        # Trigger model loading with dummy call
        app_state.presidio_analyzer.analyze(
            text="test@example.com",
            language="en",
        )

        duration = time.time() - start_time
        logger.info(
            "✓ Presidio engines initialized (%.2f seconds)",
            duration,
        )

    except Exception as e:
        logger.error(
            "Presidio initialization failed",
            extra={"error": type(e).__name__}
        )
        app_state.presidio_analyzer = None
        app_state.presidio_anonymizer = None


def load_yaml_config(file_path: str, config_name: str) -> Optional[Any]:
    """
    Safely load YAML configuration file.

    Uses yaml.safe_load for security. Missing or invalid files
    log a warning but do not crash the application.

    Args:
        file_path: Path to YAML file
        config_name: Human-readable name for logging

    Returns:
        Parsed YAML content (dict or list) or None if failed
    """
    try:
        path = Path(file_path)

        if not path.exists():
            logger.warning(
                "Configuration file not found",
                extra={"config": config_name}
            )
            return None

        with open(path, "r") as f:
            content = yaml.safe_load(f)

        # Validate basic structure
        if content is None or isinstance(content, (dict, list)):
            logger.info("✓ Loaded configuration: %s", config_name)
            return content

        logger.warning(
            "Configuration %s has invalid structure: expected dict or list",
            config_name,
        )
        return None

    except Exception as e:
        logger.warning(
            "Failed to load configuration",
            extra={"config": config_name, "error": type(e).__name__}
        )
        return None


def init_configs() -> None:
    """
    Load all YAML configurations.

    Loads sequence_rules.yaml and injection_patterns.yaml.
    Failures are non-blocking and set to empty defaults.
    """
    logger.info("Loading configuration files...")

    # Load sequence rules
    app_state.sequence_rules = load_yaml_config(
        "sequence_rules.yaml",
        "sequence_rules",
    ) or {}

    # Load injection patterns
    app_state.injection_patterns = load_yaml_config(
        "injection_patterns.yaml",
        "injection_patterns",
    ) or {}

    logger.info("✓ Configuration loading complete")


def load_opa_policies() -> None:
    """
    Load OPA policy files from policies/ directory.

    Policies are discovered from the policies/ folder.
    Empty policy set logs a warning (deny-all is enforced downstream).

    Policy files should be in Rego format (.rego).
    """
    try:
        logger.info("Scanning for OPA policy files...")

        policies_dir = Path("policies")
        if not policies_dir.exists():
            logger.warning(
                "OPA policies directory not found",
                extra={"path": str(policies_dir)}
            )
            return

        policy_files = list(policies_dir.glob("*.rego"))

        if not policy_files:
            logger.warning(
                "No OPA policy files found (deny-all will be enforced)"
            )
            return

        logger.info("✓ Found %d OPA policy file(s)", len(policy_files))

        for policy_file in policy_files:
            logger.info("  - %s", policy_file.name)

    except Exception as e:
        logger.warning(
            "Error scanning OPA policies",
            extra={"error": type(e).__name__}
        )


def run_system_precheck() -> None:
    """
    Execute system precheck validation.

    Runs the precheck module which validates:
    - Python version
    - Required modules
    - Environment configuration

    Results are logged but do not block startup.
    """
    try:
        logger.info("Running system precheck...")
        results = precheck.run_precheck()

        for check_name, check_result in results.get("checks", {}).items():
            status = "✓" if check_result else "✗"
            logger.info("  %s %s", status, check_name)

    except Exception as e:
        logger.warning(
            "System precheck execution failed",
            extra={"error": type(e).__name__}
        )


# ============================================================================
# FASTAPI LIFESPAN HANDLER (ASYNC CONTEXT MANAGER)
# ============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Handles all startup initialization BEFORE yield and optional
    cleanup AFTER yield.

    Initialization order is critical and non-negotiable:
    1. Observability (already initialized at import)
    2. Logging with PII filter (already configured)
    3. HTTP clients (httpx, OPA client)
    4. Redis (async, fail-safe)
    5. OPA health check (async, fail-safe)
    6. Presidio engines (blocking, fail-safe)
    7. YAML configurations (safe loading)
    8. OPA policies (scanning)
    9. System precheck (validation)

    All failures are caught and logged without crashing the application.
    """
    logger.info("=" * 70)
    logger.info("AGENTGUARD GATEWAY STARTUP")
    logger.info("=" * 70)

    try:
        # Initialize Redis (async)
        await init_redis()

        # Check OPA health (async)
        await init_opa_health_check()

        # Initialize Presidio (non-blocking via thread pool)
        await asyncio.to_thread(init_presidio)

        # Load configurations
        init_configs()

        # Load OPA policies
        load_opa_policies()

        # Run system precheck
        run_system_precheck()

        # Start event loop pressure guard monitoring task
        asyncio.create_task(event_loop_pressure_guard.monitor_task())

        # Log initialization status
        logger.info("-" * 70)
        logger.info("DEGRADED COMPONENTS:")
        for component, is_degraded in app_state.degraded_components.items():
            status = "DEGRADED" if is_degraded else "HEALTHY"
            logger.info("  - %s: %s", component, status)
        logger.info("-" * 70)

        # Initialize HTTP clients (CRITICAL: must be before yield)
        from app.dependency_wrappers import init_clients
        await init_clients()

        # All initialization complete
        logger.info("✓ Gateway initialization complete")
        logger.info("=" * 70)

    except Exception as e:
        # Should not happen due to nested try/except, but log anyway
        logger.error(
            "Unexpected error during startup",
            extra={"error": type(e).__name__}
        )

    # Yield control to FastAPI
    yield

    # Cleanup on shutdown
    logger.info("Gateway shutdown initiated")

    # Close HTTP clients FIRST (PATCH 1)
    try:
        from app.dependency_wrappers import close_clients
        await close_clients()
    except Exception as e:
        logger.warning(
            "Error closing HTTP clients",
            extra={"error": "operation_failed"}
        )

    # Close Redis connection pool SECOND
    try:
        if app_state.redis is not None:
            await app_state.redis.connection_pool.disconnect()
            logger.info("✓ Redis connection pool closed")
    except Exception as e:
        logger.warning(
            "Error closing Redis",
            extra={"error": "operation_failed"}
        )


# ============================================================================
# FASTAPI APPLICATION CREATION
# ============================================================================


class ExecuteRequest(BaseModel):
    """
    Request model for /execute endpoint.

    Attributes:
        agent_id: Unique identifier of the requesting agent
        tool_name: Name of the tool being requested
        token: JWT token or authentication token
        payload: Optional additional request payload
    """

    agent_id: str
    tool_name: str
    token: str
    payload: Optional[Dict[str, Any]] = {}


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        None

    Returns:
        Configured FastAPI application instance with lifespan handler
    """
    app = FastAPI(
        title="AgentGuard Gateway",
        description="Zero-trust security gateway for AI agents",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Add security middleware (PATCH 5, 6, 8)
    from app.security_middleware import (
        InputSizeLimitMiddleware,
        RequestTimeoutMiddleware,
        TimingSidechannelMitigationMiddleware,
        GlobalLoadSheddingMiddleware,
    )

    # Add in reverse order (they wrap each other)
    app.add_middleware(TimingSidechannelMitigationMiddleware)  # Outermost
    app.add_middleware(RequestTimeoutMiddleware)
    app.add_middleware(GlobalLoadSheddingMiddleware, load_shedder=global_load_shedder)
    app.add_middleware(InputSizeLimitMiddleware)  # Innermost

    # Health check endpoint
    @app.get("/health")
    async def health_check() -> Dict[str, Any]:
        """
        Health check endpoint.

        Returns:
            Status of gateway and component health
        """
        status = "degraded" if any(app_state.degraded_components.values()) else "healthy"
        return {
            "status": status,
            "redis": not app_state.degraded_components["redis"],
            "opa": not app_state.degraded_components["opa"],
        }

    # Ready check endpoint
    @app.get("/ready")
    async def ready_check() -> Dict[str, Any]:
        """
        Readiness check endpoint.

        Returns:
            True if gateway is ready to accept requests (always true in degraded mode)
        """
        # Gateway is ALWAYS ready (degraded mode is supported)
        # Component status is for monitoring only
        return {
            "ready": True,
            "components": {
                "redis": not app_state.degraded_components["redis"],
                "opa": not app_state.degraded_components["opa"],
            }
        }

    # Security metrics endpoint (ENTERPRISE HARDENING)
    @app.get("/metrics/security")
    async def security_metrics() -> Dict[str, Any]:
        """
        Security metrics endpoint.

        Returns:
            Security-related metrics for monitoring and alerting
        """
        failure_metrics = await failure_rate_guard.get_metrics()
        load_metrics = await global_load_shedder.get_metrics()
        pressure_metrics = await event_loop_pressure_guard.get_metrics()
        consistency_metrics = await distributed_consistency_guard.get_metrics()
        behavior_metrics = await behavior_guard.get_metrics()
        chaos_metrics = chaos_injector.get_metrics()

        return {
            "failure_rate_guard": failure_metrics,
            "global_load_shedder": load_metrics,
            "event_loop_pressure": pressure_metrics,
            "distributed_consistency": consistency_metrics,
            "behavior_guard": behavior_metrics,
            "chaos_testing": chaos_metrics,
        }

    # Test endpoint (health check for routing verification)
    @app.get("/test")
    async def test() -> Dict[str, str]:
        """
        Test endpoint for verifying application routing.

        Returns:
            Simple status message
        """
        return {"status": "working"}

    # Execute endpoint (Phase 2 pipeline integration)
    @app.post("/execute")
    async def execute(
        request: ExecuteRequest,
        x_request_id: str = Header(...)
    ) -> Dict[str, Any]:
        """
        Execute request through Phase 2 security pipeline.

        Validates and processes the request through the complete
        zero-trust security pipeline, returning an access decision.

        Args:
            request: ExecuteRequest with agent_id, tool_name, token, payload
            x_request_id: Unique request ID from header (required by middleware)

        Returns:
            Decision result with decision (ALLOW/BLOCK/SANDBOX) and reason
        """
        from app.pipeline import RequestContext, process_request

        try:
            # Create request context for pipeline
            context = RequestContext(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                jwt_payload={"token": request.token},
                request_id=x_request_id,
                metadata=request.payload or {}
            )

            # Process through Phase 2 pipeline
            result = await process_request(context)

            return {
                "decision": result.decision,
                "reason": result.reason,
                "trace_id": result.trace_id
            }

        except Exception as e:
            logger.error(
                "Error processing request",
                extra={"error": type(e).__name__, "request_id": x_request_id}
            )
            # Return BLOCK on any unexpected error (fail-closed)
            return {
                "decision": "BLOCK",
                "reason": "internal_error",
                "trace_id": x_request_id
            }

    return app


# Create the application instance
app = create_app()


# ============================================================================
# ENTRY POINT
# ============================================================================


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENV", "production") == "development",
        log_config=None,  # Use our logging configuration
        limit_concurrency=1000,  # Max concurrent requests (PATCH 6)
        timeout_keep_alive=30,  # Slowloris protection (PATCH 6)
        timeout_notify=30,  # Graceful shutdown timeout
    )
