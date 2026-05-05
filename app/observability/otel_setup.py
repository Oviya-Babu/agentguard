"""
OpenTelemetry initialization module.

This module sets up OpenTelemetry tracing and instrumentation.
It MUST be imported before any other application code to ensure
proper instrumentation of all components.
"""

import os
from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor

# Load environment variables
load_dotenv()


def setup_opentelemetry() -> None:
    """
    Initialize OpenTelemetry tracing and instrumentation.

    This function:
    - Creates a tracer provider with resource attributes
    - Configures OTLP exporter (or no-op if not available)
    - Instruments FastAPI, httpx, and Redis
    - Sets up batch span processor

    Must be called during application startup before any other initialization.
    Failures are logged but do not crash the application.
    """
    try:
        # Create resource with service metadata
        resource = Resource.create({
            "service.name": os.getenv("OTEL_SERVICE_NAME", "agentguard"),
            "service.version": os.getenv("OTEL_SERVICE_VERSION", "0.1.0"),
        })

        # Create tracer provider
        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)

        # Attempt to configure OTLP exporter if endpoint is provided
        otel_endpoint = os.getenv("OTEL_EXPORTER_ENDPOINT")
        if otel_endpoint:
            try:
                exporter = OTLPSpanExporter(
                    endpoint=otel_endpoint,
                    headers={
                        "Authorization": f"Basic {os.getenv('OTEL_EXPORTER_HEADERS', '')}",
                    } if os.getenv("OTEL_EXPORTER_HEADERS") else {},
                )
                provider.add_span_processor(BatchSpanProcessor(exporter))
            except Exception as e:
                # If OTLP setup fails, continue without remote export
                pass

        # Instrument key libraries
        FastAPIInstrumentor.instrument()
        HTTPXClientInstrumentor.instrument()
        RedisInstrumentor.instrument()

    except Exception as e:
        # OpenTelemetry setup failures should not crash the application
        pass


# Execute setup immediately on import
setup_opentelemetry()
