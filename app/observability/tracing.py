from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
import os
from dotenv import load_dotenv

load_dotenv()

def setup_tracing():
    resource = Resource.create({
        "service.name": os.getenv("OTEL_SERVICE_NAME", "agentguard")
    })

    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    exporter = OTLPSpanExporter(
        endpoint=os.getenv("OTEL_EXPORTER_ENDPOINT"),
        headers={
            "Authorization": f"Basic {os.getenv('OTEL_EXPORTER_HEADERS')}"
        },
    )

    provider.add_span_processor(BatchSpanProcessor(exporter))

    return trace.get_tracer(__name__)
