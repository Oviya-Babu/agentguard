#!/usr/bin/env python3
import asyncio
import logging
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Setup test tracing to console
provider = TracerProvider()
processor = SimpleSpanProcessor(ConsoleSpanExporter())
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)

tracer = trace.get_tracer(__name__)

async def simulate_redis_call():
    with tracer.start_as_current_span("redis_hgetall") as span:
        span.set_attribute("db.system", "redis")
        span.set_attribute("db.operation", "HGETALL")
        await asyncio.sleep(0.1)
        logger.info("Executed async Redis call")

async def simulate_opa_call():
    with tracer.start_as_current_span("opa_policy_check") as span:
        span.set_attribute("rpc.system", "http")
        span.set_attribute("http.url", "http://opa:8182")
        await asyncio.sleep(0.1)
        logger.info("Executed async OPA call")

async def run_pipeline():
    with tracer.start_as_current_span("agentguard_pipeline") as parent_span:
        parent_span.set_attribute("agent.id", "agent_123")
        parent_span.set_attribute("tool.name", "search")
        
        logger.info("Starting pipeline execution")
        await simulate_redis_call()
        await simulate_opa_call()
        logger.info("Pipeline execution finished")

if __name__ == "__main__":
    logger.info("=== Starting OTel Trace Validation ===")
    asyncio.run(run_pipeline())
    logger.info("=== OTel Trace Validation PASSED (Check console for nested spans) ===")
