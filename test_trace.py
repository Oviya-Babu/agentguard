from app.observability.tracing import setup_tracing

tracer = setup_tracing()

with tracer.start_as_current_span("agentguard-test-span"):
    print("Tracing working")
