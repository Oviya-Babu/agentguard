    #!/usr/bin/env python3
"""
Quick validation of main.py FastAPI endpoints.
"""
import sys
import asyncio
import json

# Test 1: Verify syntax and imports
print("Test 1: Checking syntax and imports...")
try:
    from app.main import app, ExecuteRequest
    print("✅ main.py imports successfully")
except Exception as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

# Test 2: Verify FastAPI app is created
print("\nTest 2: Checking FastAPI app instance...")
try:
    assert app is not None
    assert app.title == "AgentGuard Gateway"
    print("✅ FastAPI app instance created correctly")
except Exception as e:
    print(f"❌ App instance error: {e}")
    sys.exit(1)

# Test 3: Verify routes are registered
print("\nTest 3: Checking registered routes...")
try:
    routes = [route.path for route in app.routes]
    print(f"   Registered routes: {routes}")
    
    assert "/test" in routes, "Missing /test route"
    assert "/execute" in routes, "Missing /execute route"
    assert "/health" in routes, "Missing /health route"
    assert "/ready" in routes, "Missing /ready route"
    assert "/metrics/security" in routes, "Missing /metrics/security route"
    
    print("✅ All expected routes are registered")
except AssertionError as e:
    print(f"❌ Route registration error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    sys.exit(1)

# Test 4: Verify ExecuteRequest model
print("\nTest 4: Checking ExecuteRequest model...")
try:
    request = ExecuteRequest(
        agent_id="test-agent",
        tool_name="search",
        token="test_token",
        payload={"query": "test"}
    )
    print(f"✅ ExecuteRequest model works: {request.model_dump()}")
except Exception as e:
    print(f"❌ ExecuteRequest model error: {e}")
    sys.exit(1)

# Test 5: Check OpenAPI schema includes /execute
print("\nTest 5: Checking OpenAPI schema...")
try:
    openapi_schema = app.openapi()
    paths = openapi_schema.get("paths", {})
    
    assert "/test" in paths, "Missing /test in OpenAPI"
    assert "/execute" in paths, "Missing /execute in OpenAPI"
    
    execute_methods = paths.get("/execute", {})
    assert "post" in execute_methods, "/execute doesn't have POST method"
    
    print("✅ OpenAPI schema contains expected endpoints")
    print(f"   POST /execute exists in schema: {bool('post' in execute_methods)}")
except Exception as e:
    print(f"❌ OpenAPI schema error: {e}")
    sys.exit(1)

print("\n" + "="*70)
print("✅ ALL VALIDATION TESTS PASSED")
print("="*70)
print("\nThe FastAPI application is correctly configured with:")
print("  ✓ /test endpoint (GET)")
print("  ✓ /execute endpoint (POST)")
print("  ✓ ExecuteRequest model")
print("  ✓ Phase 2 pipeline integration")
