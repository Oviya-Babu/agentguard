"""
Test that excluded paths bypass security middleware.
"""
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from app.security_middleware import (
    InputSizeLimitMiddleware,
    RequestTimeoutMiddleware,
    TimingSidechannelMitigationMiddleware,
    EXCLUDED_PATHS,
)


@pytest.mark.asyncio
async def test_excluded_paths_bypass_middleware():
    """Verify that /docs, /openapi.json, /redoc don't require x-request-id header."""
    
    app = FastAPI()
    
    # Add middleware in order
    app.add_middleware(TimingSidechannelMitigationMiddleware)
    app.add_middleware(RequestTimeoutMiddleware)
    app.add_middleware(InputSizeLimitMiddleware)
    
    # Add test routes
    @app.get("/docs")
    async def docs():
        return {"message": "docs loaded"}
    
    @app.get("/openapi.json")
    async def openapi():
        return {"openapi": "3.0.0"}
    
    @app.get("/redoc")
    async def redoc():
        return {"message": "redoc loaded"}
    
    @app.get("/protected")
    async def protected():
        return {"message": "protected endpoint"}
    
    client = TestClient(app)
    
    # Test that excluded paths work WITHOUT x-request-id header
    print("\n✓ Testing excluded paths (no x-request-id required):")
    
    for path in ["/docs", "/openapi.json", "/redoc"]:
        response = client.get(path)
        print(f"  GET {path}: {response.status_code}")
        assert response.status_code == 200, f"Expected 200, got {response.status_code} for {path}"
    
    # Test that protected paths REQUIRE x-request-id header
    print("\n✓ Testing protected paths (x-request-id required):")
    
    response = client.get("/protected")
    print(f"  GET /protected (no header): {response.status_code}")
    assert response.status_code == 400, f"Expected 400 without header, got {response.status_code}"
    
    response = client.get("/protected", headers={"x-request-id": "test-123"})
    print(f"  GET /protected (with header): {response.status_code}")
    assert response.status_code == 200, f"Expected 200 with header, got {response.status_code}"
    
    print("\n✅ All tests passed!")
    print(f"\nExcluded paths: {EXCLUDED_PATHS}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_excluded_paths_bypass_middleware())
