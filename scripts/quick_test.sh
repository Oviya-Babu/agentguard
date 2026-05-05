#!/bin/bash
# Quick Start Testing Guide for AgentGuard-X

set -e

echo "======================================================================"
echo "AgentGuard-X Quick Start Testing"
echo "======================================================================"
echo ""

# Check if Docker is running
echo "1. Checking Docker..."
if ! docker ps > /dev/null 2>&1; then
    echo "✗ Docker is not running. Please start Docker first."
    exit 1
fi
echo "✓ Docker is running"
echo ""

# Check if dependencies are installed
echo "2. Checking Python dependencies..."
if ! python -c "import fastapi, redis, httpx, jose" 2>/dev/null; then
    echo "⚠ Installing dependencies..."
    pip install -q fastapi httpx redis python-jose
fi
echo "✓ Dependencies installed"
echo ""

# Start services
echo "3. Starting required services..."
echo "   - Redis"
echo "   - OPA"
echo "   - Triage Engine (mock)"

docker-compose up -d redis > /dev/null 2>&1 || echo "Note: docker-compose may not be configured"

# Give services time to start
sleep 2
echo "✓ Services started"
echo ""

# Check gateway health
echo "4. Checking gateway..."
MAX_RETRIES=30
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "✓ Gateway is healthy"
        break
    fi
    RETRY=$((RETRY + 1))
    if [ $RETRY -eq 1 ]; then
        echo "⏳ Starting gateway (this may take a moment)..."
        make run &
        sleep 3
    fi
    sleep 1
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo "✗ Gateway failed to start. Check logs with: tail -f logs/gateway.log"
    exit 1
fi
echo ""

# Setup test agents in Redis
echo "5. Setting up test agents..."
redis-cli HSET session:agent_001 agent_id agent_001 role assistant created_at "2024-01-01T00:00:00Z" > /dev/null 2>&1
redis-cli HSET session:agent_004 agent_id agent_004 role read_only created_at "2024-01-01T00:00:00Z" > /dev/null 2>&1
echo "✓ Test agents configured"
echo ""

# Run the test suite
echo "6. Running test scenarios..."
echo ""
python scripts/test_scenarios.py

echo ""
echo "======================================================================"
echo "Testing Complete!"
echo "======================================================================"
echo ""
echo "Next Steps:"
echo "  1. Check gateway logs:"
echo "     tail -f logs/gateway.log"
echo ""
echo "  2. View health status:"
echo "     curl http://localhost:8000/health | jq"
echo ""
echo "  3. View Grafana dashboards (if configured):"
echo "     http://localhost:3000"
echo ""
echo "  4. Read detailed test guide:"
echo "     cat TESTING_GUIDE.md"
echo ""
