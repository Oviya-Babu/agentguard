# AgentGuard-X: Security Mesh for Agentic AI Systems

**Mission-Critical Security Gateway for Autonomous AI Agents**

AgentGuard-X is a production-grade security mesh that sits between autonomous AI agents (LangChain, CrewAI) and all tools they invoke. It intercepts, validates, and enforces security policy on every single tool execution without disrupting legitimate operations.

## What It Does

✓ **Intercepts** all tool calls before execution  
✓ **Validates** agent identity, authorization, and rate limits  
✓ **Detects** prompt injection, exfiltration sequences, and anomalies  
✓ **Sanitizes** tool outputs by redacting PII and removing injection payloads  
✓ **Audits** every decision with full tracing and observability  
✓ **Protects** against LLM01, LLM06, LLM08 attacks (OWASP LLM Top 10)

## Architecture

```
AI Agent
   ↓
[1] Global Rate Limit (Redis Lua)
   ↓
[2] JWT Validation (HS256, Expiry, Claims)
   ↓
[3] Agent Registration (Redis Session)
   ↓
[4] RBAC Enforcement (OPA Policies)
   ↓
[5] Per-Agent Rate Limit (Sliding Window)
   ↓
[6] Sequence Analysis (Attack Patterns)
   ↓
[7] Triage Engine (Behavioral Scoring, 50ms timeout)
   ↓
DECISION: ALLOW / BLOCK / SANDBOX
   ↓
[8] Output Sanitization (Presidio PII + Injection Scanning)
   ↓
Tool Execution & Result to Agent
```

## Quick Start

### 1. Install Dependencies

```bash
make setup
```

This installs all dependencies and sets up pre-commit hooks.

### 2. Start Services

```bash
# Start Redis, OPA, and other dependencies
docker-compose up -d

# Start the gateway (in another terminal)
make run
```

### 3. Test the System

```bash
# Automated test suite (6 scenarios × automated verification)
python scripts/test_scenarios.py
```

Expected output:
```
GATEWAY HEALTH CHECK
Status: HEALTHY
Redis: ✓ UP
OPA: ✓ UP

SCENARIO 1: Clean Request
✓ [Scenario 1: Clean Request] PASSED - Decision: ALLOW

SCENARIO 2: Prompt Injection
✓ [Scenario 2: Prompt Injection] PASSED - Decision: BLOCK

TEST SUMMARY
✓ Passed:  4
✗ Failed:  0
```

### 4. View Logs

```bash
# Real-time security decisions (no PII exposed)
tail -f logs/gateway.log | grep decision

# Check specific agent
tail -f logs/gateway.log | grep "agent_001"
```

## Testing Guide

### Quick Reference

See [QUICK_TEST_REFERENCE.md](QUICK_TEST_REFERENCE.md) for:
- Test matrix (all 10 scenarios)
- Command examples
- Expected outputs
- Success criteria

### Detailed Test Scenarios

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for:
- Complete input/output examples (10 scenarios)
- Step-by-step execution walkthrough
- Trace structure and observability
- Log output examples

### Manual Testing

```bash
# Run individual curl tests
bash scripts/test_manual.sh

# Or use Python test suite
python scripts/test_scenarios.py
```

## Test Scenarios

| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| **Clean Request** | Valid agent, permitted tool | `decision: ALLOW` |
| **Prompt Injection** | Tool input with injection patterns | `decision: BLOCK` |
| **Rate Limited** | 101st request in window | `decision: BLOCK` |
| **Unknown Agent** | Invalid JWT | `HTTP 401` |
| **Forbidden Tool** | Tool outside agent's role | `decision: BLOCK` (RBAC) |
| **PII in Output** | Tool returns SSN/email/credit card | Redacted as `<ENTITY_TYPE_N>` |
| **Exfiltration Sequence** | read_file → compress → http_post | `decision: BLOCK` (step 3) |
| **Redis Down** | Redis unavailable | `decision: SANDBOX` |
| **OPA Down** | Policy engine down | `decision: BLOCK` (deny-all) |
| **Full Tracing** | Valid request with headers | Response includes `trace_id` |

## Response Examples

### Success (HTTP 200)

```json
{
  "decision": "ALLOW",
  "reason": "All checks passed",
  "trace_id": "req-12345-67890"
}
```

### Blocked (HTTP 403)

```json
{
  "decision": "BLOCK",
  "reason": "Access denied by policy",
  "trace_id": "req-22345-67890"
}
```

### Degraded (HTTP 200)

```json
{
  "decision": "SANDBOX",
  "reason": "Infrastructure degraded (redis)",
  "trace_id": "req-33345-67890"
}
```

## Integration with LangChain/CrewAI

```python
from app.callback_handler import SecurityGatewayAsyncCallbackHandler

# Create the security handler
handler = SecurityGatewayAsyncCallbackHandler(
    agent_id="my_agent_001",
    jwt_token="eyJhbGciOiJIUzI1NiJ9..."
)

# Pass it to your agent
agent = initialize_agent(
    tools=tools,
    callbacks=[handler],
    ...
)

# All tool calls are now protected by AgentGuard-X
result = agent.run("What is Python?")
```

## Security Features

### ✓ Fail-Closed Design
- Redis unavailable → SANDBOX (never ALLOW)
- OPA unavailable → deny all (never allow without policy)
- Triage timeout → SANDBOX (never default to ALLOW)
- Any error → BLOCK (never expose agent to failures)

### ✓ Atomic Operations
- Global rate limit: Single Redis Lua call
- Per-agent rate limit: Atomic ZADD + EXPIRE
- Sequence analysis: WATCH+MULTI+EXEC transaction

### ✓ PII Protection
- Presidio detects: SSN, email, phone, credit card, API key, crypto address
- Redaction format: `<ENTITY_TYPE_N>` (no raw values ever logged)
- Log filtering: All log lines scanned before output

### ✓ Attack Detection
- **Prompt Injection**: 3-tier pattern matching (exact, regex, semantic)
- **Excessive Agency**: RBAC + rate limits + sequence detection
- **Data Exfiltration**: Multi-step attack pattern recognition
- **Behavioral Anomalies**: Triage engine scoring (50ms timeout)

## Monitoring & Observability

### Health Checks

```bash
# Gateway health
curl http://localhost:8000/health | jq

# Readiness
curl http://localhost:8000/ready | jq

# Security metrics
curl http://localhost:8000/metrics/security | jq
```

### OpenTelemetry Tracing

Every request produces a complete trace visible in Grafana Tempo:

```
request_pipeline (12.3ms)
├─ step_1_global_rate_limit (0.2ms)
├─ step_2_jwt_validation (1.1ms)
├─ step_3_agent_session_lookup (2.3ms)
├─ step_4_rbac_check (4.5ms)
├─ step_5_per_agent_rate_limit (0.4ms)
├─ step_6_sequence_analysis (0.8ms)
├─ step_7_triage_engine (2.8ms)
└─ output_sanitization (0.3ms)
```

### Logs

All security decisions logged with tracing support:

```
2024-01-01T12:00:00.000Z [INFO] Request pipeline complete
  agent_id: agent_001
  tool_name: web_search
  decision: ALLOW
  latency_ms: 12.3
  trace_id: 4bf92f3577b34da6a3ce929d0e0e4736
```

**Logs never contain:**
- Raw PII values (SSN, email, credit cards)
- Raw JWT tokens
- Raw tool input/output
- Raw injection payloads

Only structured, safe information is logged.

## Performance

| Metric | Target | Status |
|--------|--------|--------|
| Gateway overhead p95 | <10ms | ✓ |
| Full pipeline p95 | <60ms | ✓ |
| Triage call latency | 3-20ms | ✓ |
| Presidio first-call | <50ms | ✓ |
| Global RPS capacity | 10,000 | ✓ |
| Concurrent rate limit atomicity | 50+ concurrent | ✓ |

## Development

### Code Quality

```bash
make lint          # Run ruff linter
make type-check    # Run mypy type checker
make format        # Auto-format code
make test-coverage # Run all tests with coverage
```

### Testing

```bash
# Phase 2 validation tests (6 scenarios × 10 runs each)
make test

# Specific test file
pytest tests/test_phase2_gateway_validation.py -v

# With coverage report
make test-coverage
```

### Pre-commit Hooks

Hooks automatically run on every commit:

```bash
ruff check .          # Linting
mypy . --strict       # Type checking
pytest tests/         # Tests
```

## Configuration

All configuration via environment variables in `.env`:

```bash
# Required
JWT_SECRET_KEY=your-secret-key-here
REDIS_URL=redis://localhost:6379
OPA_URL=http://localhost:8181
TRIAGE_ENGINE_URL=https://localhost:9000

# Optional
LOG_LEVEL=INFO
OTEL_EXPORTER_ENDPOINT=https://otlp.example.com/v1/traces
```

## Project Structure

```
agentguard/
├── app/
│   ├── main.py                      # FastAPI application
│   ├── pipeline.py                  # 7-step validation pipeline
│   ├── callback_handler.py           # LangChain integration
│   ├── output_sanitizer.py           # PII redaction + injection scanning
│   ├── exceptions.py                 # Exception hierarchy
│   ├── triage_client.py              # Triage engine integration
│   ├── settings.py                   # Configuration
│   └── observability/
│       └── otel_setup.py             # OpenTelemetry setup
├── tests/
│   └── test_phase2_gateway_validation.py  # Core validation tests
├── scripts/
│   ├── test_scenarios.py             # Automated test runner
│   ├── test_manual.sh                # Manual curl tests
│   └── quick_test.sh                 # Quick start testing
├── .env                              # Configuration
├── Makefile                          # Automation
├── .pre-commit-config.yaml           # Code quality gates
├── QUICK_TEST_REFERENCE.md           # Quick testing guide
├── TESTING_GUIDE.md                  # Detailed test scenarios
└── README.md                         # This file
```

## Key Files

### Core Implementation
- [app/main.py](app/main.py) - FastAPI application with lifespan management
- [app/pipeline.py](app/pipeline.py) - Complete 7-step validation pipeline
- [app/callback_handler.py](app/callback_handler.py) - LangChain/CrewAI integration
- [app/output_sanitizer.py](app/output_sanitizer.py) - PII redaction + injection scanning

### Configuration & Testing
- [.env](.env) - Environment variables
- [Makefile](Makefile) - Automation targets
- [.pre-commit-config.yaml](.pre-commit-config.yaml) - Code quality gates
- [QUICK_TEST_REFERENCE.md](QUICK_TEST_REFERENCE.md) - Quick testing guide
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Detailed test scenarios

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `connection refused` | Start gateway: `make run` |
| `JWT invalid` | Regenerate token with correct secret |
| `Agent not found` | Register agent in Redis: `redis-cli HSET session:agent_id ...` |
| `OPA unreachable` | Start OPA: `docker-compose up -d opa` |
| `Redis unreachable` | Start Redis: `docker-compose up -d redis` |
| `High latency (>100ms)` | Wait for Presidio pre-loading on first request |

## Success Criteria

Your system is working correctly when:

✓ **Clean requests get ALLOW verdict**
```
Valid agent + permitted tool → decision: ALLOW
```

✓ **Attacks are blocked**
```
Prompt injection → decision: BLOCK
Forbidden tool → decision: BLOCK (RBAC)
Rate limit exceeded → decision: BLOCK
```

✓ **PII is never logged**
```
grep "123-45-6789" logs/gateway.log  # No matches
```

✓ **Fail-closed behavior**
```
Redis down → decision: SANDBOX
OPA down → decision: BLOCK (deny-all)
```

✓ **Performance acceptable**
```
Gateway overhead p95 < 10ms
Full pipeline p95 < 60ms
```

## Next Steps

1. **Run tests:** `python scripts/test_scenarios.py`
2. **Check logs:** `tail -f logs/gateway.log | grep decision`
3. **View traces:** Open Grafana and search by `trace_id`
4. **Integrate:** Use `SecurityGatewayAsyncCallbackHandler` in your agent
5. **Read docs:** See `TESTING_GUIDE.md` and `QUICK_TEST_REFERENCE.md`

## License

Proprietary - AgentGuard-X Security Mesh

## Support

For issues or questions, refer to:
- [QUICK_TEST_REFERENCE.md](QUICK_TEST_REFERENCE.md) - Testing quick reference
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Detailed test scenarios
- [app/main.py](app/main.py) - Source code documentation

---

**AgentGuard-X protects autonomous AI agents from prompt injection, excessive agency, PII leakage, and supply chain attacks.**
