# 🚀 QUICK REFERENCE GUIDE

**AgentGuard Zero-Trust AI Gateway**  
**Final Hardening Complete - Production Ready**

---

## 30-SECOND STARTUP

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
export JWT_ISSUER="your-issuer"
export JWT_ALGORITHM="HS256"
export OPA_URL="http://localhost:8181"
export TRIAGE_URL="https://localhost:9999"
export REDIS_URL="redis://localhost:6379"

# 3. Run tests (optional)
python3 -m pytest tests/test_final_hardening.py -v

# 4. Start server
python3 app/main.py
```

---

## BASIC API USAGE

### Make a Request

```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: req-12345" \
  -d '{
    "agent_id": "agent-123",
    "tool_name": "search_web",
    "token": "eyJhbGc...",
    "payload": {}
  }'
```

### Expected Responses

**200 OK** - Request approved
```json
{"status": "approved", "execution_id": "exec-xyz"}
```

**403 Forbidden** - Request blocked (RBAC/rate limit/etc)
```json
{"error": "security_block", "reason": "rate_limit_exceeded"}
```

**429 Too Many Requests** - Rate limit exceeded
```json
{"error": "rate_limit"}
```

**504 Gateway Timeout** - Request took > 30 seconds
```json
{"error": "timeout"}
```

**413 Payload Too Large** - Request body > 1MB
```json
{"error": "payload_too_large"}
```

---

## HEALTH CHECKS

```bash
# Is server running?
curl http://localhost:8000/health
# {"status": "healthy" or "degraded"}

# Is server ready?
curl http://localhost:8000/ready
# {"ready": true}
```

---

## DEBUGGING

### View Logs
```bash
# All logs
python3 app/main.py 2>&1 | grep -i warning

# Security logs only
python3 app/main.py 2>&1 | grep -i "BLOCK\|DENY\|SANDBOX"

# Trace specific request
python3 app/main.py 2>&1 | grep "req-12345"
```

### Check Circuit Breaker Status
```python
# In code: from app.dependency_wrappers import redis_circuit_breaker
redis_circuit_breaker.state  # "CLOSED", "OPEN", or "HALF_OPEN"
```

### Check Degraded Components
```python
# In code: from app.main import app_state
app_state.degraded_components
# {"redis": false, "opa": false, "presidio": false, ...}
```

---

## COMMON CONFIGURATIONS

### Single Instance (Default)
```bash
INSTANCE_MODE=single
# 10K req/s rate limit fallback
# In-memory fallback safe (single process)
```

### Multi-Instance Distributed
```bash
INSTANCE_MODE=distributed
# 100 req/s rate limit fallback (STRICT)
# Requires Redis available
# Circuit breaker active
```

### Strict mTLS
```bash
MTLS_VERIFY_CN_SAN=true
EXPECTED_SERVICE_IDENTITY=agentguard-triage
# Verify certificate CN and SAN match service identity
```

### PII Protection
```bash
HASH_AGENT_ID_IN_LOGS=true
# SHA256(agent_id)[:16] in logs instead of full agent_id
```

### Custom Timeouts
```bash
REQUEST_TIMEOUT_SECONDS=45.0      # Default: 30s
MIN_RESPONSE_TIME=0.020           # Default: 15ms (20ms here)
```

---

## SECURITY CHECKLIST

Before going to production:

- [ ] All 12 hardening patches applied (verify in code)
- [ ] Tests pass: `pytest tests/test_final_hardening.py`
- [ ] Redis running (or acceptable to run degraded)
- [ ] OPA running (or acceptable to deny all requests)
- [ ] Triage service with mTLS certificates
- [ ] JWT issuer/algorithm configured
- [ ] Log aggregation configured (ELK/Datadog)
- [ ] Metrics collection configured (Prometheus)
- [ ] Rate limits tuned for your workload
- [ ] Alerts configured for critical failures

---

## TROUBLESHOOTING QUICK ANSWERS

| Problem | Solution |
|---------|----------|
| "Redis unavailable" | OK - enters degraded mode. Verify Redis running or intended. |
| "OPA timeout" | OK - defaults to BLOCK (safe). Verify OPA running. |
| "Triage timeout" | OK - defaults to SANDBOX (safe). Verify Triage running. |
| HTTP 413 | Request > 1MB. Send smaller payloads. |
| HTTP 504 | Request > 30s. Increase REQUEST_TIMEOUT_SECONDS or optimize. |
| HTTP 400 (missing x-request-id) | Add `X-Request-ID: unique-value` header. |
| HTTP 403 (BLOCK) | JWT invalid, rate limited, or RBAC denied. Check logs. |
| Slow responses | Min response time 15ms. Increase MIN_RESPONSE_TIME if needed. |

---

## ARCHITECTURE MAP

```
Client Request
    ↓
Input Size Limit Middleware (1MB, 80KB headers)
    ↓
Request Timeout Middleware (30s hard limit)
    ↓
Timing Side-Channel Middleware (15ms minimum)
    ↓
Exception Hierarchy (immutable, safe messages)
    ↓
8-Step Pipeline:
  1. Global rate limit (10K/100 RPS fallback)
  2. JWT validation (issuer, audience, algorithm, expiry)
  3. Replay protection (SETNX + 30s TTL)
  4. Session lookup (Redis HGETALL)
  5. RBAC check (OPA 100ms timeout)
  6. Per-agent rate limit (sliding window)
  7. Sequence analysis (WATCH/MULTI atomic)
  8. Triage engine (50ms timeout)
    ↓
Response (APPROVED/BLOCKED/SANDBOX)
```

---

## METRICS TO MONITOR

```python
# OpenTelemetry metrics
triage_failure_total          # Should be < 1%
triage_latency_ms            # p99 < 50ms
request_pipeline_duration_ms # p99 < 200ms

# Component health
/health endpoint              # "healthy" or "degraded"
redis_available              # true/false
opa_available                # true/false
circuit_breaker_state        # "CLOSED", "OPEN", "HALF_OPEN"

# Security
http_403_total               # BLOCK decisions
http_429_total               # Rate limit
replay_attack_total          # Prevented attacks
distributed_mode_without_redis # CRITICAL alert
```

---

## FILE STRUCTURE

```
agentguard/
├── app/
│   ├── main.py                    # FastAPI app, lifespan, middleware
│   ├── exceptions.py              # Security exception hierarchy
│   ├── pipeline.py                # 8-step validation
│   ├── dependency_wrappers.py     # Redis/OPA clients, circuit breaker
│   ├── triage_client.py           # Triage engine client (fail-closed)
│   ├── security_middleware.py     # Input/timeout/timing (NEW)
│   ├── settings.py                # Configuration (NEW)
│   ├── security_utils.py          # mTLS/logging/distributed (NEW)
│   ├── log_filter.py              # PII filtering
│   └── precheck.py                # System validation
├── tests/
│   ├── test_security_pipeline.py  # Original red team tests
│   └── test_final_hardening.py    # Final patch validation (NEW)
├── FINAL_HARDENING_PATCHES.md     # 12 patch documentation
├── DEPLOYMENT_GUIDE.md            # Deployment & troubleshooting
├── SECURITY_HARDENING_REPORT.md   # Phase 2 security fixes
├── EXECUTION_SUMMARY.md           # Phase 2 details
└── requirements.txt               # Dependencies
```

---

## KEY CONCEPTS

**Fail-Closed**: When in doubt, BLOCK or SANDBOX (default safe)  
**Zero-Trust**: No implicit trust in Redis, OPA, Triage  
**Circuit Breaker**: Auto-recovery from cascading failures  
**Degraded Mode**: Accept reduced security when dependencies fail  
**Rate Limit Fallback**: In-memory limits if Redis unavailable  
**Timing Normalization**: Response times constant for BLOCK vs ALLOW  
**Distributed Safety**: Strict 100 RPS limit in distributed mode  
**Immutable Exceptions**: Security context cannot be modified  
**PII Filtering**: No secrets/tokens/PII in logs  

---

## NEXT STEPS

1. **Read**: FINAL_HARDENING_PATCHES.md (complete patch documentation)
2. **Deploy**: Follow DEPLOYMENT_GUIDE.md
3. **Test**: Run `pytest tests/test_final_hardening.py -v`
4. **Monitor**: Set up metrics collection and alerting
5. **Harden**: Enable mTLS, logging hashing, distributed mode as needed

---

## SUPPORT

- **Questions**: See DEPLOYMENT_GUIDE.md troubleshooting section
- **Issues**: Check logs and correlate by X-Request-ID header
- **Security**: Review SECURITY_HARDENING_REPORT.md
- **Tests**: Run `pytest tests/ -v` for full validation

---

**Status**: ✅ Production Ready  
**Last Updated**: May 4, 2026  
**Patches**: 12/12 Complete
