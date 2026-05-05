# 🚀 DEPLOYMENT & TROUBLESHOOTING GUIDE

**Status**: Production Ready  
**Version**: Phase 2 Complete + Final Hardening (12/12 Patches)  
**Date**: May 4, 2026  

---

## PRE-DEPLOYMENT CHECKLIST

### Infrastructure
- [ ] Redis 6.0+ available (or degraded mode acceptable)
- [ ] OPA policy engine running (or degraded mode acceptable)
- [ ] Triage service with mTLS certificates
- [ ] OpenTelemetry collector running (or logs to stdout)
- [ ] Presidio models downloaded (or skip PII redaction)

### Configuration
- [ ] JWT_ISSUER set
- [ ] JWT_ALGORITHM set (HS256 or RS256)
- [ ] OPA_URL set
- [ ] TRIAGE_URL set (with mTLS)
- [ ] TRIAGE_CERT_DIR set with CA, client cert/key
- [ ] REDIS_URL set (or leave default localhost:6379)

### Optional (Hardening)
- [ ] INSTANCE_MODE set if distributed (default: single)
- [ ] MTLS_VERIFY_CN_SAN=true if strict mTLS
- [ ] EXPECTED_SERVICE_IDENTITY set if strict mTLS
- [ ] REQUEST_TIMEOUT_SECONDS tuned if needed (default: 30s)
- [ ] HASH_AGENT_ID_IN_LOGS=true for PII protection

---

## DEPLOYMENT STEPS

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Initialize Config Files
```bash
# Create sequence_rules.yaml (empty is OK)
echo "{}" > sequence_rules.yaml

# Create injection_patterns.yaml (empty is OK)
echo "{}" > injection_patterns.yaml

# Create policies/ directory
mkdir -p policies

# Add OPA policies (optional, deny-all is enforced if empty)
```

### 3. Set Environment Variables
```bash
export JWT_ISSUER="your-issuer"
export JWT_ALGORITHM="HS256"
export OPA_URL="http://opa-server:8181"
export TRIAGE_URL="https://triage-server:9999"
export TRIAGE_CERT_DIR="/path/to/certs"
export REDIS_URL="redis://redis-server:6379"
export INSTANCE_MODE="single"  # or "distributed"
export LOG_LEVEL="INFO"
```

### 4. Verify System Precheck
```bash
python3 -c "from app import precheck; precheck.run_system_precheck()"
```

### 5. Run Tests
```bash
# Run final hardening tests
python3 -m pytest tests/test_final_hardening.py -v

# Run security pipeline tests (original)
python3 -m pytest tests/test_security_pipeline.py -v
```

### 6. Start Application
```bash
# Development
python3 app/main.py

# Production (with gunicorn)
gunicorn -w 4 -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 60 \
  --access-logfile - \
  app.main:app
```

### 7. Health Checks
```bash
# Check health
curl http://localhost:8000/health

# Check readiness
curl http://localhost:8000/ready

# Expected responses:
# {"status": "healthy" or "degraded", "redis": true/false, "opa": true/false}
# {"ready": true, "components": {"redis": true/false, "opa": true/false}}
```

---

## COMMON ISSUES & TROUBLESHOOTING

### Issue 1: "Redis unavailable" at startup

**Symptom**: `WARNING: Redis connection failed` in logs  
**Root Cause**: Redis not reachable  

**Solutions**:
1. Verify Redis is running: `redis-cli ping`
2. Check REDIS_URL: `echo $REDIS_URL`
3. Check firewall/network: `nc -zv redis-host 6379`
4. **Graceful Fallback**: Gateway enters degraded mode
   - In-memory rate limiter activated (10K RPS default)
   - All requests continue (SANDBOX/BLOCK based on other checks)

**Action**: Start with `INSTANCE_MODE=single` if testing. Production requires Redis + `INSTANCE_MODE=distributed` enforcement.

---

### Issue 2: "OPA policy check timeout" in logs

**Symptom**: `WARNING: OPA policy check timeout` after 100ms  
**Root Cause**: OPA server slow or unreachable

**Solutions**:
1. Check OPA health: `curl http://opa-server:8181/health`
2. Check OPA policy: `curl http://opa-server:8181/v1/data/agentguard/allow`
3. Check network latency: `time curl http://opa-server:8181/health`
4. **Fail-Closed Behavior**: Request is BLOCKED (safe default)

**Action**: Set up OPA or accept BLOCK for all requests.

---

### Issue 3: "Triage timeout" messages

**Symptom**: `Triage timeout (50ms exceeded)` in logs  
**Root Cause**: Triage service slow or network latency

**Solutions**:
1. Check Triage health: `curl -k https://triage-server:9999/health`
2. Measure latency: `time curl -k https://triage-server:9999/check`
3. **Fail-Closed Behavior**: Request returns SANDBOX (safe default)

**Action**: This is expected behavior. Triage fast-fails to SANDBOX.

---

### Issue 4: Circuit breaker stuck OPEN

**Symptom**: All Redis/Triage calls fail for 10+ seconds  
**Root Cause**: Service recovered but circuit still open (cooldown period)

**Solutions**:
1. Wait 10 seconds (default recovery timeout)
2. Check logs: `grep "Circuit breaker HALF_OPEN"` - recovery attempt
3. Check logs: `grep "Circuit breaker CLOSED"` - recovery successful

**Action**: No action needed. System auto-recovers.

---

### Issue 5: "distributed_mode_without_redis" warning

**Symptom**: Strict SANDBOX behavior even though Redis eventually comes back  
**Root Cause**: Deployed in distributed mode without Redis available

**Solutions**:
1. Start Redis before gateway: `redis-server`
2. Change to single mode: `INSTANCE_MODE=single`
3. Check Redis: `redis-cli ping` should return PONG

**Action**: In production, always ensure Redis for distributed mode.

---

### Issue 6: Request rejected with HTTP 413

**Symptom**: `Request body too large` (HTTP 413)  
**Root Cause**: Request body > 1MB

**Solutions**:
1. Check payload size: large batch of agent requests
2. Split into smaller batches
3. Increase limit: `app/security_middleware.py` MAX_BODY_SIZE (not recommended)

**Action**: Send smaller payloads.

---

### Issue 7: Request rejected with HTTP 504

**Symptom**: `Request timeout` (HTTP 504)  
**Root Cause**: Request processing > 30 seconds

**Solutions**:
1. Check slow operations in logs
2. Check Redis performance
3. Check OPA response time
4. Increase timeout: `REQUEST_TIMEOUT_SECONDS` env var (default: 30s)

**Action**: Optimize slow operations or increase timeout if acceptable.

---

### Issue 8: "Missing x-request-id header"

**Symptom**: `HTTP 400: Missing x-request-id header`  
**Root Cause**: Client not sending x-request-id

**Solutions**:
1. Client must include header: `X-Request-ID: unique-uuid`
2. Example: `curl -H "X-Request-ID: req-123" http://gateway/...`

**Action**: Update client to include header.

---

### Issue 9: Distributed mode fallback rate limit too low

**Symptom**: Requests throttled at 100 req/s in distributed mode  
**Root Cause**: Safety feature prevents cascade

**Solutions**:
1. This is intended behavior (safety guard)
2. Ensure Redis is always available in distributed
3. Consider deploying as single mode if no Redis

**Action**: Start Redis or switch to single mode.

---

### Issue 10: Logs show "operation_failed" everywhere

**Symptom**: Generic error messages in logs  
**Root Cause**: Security feature (no exception type leakage)

**Solutions**:
1. Check structured log fields (extra={...}) for details
2. Use log aggregation to correlate request_id
3. Check system metrics (Redis, OPA availability)

**Action**: Normal behavior. Use ELK/Datadog to correlate logs by request_id.

---

## MONITORING & ALERTING

### Key Metrics to Track

```
1. HTTP Status Codes
   - 200: OK
   - 403: BLOCK (security decision)
   - 429: RATE_LIMIT (exceeded)
   - 504: TIMEOUT (slow request)
   - 413: TOO_LARGE (payload)

2. OpenTelemetry Metrics
   - triage_failure_total: Should be < 1% of triage calls
   - triage_latency_ms: p99 should be < 50ms
   - request_pipeline_duration_ms: Track latency

3. Component Health
   - redis: degraded_components["redis"] = true → alert
   - opa: degraded_components["opa"] = true → alert
   - circuit_breaker state = "open" → alert after 30s

4. Security Logs
   - "distributed_mode_without_redis" → alert (critical)
   - "Circuit breaker OPEN" → alert (service issue)
   - "mTLS certificate identity mismatch" → alert (security)
```

### Alerting Rules

```yaml
alert: RedisUnavailable
  for: 5m
  expr: degraded_components["redis"] == true
  action: page on-call

alert: OPAUnavailable
  for: 5m
  expr: degraded_components["opa"] == true
  action: page on-call

alert: CircuitBreakerOpen
  for: 30s
  expr: circuit_breaker_state == "open"
  action: investigate

alert: DistributedModeNoRedis
  for: 1m
  expr: logs contain "distributed_mode_without_redis"
  action: page on-call (critical)

alert: HighTriageFailureRate
  for: 5m
  expr: triage_failure_total > 5% of triage_calls
  action: page on-call

alert: mTLSMismatch
  for: 1m
  expr: logs contain "mTLS certificate identity mismatch"
  action: investigate (security)
```

---

## PERFORMANCE TUNING

### Timeouts
```python
# Default: 30 seconds per request
REQUEST_TIMEOUT_SECONDS=30.0

# Tune based on:
# - Redis latency (typically <10ms)
# - OPA latency (typically <100ms)
# - Triage latency (typical <50ms)
# - Total: usually <200ms if all services healthy
```

### Rate Limiting
```python
# Single mode: 10K req/s fallback
# Distributed mode: 100 req/s fallback (strict)
# Tune based on:
# - Expected RPS
# - Redis performance
# - Agent concurrency
```

### Connection Limits
```python
# Default: 1000 concurrent connections
limit_concurrency=1000

# Tune based on:
# - Number of agents
# - Request duration
# - Server memory/CPU
```

### Timing Side-Channel
```python
# Default: 15ms minimum response time
MIN_RESPONSE_TIME=0.015

# Lower = faster response (less safe from timing attacks)
# Higher = slower response (more safe but adds latency)
```

---

## PRODUCTION HARDENING CHECKLIST

- [ ] All 12 hardening patches applied
- [ ] TLS/mTLS certificates generated and deployed
- [ ] Log aggregation configured (ELK, Datadog, etc.)
- [ ] Metrics collection configured (Prometheus, etc.)
- [ ] Alerting rules deployed
- [ ] Rate limiting configured appropriately
- [ ] Backup Redis/OPA cluster ready
- [ ] Disaster recovery plan in place
- [ ] Security audit completed
- [ ] Load testing passed
- [ ] Graceful degradation tested

---

## ROLLBACK PLAN

If issues occur:

1. **Immediate (< 5 min)**:
   - Revert to previous version
   - Or disable hardening patches (remove middleware)

2. **Short-term (5-60 min)**:
   - Diagnose issue using logs/metrics
   - Fix configuration (timeouts, limits)
   - Restart gateway

3. **Long-term**:
   - Address root cause
   - Update deployment
   - Re-deploy with fixes

---

## SUPPORT & DOCUMENTATION

- **Security Issues**: Check SECURITY_HARDENING_REPORT.md
- **Test Failures**: Run `pytest tests/test_final_hardening.py -v`
- **Deployment**: See FINAL_HARDENING_PATCHES.md
- **Architecture**: See EXECUTION_SUMMARY.md

---
