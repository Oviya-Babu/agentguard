# AgentGuard-X: Security Mesh for Agentic AI Systems

**Mission-Critical Security Gateway for Autonomous AI Agents**

AgentGuard-X is a production-grade security mesh that sits between autonomous AI agents (LangChain, CrewAI) and all tools they invoke. It intercepts, validates, and enforces security policy on every tool execution — **before it reaches the execution layer**.

---

## 🔐 Core Security Principle

> **"Never trust agent output. Always verify intent before execution."**

AgentGuard-X enforces **inline, pre-execution security validation** across the entire decision pipeline.

---

## 🚀 What It Does

✓ **Intercepts** all tool calls before execution
✓ **Validates** agent identity, authorization, and rate limits
✓ **Detects** prompt injection, exfiltration sequences, and anomalies
✓ **Sanitizes** tool outputs by redacting PII and removing injection payloads
✓ **Audits** every decision with full tracing and observability
✓ **Protects** against OWASP LLM Top 10 threats (LLM01, LLM06, LLM08)

---

## 🧠 Architecture Overview

```
AI Agent
   ↓
[1] Global Rate Limit (Redis Lua)
   ↓
[2] JWT Validation (RS256 recommended)
   ↓
[3] Agent Registration (Redis Session)
   ↓
[4] RBAC Enforcement (OPA Policies)
   ↓
[5] Per-Agent Rate Limit (Sliding Window)
   ↓
[6] Sequence Analysis (Attack Patterns)
   ↓
[7] Triage Engine (Behavioral Scoring)
   ↓
DECISION: ALLOW / BLOCK / SANDBOX
   ↓
[8] Output Sanitization (Presidio + Injection Scanning)
   ↓
Tool Execution & Result to Agent
```

---

## ⚡ Quick Start

### 1. Install Dependencies

```bash
make setup
```

### 2. Start Services

```bash
docker compose up -d
make run
```

### 3. Run Tests

```bash
python scripts/test_scenarios.py
```

---

## 🔎 Observability Endpoints

### Health Check (Public)

```bash
curl http://localhost:8000/health
```

Response:

```json
{ "status": "ok" }
```

---

### Readiness Probe (Sanitized)

```bash
curl http://localhost:8000/ready
```

Response:

```json
{
  "status": "ready"
}
```

> ⚠️ Internal service details (Redis/OPA URLs, ports) are intentionally hidden.

---

### Security Metrics (Protected 🔐)

```bash
curl http://localhost:8000/metrics/security \
  -H "x-api-key: <admin-key>"
```

Response (Aggregated Only):

```json
{
  "allowed_requests": 124,
  "blocked_requests": 18,
  "sandboxed_requests": 6
}
```

> ❗ No rule names, payloads, or detection logic is exposed to prevent adversarial probing.

---

## 🛡️ Security Features

### ✓ Fail-Closed Design

* Redis unavailable → SANDBOX
* OPA unavailable → BLOCK
* Triage timeout → SANDBOX
* Any error → BLOCK

---

### ✓ Identity & Access Control

* JWT validation (**RS256 recommended over HS256**)
* Agent registration via Redis session
* RBAC enforcement via OPA

---

### ✓ Attack Detection

* Prompt Injection (pattern + semantic detection)
* Data Exfiltration (multi-step sequence analysis)
* Excessive Agency (RBAC + rate limiting)
* Behavioral anomalies via triage scoring

---

### ✓ Output Protection

* PII detection (Presidio)
* Redaction format: `<ENTITY_TYPE_N>`
* Injection payload stripping

---

### ✓ Observability (Safe by Design)

* Structured logs only (no raw inputs/outputs)
* Trace IDs for debugging
* OpenTelemetry integration (restricted access)

---

## 🔐 Security Hardening (IMPORTANT)

### 1. JWT Security

* Use **RS256 (public/private key)**
* Rotate keys periodically
* Never store secrets in plaintext `.env` in production

---

### 2. Endpoint Protection

* `/metrics/security` → requires API key
* Rate limiting applied to all endpoints
* Sensitive endpoints should be internal-only in production

---

### 3. Input Defense

* Input normalization (decode + canonicalize)
* Payload size limits enforced
* Reject malformed or oversized inputs early

---

### 4. Response Minimization

Responses intentionally avoid detailed reasoning:

```json
{
  "decision": "BLOCK"
}
```

> Prevents attackers from learning policy behavior.

---

### 5. Cross-Session Monitoring (Recommended)

Track sequences across sessions to prevent distributed attacks.

---

## 📊 Performance Targets

| Metric               | Target |
| -------------------- | ------ |
| Gateway overhead p95 | <10ms  |
| Full pipeline p95    | <60ms  |
| RPS capacity         | 10,000 |

---

## 🧪 Test Scenarios

| Scenario            | Expected Result |
| ------------------- | --------------- |
| Clean request       | ALLOW           |
| Prompt injection    | BLOCK           |
| Forbidden tool      | BLOCK           |
| Rate limit exceeded | BLOCK           |
| Redis down          | SANDBOX         |
| OPA down            | BLOCK           |

---

## ⚠️ Known Limitations (Important)

AgentGuard-X is designed for strong enforcement, but:

* Pattern-based detection can be bypassed by advanced prompt obfuscation
* Cross-session attack correlation is limited (future enhancement)
* PII detection depends on model accuracy (not perfect)
* Behavioral scoring depends on triage engine latency
* Metrics endpoints must remain protected to prevent feedback attacks

---

## 🔮 Future Enhancements

* LLM-based semantic intent verification
* Cross-agent behavioral graph analysis
* Zero-trust agent identity scoring
* Adaptive policy learning engine
* Adversarial prompt simulation testing

---

## 🧱 Project Structure

```
agentguard/
├── app/
├── tests/
├── scripts/
├── policies/
├── logs/
└── README.md
```

---

## ✅ Success Criteria

✓ Clean requests → ALLOW
✓ Malicious inputs → BLOCK
✓ PII never logged
✓ Fail-closed enforced
✓ No sensitive data leakage

---

## 🧠 Key Insight

> AgentGuard-X shifts security from **monitoring what happened**
> to **controlling what is allowed to happen**

---

## 📌 License

Proprietary — AgentGuard-X

---

## 💬 Support

Refer to:

* TESTING_GUIDE.md
* QUICK_TEST_REFERENCE.md
* Source code documentation

---

**AgentGuard-X — Securing AI from intent to execution.**
