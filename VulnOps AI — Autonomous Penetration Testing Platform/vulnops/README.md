# 🔴 VulnOps AI — Autonomous Penetration Testing Platform

**Shaked Yakobi (322659384) & Ron Atia (209445519)**
Final Project — AI in Cybersecurity Course (NVIDIA Morpheus)

---

## Overview

VulnOps AI is an **autonomous AI-driven security reconnaissance platform** that simulates the behavior of a human penetration tester.

The system uses an **AG2 agentic LLM** to autonomously plan and execute 6 safe reconnaissance modules against a target, classify every finding against the **MITRE ATT&CK framework**, stream all events to **Kafka**, trace every operation through **Jaeger**, and generate a full security report — all without human intervention.

---

## Architecture

```
User Input (Target URL)  →  Chainlit War Room UI
                                    │
                                    ▼
                     AG2 Autonomous Recon Agent (LLM)
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
             scan_target_info   check_http_headers  check_security_headers
             check_cors         check_sensitive_paths  check_robots_txt
                    │
                    ▼
         MITRE ATT&CK Classification
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
   Kafka (vulnops.findings)   Jaeger (vulnops-ai traces)
   → Redpanda Console         → Distributed tracing UI
          │
          ▼
   AI Final Security Report
```

---

## Reconnaissance Tools & MITRE ATT&CK Mapping

| Tool | What it checks | MITRE Tactic | Technique |
|------|---------------|--------------|-----------|
| `scan_target_info` | Target liveness, response time, redirects | TA0043 Reconnaissance | T1595 Active Scanning |
| `check_http_headers` | Server/technology version disclosure | TA0043 Reconnaissance | T1592 Gather Victim Host Info |
| `check_security_headers` | Missing CSP, HSTS, X-Frame-Options, etc. | TA0001 Initial Access | T1190 Exploit Public-Facing App |
| `check_cors` | CORS misconfiguration, wildcard origins | TA0009 Collection | T1185 Browser Session Hijacking |
| `check_sensitive_paths` | Exposed /admin, /.env, /backup, /api/users | TA0043 Reconnaissance | T1595 Active Scanning |
| `check_robots_txt` | Sensitive paths revealed in robots.txt | TA0043 Reconnaissance | T1596 Search Open Technical DBs |

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| AI Agent | AG2 (AutoGen) + Groq/OpenRouter LLM | Autonomous planning & reasoning |
| UI | Chainlit | War Room chat interface |
| Message Queue | Apache Kafka (KRaft) | Real-time findings streaming |
| Kafka UI | Redpanda Console | Event inspection |
| Distributed Tracing | Jaeger + OpenTelemetry | Pipeline observability |
| Recon Tools | Python + requests | Safe HTTP reconnaissance |
| Mock Target | Flask | Intentionally vulnerable demo app |
| Orchestration | Docker Compose | Full stack deployment |

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| VulnOps War Room | 8000 | Main Chainlit UI |
| Mock Vulnerable Target | 5001 | Demo target for scanning |
| Redpanda Console | 8080 | Kafka topic viewer |
| Jaeger UI | 16686 | Distributed trace viewer |
| Kafka | 9092 | Internal message broker |

---

## Setup & Running

### Prerequisites
- Docker Desktop installed and running
- A free API key from [openrouter.ai](https://openrouter.ai) or [console.groq.com](https://console.groq.com)

### 1. Create `.env` file
```bash
API_KEY=your_api_key_here
```

### 2. Build the images
```bash
docker compose build
```

### 3. Start all services
```bash
docker compose up
```

### 4. Open in browser
| URL | What you'll see |
|-----|----------------|
| http://localhost:8000 | VulnOps War Room |
| http://localhost:5001 | Mock vulnerable target |
| http://localhost:8080 | Redpanda — Kafka events |
| http://localhost:16686 | Jaeger — pipeline traces |

### 5. Run a scan
In the War Room, type:
```
http://target:5000
```

### 6. Stop
```bash
docker compose down
```

---

## Project Structure

```
vulnops/
├── Dockerfile                  ← VulnOps app image
├── compose.yml                 ← Full stack orchestration
├── requirements.txt            ← Python dependencies
├── chainlit.md                 ← War Room welcome screen
├── .env.example                ← API key template
├── app/
│   ├── app.py                  ← Chainlit + AG2 War Room
│   ├── tools.py                ← 6 recon tools with MITRE ATT&CK
│   ├── kafka_pub.py            ← Non-blocking Kafka publisher
│   └── tracer.py               ← Jaeger/OpenTelemetry setup
└── target/
    ├── Dockerfile
    └── app.py                  ← Mock vulnerable Flask target
```

---

## Example Findings

From a scan of the mock target, VulnOps AI detected:

| Severity | Finding | MITRE Technique |
|----------|---------|-----------------|
| 🔴 Critical | `.env` file publicly accessible — exposes DB passwords & API keys | T1595 |
| 🟠 High | `/admin` panel with no authentication | T1595 |
| 🟠 High | `/api/users` endpoint open — returns full user list | T1595 |
| 🟠 High | Open CORS policy — allows any origin | T1185 |
| 🟡 Medium | Missing Content-Security-Policy header — XSS risk | T1190 |
| 🟢 Low | Server header reveals Flask version | T1592 |

---

## Key Concepts Demonstrated

| Concept | Implementation |
|---------|---------------|
| Agentic AI | AG2 ConversableAgent autonomously decides which tools to call |
| MITRE ATT&CK | Every finding mapped to tactic + technique |
| Event-driven pipeline | Findings streamed to Kafka in real time |
| Distributed tracing | Every tool call traced end-to-end in Jaeger |
| Containerized deployment | Full stack runs with one `docker compose up` |
| Safe exploitation | All checks are read-only — no destructive actions |

---

## Security Notes

- All reconnaissance is **read-only and non-destructive**
- Only scan systems **you own or have explicit permission to test**
- The mock target (`target/app.py`) is intentionally misconfigured for **demo purposes only** — do not deploy it publicly
