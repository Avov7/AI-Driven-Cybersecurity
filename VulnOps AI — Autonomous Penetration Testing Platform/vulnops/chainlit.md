# 🔴 VulnOps AI — Autonomous Penetration Testing Platform

Welcome to the **VulnOps AI War Room**.

This platform uses an **AI agentic pipeline** to autonomously perform safe security reconnaissance,
classify findings against the **MITRE ATT&CK framework**, and generate a full security report.

---

## How the pipeline works

```
Your Target URL
      │
      ▼
AI Campaign Planner (Groq LLM)
      │  generates attack plan
      ▼
Recon Agents (6 parallel tasks)
  ├── HTTP Header Analysis        → TA0043 / T1592
  ├── Security Header Audit       → TA0001 / T1190
  ├── CORS Misconfiguration Check → TA0001 / T1190
  ├── Sensitive Path Discovery    → TA0043 / T1595
  ├── robots.txt Analysis         → TA0043 / T1596
  └── Full Reconnaissance Report
      │
      ▼
Kafka topic: vulnops.findings  →  Redpanda Console (localhost:8080)
Jaeger traces                  →  Jaeger UI         (localhost:16686)
      │
      ▼
AI Final Report with MITRE ATT&CK coverage
```

---

## Try it now

Type a target URL to begin a scan:

- `http://target:5000` — the built-in mock vulnerable target
- Any public URL you own (only scan systems you have permission to test)

Each tool call is visible below as an expandable **Step**.
