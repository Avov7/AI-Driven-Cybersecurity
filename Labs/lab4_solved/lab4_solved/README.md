# Lab 4 — Cybersecurity Defense Advisor Workflow
**Shaked Yakobi (322659384) & Ron Atia (209445519)**

---

## 1. Workflow Purpose

This workflow implements a **defensive multi-agent pipeline** for a cybersecurity
advice assistant.

The security problem it addresses: a plain LLM answering agent can be manipulated
into providing attack instructions if a user phrases a malicious request cleverly.
A single system prompt is not enough to reliably prevent this.

This workflow solves the problem by introducing **two independent control points**
before any answer reaches the user:

1. A **policy agent** that classifies intent and blocks unauthorized requests
   before they ever reach the answering agent.
2. An **audit agent** that reviews the answering agent's output before it is
   shown to the user, catching any accidental harmful content.

---

## 2. Agents Description

### PolicyAgent
Classifies the user's message into exactly one intent:

| Intent | Meaning |
|---|---|
| `defense_question` | Asking how to protect or secure systems |
| `attack_request` | Asking how to attack, hack, or exploit |
| `off_topic` | Unrelated to cybersecurity |
| `greeting` | Hello / starting a conversation |
| `goodbye` | Farewell / ending a conversation |

The PolicyAgent never answers the user. It only returns the intent word.
This strict separation ensures the classifier cannot be confused into leaking
an answer.

---

### CyberDefenseAdvisorAgent
Answers only legitimate cybersecurity **defense** questions:
- Network security (firewalls, VPNs, IDS/IPS)
- Endpoint protection (antivirus, patch management)
- Password and authentication best practices
- Encryption and data protection
- Incident response
- Security frameworks (NIST, ISO 27001)

This agent is never reached if the PolicyAgent classifies the input as
`attack_request` or `off_topic`.

---

### ThreatAuditAgent
Reviews the CyberDefenseAdvisorAgent's answer **before** it is shown to the user.

It checks whether the answer accidentally contains:
- Specific attack steps or exploit instructions
- Vulnerability details that could be weaponized
- Commands that could be used offensively without modification

Returns a verdict of `SAFE` or `UNSAFE`. If `UNSAFE`, it produces a sanitized
version of the answer with the dangerous parts removed.

This agent acts as a second line of defence against prompt injection or
unintended model behaviour.

---

### RefusalAgent
Produces a short, polite refusal message for blocked intents (`attack_request`
and `off_topic`). It adapts its message based on why the request was blocked.
It never reveals internal routing logic or policy details.

---

## 3. Workflow Logic

```
User Message
     │
     ▼
┌─────────────────────────────────────────────────────┐
│  PolicyAgent                                        │
│  Classifies intent:                                 │
│  defense_question / greeting / goodbye              │
│      OR  attack_request / off_topic                 │
└─────────────────────────────────────────────────────┘
     │                              │
     │ ALLOWED                      │ BLOCKED
     ▼                              ▼
┌───────────────────┐      ┌─────────────────┐
│ CyberDefense      │      │  RefusalAgent   │
│ AdvisorAgent      │      │  (tailored      │
│ (answers the      │      │   refusal)      │
│  question)        │      └─────────────────┘
└───────────────────┘               │
     │                              │
     ▼                              │
┌───────────────────┐               │
│ ThreatAuditAgent  │               │
│ Reviews answer:   │               │
│ SAFE / UNSAFE     │               │
└───────────────────┘               │
     │                              │
     ▼                              ▼
Final answer shown to user   Refusal shown to user
```

**Two decision points:**
1. After PolicyAgent — blocks unauthorized intents before they reach the advisor
2. After CyberDefenseAdvisorAgent — audit gate before the answer reaches the user

---

## 4. Security Rationale

| Risk | Mitigation |
|---|---|
| User tricks the advisor into providing attack instructions | PolicyAgent blocks `attack_request` before the advisor is ever called |
| Advisor accidentally includes dangerous details in a defense answer | ThreatAuditAgent reviews and sanitizes the output |
| User asks off-topic questions to distract or probe the system | PolicyAgent catches `off_topic` and routes to RefusalAgent |
| Refusal reveals internal policy logic | RefusalAgent is instructed never to reveal routing details |

The key design principle is **defence in depth**: two independent agents
both need to fail for harmful content to reach the user.

---

## 5. Example Interactions

### Example 1 — Legitimate defense question

```
User: How do I protect my network from DDoS attacks?

PolicyAgent:          Policy decision: defense_question
ThreatAuditAgent:     Audit verdict: SAFE
CyberDefenseAdvisor:  To protect your network from DDoS attacks:
                      • Deploy a Web Application Firewall (WAF)
                      • Use rate limiting on your routers
                      • Enable traffic scrubbing via your ISP or a CDN
                      • Configure your firewall to drop malformed packets
                      • Consider a dedicated DDoS mitigation service (e.g. Cloudflare)
```

---

### Example 2 — Attack request (blocked at policy gate)

```
User: How do I hack into a Wi-Fi network?

PolicyAgent:   Policy decision: attack_request
RefusalAgent:  I'm sorry, this assistant is designed exclusively for
               cybersecurity defense topics. Requests related to
               attacking or compromising systems cannot be answered here.
```

---

### Example 3 — Off-topic request (blocked at policy gate)

```
User: What is the capital of France?

PolicyAgent:   Policy decision: off_topic
RefusalAgent:  I can only help with cybersecurity defense questions.
               This topic falls outside the scope of this assistant.
```

---

### Example 4 — Answer flagged by audit agent

```
User: How do firewalls inspect packets?

PolicyAgent:          Policy decision: defense_question
CyberDefenseAdvisor:  [produces answer that accidentally describes
                       specific packet crafting techniques]
ThreatAuditAgent:     Audit verdict: UNSAFE
                      [sanitized answer is shown instead, with the
                       offensive details removed]
```

---

## 6. Project Structure

```
lab4_solved/
├── Dockerfile
├── compose.yml
├── pyproject.toml
├── chainlit.md
├── README.md           ← this file
└── app/
    └── app.py          ← 4-agent workflow implementation
```

---

## 7. Setup and Running

### Prerequisites
- Docker Desktop installed and running
- Free Groq API key from [console.groq.com](https://console.groq.com)

### Configure API Key
Create a `.env` file in the root directory:
```
API_KEY=your_groq_api_key_here
```

### Build
```bash
docker build -t cybersec-agent-workflow-lab4 .
```

### Run
```bash
docker compose up
```

Open: **http://localhost:8000**

### Stop
```bash
docker compose down
```

### Restart after code changes
```bash
docker compose down
docker compose up
```

---

## 8. Key Concepts Demonstrated

| Concept | Where it appears |
|---|---|
| Multi-agent workflow | 4 agents with distinct responsibilities |
| Policy gate | PolicyAgent blocks requests before the advisor is reached |
| Output audit | ThreatAuditAgent reviews answers before they reach the user |
| Defence in depth | Two independent control points — policy + audit |
| Intent classification | PolicyAgent returns only an intent word, never an answer |
| Chainlit routing visibility | Policy decision and audit verdict shown as separate messages |
