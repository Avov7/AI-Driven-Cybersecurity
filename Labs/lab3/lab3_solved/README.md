# Lab 3 — Password Security Agent
**Shaked Yakobi (322659384) & Ron Atia (209445519)**

---

## 1. Overview

This lab implements a **Password Security Agent** built with AG2 (AutoGen) and Chainlit.

The agent helps users evaluate, analyze, and improve their passwords through structured tool calls — demonstrating the core concept of LLM agents that invoke Python functions rather than just generating text.

---

## 2. Environment Setup

### 2.1 Prerequisites
- Docker Desktop installed and running
- A free Groq API key from [console.groq.com](https://console.groq.com) (no credit card required)

### 2.2 Configure API Key
Create a `.env` file in the root of this directory:
### 2.3 Build the Docker Image
```bash
docker build -t cybersec-agent-chainlit-lab3 .
```

### 2.4 Run the Application
```bash
docker compose up
```
Open the Chainlit UI at **http://localhost:8000**

### 2.5 Restart After Code Changes
```bash
docker compose down
docker compose up
```

---

## 3. Agent Description

The **Password Security Agent** is a conversational assistant that helps users understand and improve their password security.

It uses four tools to retrieve structured data, then reasons over the results to give clear, actionable explanations in plain English — demonstrating the key principle that **tools handle data, the agent handles reasoning**.

---

## 4. Agent Tools

### `check_password_strength(password)`
Analyses the structural properties of a password.

- **Input:** password string
- **Returns:** length, character variety (uppercase/lowercase/digits/special chars), estimated bit entropy, and a strength label: `Weak / Fair / Strong / Very Strong`

### `check_common_password(password)`
Checks whether the password appears in a list of 36 known weak/common passwords.

- **Input:** password string
- **Returns:** whether the password is common, list size checked, and a risk explanation

### `get_security_tips(topic)`
Returns structured security advice for a given topic.

- **Input:** topic — one of `length`, `complexity`, `uniqueness`, `general`
- **Returns:** a list of actionable tips for that topic

### `strengthen_password(password)`
Generates improved versions of a weak password.

- **Input:** password string
- **Returns:** detected weaknesses, 3 concrete improved password suggestions, and an explanation of what was changed in each

---

## 5. Example Interactions

**Evaluating a password:**
User: Check the strength of: Summer2024!
Agent: [calls check_password_strength]

[calls check_common_password]
Result: Strong password — 11 chars, all 4 character types, ~69 bits entropy.

Not found in common password list. Suggestion: extend to 16+ chars.

**Improving a weak password:**
User: Strengthen the password: hello
Agent: [calls strengthen_password]

[calls check_password_strength on best suggestion]
Result: "hello" is weak — too short, no uppercase, no digits, no special chars.

Suggested improvements:

1. Hello42!xP7  — added uppercase, digits, special char, length 12

2. Hello19@xP3  — variant with different digits and special char

3. Hello73#xP5  — another variant for uniqueness

**Getting security tips:**
User: Give me tips on creating a strong password
Agent: [calls get_security_tips("general")]
Result: Returns 4 practical tips including enabling 2FA and using a password manager.

---

## 6. Project Structure
lab3_solved/

├── Dockerfile

├── compose.yml

├── pyproject.toml

├── uv.lock

├── chainlit.md

├── README.md          ← this file

└── app/

└── agent/

├── app.py     ← agent implementation

└── README.md  ← agent-specific documentation

---

## 7. Key Concepts Demonstrated

| Concept | How it appears in this lab |
|---|---|
| LLM Agent vs chatbot | Agent calls Python tools; does not guess strength values |
| Tool registration | `functions=[...]` argument in `ConversableAgent` |
| Tool–agent split | Tools compute data, agent interprets and explains |
| Chainlit Steps | Every tool call is visible as an expandable step in the UI |
| Containerized environment | Runs fully inside Docker, no local Python setup needed |