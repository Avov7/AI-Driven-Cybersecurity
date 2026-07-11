"""
VulnOps AI — War Room
Chainlit front-end wired to an AG2 autonomous reconnaissance agent.

Workflow:
  User provides a target URL
  → AG2 agent calls 6 recon tools in sequence
  → Each tool call is shown as a Chainlit Step
  → Findings are published to Kafka (vulnops.findings)
  → Jaeger traces every span
  → LLM generates a final MITRE ATT&CK-mapped security report
"""
import json
import os
import uuid

import chainlit as cl
from autogen import ConversableAgent
from autogen.events.agent_events import ExecuteFunctionEvent, ExecutedFunctionEvent

from tools import (
    scan_target_info,
    check_http_headers,
    check_security_headers,
    check_cors,
    check_sensitive_paths,
    check_robots_txt,
)

# ─── LLM configuration (Groq / any OpenAI-compatible endpoint) ───────────────
_api_key = os.getenv("API_KEY")
if not _api_key:
    raise RuntimeError(
        "API_KEY is not set. "
        "Create a .env file with API_KEY=your_groq_key and restart."
    )

llm_config = {
    "config_list": [
        {
            "model":    os.getenv("MODEL", "llama-3.3-70b-versatile"),
            "api_key":  _api_key,
            "base_url": os.getenv("API_BASE_URL", "https://api.groq.com/openai/v1"),
            "price":    [0, 0],
        }
    ],
}

# ─── System prompt ────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
You are VulnOps AI, an autonomous cybersecurity reconnaissance agent.
Your mission is to perform a comprehensive, SAFE, read-only security assessment
of the given target URL.

You have six reconnaissance tools. You MUST call ALL of them for every assessment:

1. scan_target_info          — Confirms target is live; measures response time.
2. check_http_headers        — Detects server/technology version disclosure.
3. check_security_headers    — Audits for missing security headers (CSP, HSTS, etc.).
4. check_cors                — Tests CORS misconfiguration.
5. check_sensitive_paths     — Discovers exposed admin panels, config files, backups.
6. check_robots_txt          — Analyses robots.txt for hidden sensitive paths.

IMPORTANT RULES:
- Call every tool with the same target_url and campaign_id provided by the user.
- Call the tools in order: scan_target_info first, then the others.
- Do NOT skip any tool, even if an earlier tool found no issues.
- Do NOT perform any destructive operations.
- Only analyse targets the user explicitly provides.

After ALL tools have been called, produce a FINAL SECURITY REPORT with:

## 🔍 VulnOps AI — Security Assessment Report

**Target:** <url>
**Campaign ID:** <id>

### Executive Summary
<1-2 sentence summary of what was found>

### Findings by Severity
| Icon | Severity | Count |
|------|----------|-------|
| 🔴 | Critical | N |
| 🟠 | High | N |
| 🟡 | Medium | N |
| 🟢 | Low | N |
| ⚪ | Informational | N |
**Total findings: N**

### MITRE ATT&CK Coverage
List each tactic/technique that was triggered, with the finding that maps to it.

### Top 3 Priority Remediations
1. [Highest severity finding + one-line fix]
2. ...
3. ...

### Conclusion
<1-2 sentences on overall risk posture>

Answer in English only. Be concise and technical.
"""

# ─── Welcome message ─────────────────────────────────────────────────────────
WELCOME = """\
**VulnOps AI is ready.**

To start a security assessment, type the target URL.

**Built-in demo target:** `http://target:5000`
(This is a mock vulnerable application running inside Docker.)

You can also test any public URL you own.
Each tool call will appear as an expandable step below.
"""


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _fmt(obj: object) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (dict, list)):
        return json.dumps(obj, indent=2, default=str)
    return str(obj)


# ─── Chainlit handlers ───────────────────────────────────────────────────────
@cl.on_chat_start
async def on_chat_start():
    campaign_id = str(uuid.uuid4())[:8]
    cl.user_session.set("campaign_id", campaign_id)

    agent = ConversableAgent(
        name="vulnops_recon_agent",
        system_message=SYSTEM_PROMPT,
        llm_config=llm_config,
        human_input_mode="NEVER",
        functions=[
            scan_target_info,
            check_http_headers,
            check_security_headers,
            check_cors,
            check_sensitive_paths,
            check_robots_txt,
        ],
    )
    cl.user_session.set("agent", agent)
    await cl.Message(content=WELCOME, author="VulnOps AI").send()


@cl.on_message
async def on_message(message: cl.Message):
    agent: ConversableAgent = cl.user_session.get("agent")
    campaign_id: str = cl.user_session.get("campaign_id", "unknown")

    target = message.content.strip()

    # Basic URL sanity check
    if not (target.startswith("http://") or target.startswith("https://")):
        await cl.Message(
            content=(
                "⚠️ Please provide a full URL starting with `http://` or `https://`.\n"
                "Example: `http://target:5000`"
            ),
            author="VulnOps AI",
        ).send()
        return

    await cl.Message(
        content=(
            f"🚀 **Starting campaign `{campaign_id}`**\n"
            f"Target: `{target}`\n\n"
            f"Running 6 reconnaissance modules... "
            f"Tool calls will appear below as expandable steps.\n\n"
            f"📡 Findings are streamed live to Kafka topic `vulnops.findings` "
            f"→ visible at [localhost:8080](http://localhost:8080)\n"
            f"🔍 Traces visible at [localhost:16686](http://localhost:16686)"
        ),
        author="VulnOps AI",
    ).send()

    # Run the AG2 agent — it will call all 6 tools autonomously
    user_prompt = (
    f"Perform a complete security assessment of this target:\n"
    f"URL: {target}\n"
    f"campaign_id: {campaign_id}\n\n"
    f"Call ALL six tools in order. After all tools are done, write the final report."
)

    response = await agent.a_run(
        message=user_prompt,
        clear_history=False,
        max_turns=20,
        summary_method="last_msg",
        user_input=False,
    )

    # ── Collect tool inputs so we can pair them with outputs ──────────────────
    tool_inputs: dict[str, dict] = {}

    async for event in response.events:
        if isinstance(event, ExecuteFunctionEvent):
            ed = event.content
            key = getattr(ed, "call_id", None) or ed.func_name
            tool_inputs[key] = {
                "name":  ed.func_name,
                "input": _fmt(ed.arguments) or "(no arguments)",
            }
            continue

        if not isinstance(event, ExecutedFunctionEvent):
            continue

        ed = event.content
        key = getattr(ed, "call_id", None) or ed.func_name
        step_meta = tool_inputs.get(
            key, {"name": ed.func_name, "input": "(no arguments)"}
        )

        # Parse findings from tool output for severity colouring
        try:
            result = json.loads(_fmt(ed.content)) if isinstance(ed.content, str) else ed.content
            findings = result.get("findings", []) if isinstance(result, dict) else []
        except Exception:
            findings = []

        # Choose step icon based on highest severity found
        severity_order = ["critical", "high", "medium", "low", "informational"]
        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "informational": "⚪"}
        top_sev = "informational"
        for f in findings:
            sev = f.get("severity", "informational").lower()
            if severity_order.index(sev) < severity_order.index(top_sev):
                top_sev = sev
        icon = icons.get(top_sev, "⚪")

        tool_label = f"{icon} {step_meta['name']} ({len(findings)} finding{'s' if len(findings) != 1 else ''})"

        async with cl.Step(name=tool_label, type="tool") as step:
            step.input = step_meta["input"]
            step.output = _fmt(ed.content)

    # ── Final report ──────────────────────────────────────────────────────────
    summary = await response.summary
    final_text = _fmt(summary)
    await cl.Message(content=final_text, author="VulnOps AI").send()

    await cl.Message(
        content=(
            f"✅ **Campaign `{campaign_id}` complete.**\n\n"
            f"📊 Check Redpanda Console → [localhost:8080](http://localhost:8080) "
            f"→ Topics → `vulnops.findings` to see all events streamed during the scan.\n\n"
            f"🔍 Check Jaeger → [localhost:16686](http://localhost:16686) "
            f"→ Service: `vulnops-ai` → Find Traces to see the full pipeline execution trace."
        ),
        author="VulnOps AI",
    ).send()
