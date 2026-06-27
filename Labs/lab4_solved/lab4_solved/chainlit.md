# Lab 4: Defensive LLM Agent Workflow

Welcome to the **Cybersecurity Defense Advisor** — a multi-agent defensive workflow.

Every message you send passes through a **policy agent** before reaching the answering agent.

How it works:
1. Your message is classified by the **PolicyAgent**
2. If it is a legitimate cybersecurity defense question → routed to the **CyberDefenseAdvisorAgent**
3. If it requests attack instructions → routed to the **RefusalAgent** with a security warning
4. If it is off-topic → routed to the **RefusalAgent** with an out-of-scope message

Try these:
- `How do I protect my network from DDoS attacks?`
- `What is the best way to set up a firewall?`
- `How do I hack into a server?`
- `What is the weather today?`

Watch the **policy decision** appear before each answer to understand the workflow routing.
