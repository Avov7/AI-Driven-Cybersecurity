import os
import json
import re
import math
import random
from typing import Annotated, Dict, List

import chainlit as cl
from autogen import ConversableAgent
from autogen.events.agent_events import ExecuteFunctionEvent, ExecutedFunctionEvent

# ---------------------------
#  In-memory data: common weak passwords and security tips
# ---------------------------

# A small representative set of the most commonly used passwords
COMMON_PASSWORDS: List[str] = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "dragon", "111111",
    "baseball", "iloveyou", "trustno1", "sunshine", "princess",
    "welcome", "admin", "login", "passw0rd", "starwars",
    "solo", "superman", "michael", "jessica", "password1",
    "qwerty123", "000000", "1q2w3e", "zaq1zaq1", "qazwsx",
]

SECURITY_TIPS: Dict[str, List[str]] = {
    "length": [
        "Use at least 12 characters; 16 or more is ideal.",
        "Longer passwords are exponentially harder to crack.",
        "Consider using a passphrase: 4+ random words joined together.",
    ],
    "complexity": [
        "Mix uppercase letters, lowercase letters, digits, and symbols.",
        "Avoid predictable substitutions like 'a' → '@' or 'e' → '3'.",
        "Don't use keyboard patterns such as 'qwerty' or '1234'.",
    ],
    "uniqueness": [
        "Never reuse a password across different services.",
        "Use a password manager to generate and store unique passwords.",
        "If one service is breached, unique passwords protect all others.",
    ],
    "general": [
        "Enable two-factor authentication (2FA) wherever possible.",
        "Never share your password via email, chat, or phone.",
        "Change passwords immediately if you suspect a breach.",
        "Avoid storing passwords in plain-text files or browser auto-fill on shared devices.",
    ],
}

# ---------------------------
#  Tools
# ---------------------------


def check_password_strength(
    password: Annotated[
        str,
        "The password string to evaluate. Will be analysed for length, "
        "character variety and estimated entropy.",
    ],
) -> Dict:
    """
    Analyse a password and return a structured strength report.

    Checks performed:
    - Length
    - Presence of uppercase letters, lowercase letters, digits, special characters
    - Estimated bit entropy
    - Overall strength label: Weak / Fair / Strong / Very Strong
    """
    length = len(password)

    has_upper   = bool(re.search(r"[A-Z]", password))
    has_lower   = bool(re.search(r"[a-z]", password))
    has_digit   = bool(re.search(r"\d",    password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    # Estimate character-set size for entropy calculation
    charset_size = 0
    if has_lower:   charset_size += 26
    if has_upper:   charset_size += 26
    if has_digit:   charset_size += 10
    if has_special: charset_size += 32   # approximate printable special chars

    entropy_bits = round(length * math.log2(charset_size), 1) if charset_size > 0 else 0

    # Count how many character-type criteria are satisfied
    criteria_met = sum([has_upper, has_lower, has_digit, has_special])

    # Determine overall strength
    if length < 8 or criteria_met <= 1 or entropy_bits < 30:
        strength = "Weak"
    elif length < 12 or criteria_met == 2 or entropy_bits < 50:
        strength = "Fair"
    elif length < 16 or criteria_met == 3 or entropy_bits < 70:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {
        "ok": True,
        "password_length": length,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_digits":    has_digit,
        "has_special_chars": has_special,
        "character_variety_score": f"{criteria_met}/4",
        "estimated_entropy_bits": entropy_bits,
        "strength_label": strength,
    }


def check_common_password(
    password: Annotated[
        str,
        "The password to check against a list of commonly used weak passwords.",
    ],
) -> Dict:
    """
    Check whether the given password appears in a list of known common passwords.

    Returns whether it is common, the total list size, and a few sample entries
    so the agent can explain the risk.
    """
    is_common = password.lower() in [p.lower() for p in COMMON_PASSWORDS]

    return {
        "ok": True,
        "password_is_common": is_common,
        "checked_against_list_size": len(COMMON_PASSWORDS),
        "sample_common_passwords": COMMON_PASSWORDS[:5],
        "risk_note": (
            "This password is extremely easy to guess and will be tried first "
            "in any dictionary or brute-force attack."
            if is_common
            else "Password was not found in the common password list."
        ),
    }


def get_security_tips(
    topic: Annotated[
        str,
        "Topic for security tips. Must be one of: 'length', 'complexity', "
        "'uniqueness', 'general'.",
    ],
) -> Dict:
    """
    Return a structured list of security tips for the given topic.

    Available topics:
    - length      : advice about password length
    - complexity  : advice about character variety
    - uniqueness  : advice about reusing passwords
    - general     : general security best practices
    """
    valid_topics = list(SECURITY_TIPS.keys())

    if topic not in SECURITY_TIPS:
        return {
            "ok": False,
            "error": "topic_not_found",
            "message": (
                f"Topic '{topic}' is not available. "
                f"Valid topics: {', '.join(valid_topics)}."
            ),
            "valid_topics": valid_topics,
        }

    return {
        "ok": True,
        "topic": topic,
        "tips": SECURITY_TIPS[topic],
        "tip_count": len(SECURITY_TIPS[topic]),
    }


def strengthen_password(
    password: Annotated[
        str,
        "The password string to improve. The function will identify missing "
        "character classes and generate stronger alternatives.",
    ],
) -> Dict:
    """
    Analyze a password and return stronger replacement suggestions.

    The function identifies common weaknesses and generates three improved
    suggestions that fix the detected issues.
    """
    weaknesses: List[str] = []
    if len(password) < 12:
        weaknesses.append("too short (under 12 characters)")
    if not re.search(r"[A-Z]", password):
        weaknesses.append("missing uppercase letters")
    if not re.search(r"[a-z]", password):
        weaknesses.append("missing lowercase letters")
    if not re.search(r"\d", password):
        weaknesses.append("missing digits")
    if not re.search(r"[^A-Za-z0-9]", password):
        weaknesses.append("missing special characters")

    if not weaknesses:
        weaknesses.append("no obvious weaknesses found")

    seed_value = len(password) + sum(ord(ch) for ch in password)
    random.seed(seed_value)

    suggestions: List[str] = []
    explanations: List[str] = []

    for index in range(3):
        suggestion = password
        explanation_parts: List[str] = []

        if len(suggestion) < 12:
            while len(suggestion) < 14:
                suggestion += str(random.randint(0, 9))
                if len(suggestion) < 14:
                    suggestion += random.choice("!@#$")
            explanation_parts.append("Extended length to at least 14 characters")

        if not re.search(r"[A-Z]", suggestion):
            insert_pos = max(1, len(suggestion) // 2)
            suggestion = (
                suggestion[:insert_pos]
                + random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
                + suggestion[insert_pos:]
            )
            explanation_parts.append("Added uppercase letters")

        if not re.search(r"[a-z]", suggestion):
            insert_pos = max(1, len(suggestion) // 2)
            suggestion = (
                suggestion[:insert_pos]
                + random.choice("abcdefghijklmnopqrstuvwxyz")
                + suggestion[insert_pos:]
            )
            explanation_parts.append("Added lowercase letters")

        if not re.search(r"\d", suggestion):
            suggestion += f"{random.randint(0, 9)}{random.randint(0, 9)}"
            explanation_parts.append("Added two random digits")

        if not re.search(r"[^A-Za-z0-9]", suggestion):
            special_char = random.choice("!@#$")
            suggestion += special_char
            explanation_parts.append(f"Added special character {special_char}")

        if len(suggestion) < 14:
            while len(suggestion) < 14:
                suggestion += str(random.randint(0, 9))
                if len(suggestion) < 14:
                    suggestion += random.choice("!@#$")

        if not explanation_parts:
            explanation_parts.append("Kept the original structure while strengthening the password")

        suggestions.append(suggestion)
        explanations.append("; ".join(explanation_parts))
        random.seed(seed_value + index + 1)

    return {
        "ok": True,
        "original_password": password,
        "weaknesses": weaknesses,
        "suggestions": suggestions,
        "explanations": explanations,
    }


# ---------------------------
#  LLM configuration
# ---------------------------

api_base_url = os.getenv("API_BASE_URL")
api_key      = os.getenv("API_KEY")
model        = os.getenv("MODEL", "llama-3.3-70b-versatile")

if not api_key:
    raise RuntimeError(
        "API_KEY is not set. "
        "Set it in your .env file or via docker compose environment."
    )

llm_config = {
    "config_list": [
        {
            "model":    model,
            "api_key":  api_key,
            "base_url": api_base_url,
            "price":    [0, 0],
        }
    ],
}

# ---------------------------
#  System prompt
# ---------------------------

SYSTEM_PROMPT = """\
You are a Password Security Agent. Your job is to help users evaluate the
strength of their passwords and give them practical security advice.

You have access to four tools:

1. check_password_strength(password)
   – Analyses a password for length, character variety, and estimated bit
     entropy, and returns a strength label: Weak / Fair / Strong / Very Strong.

2. check_common_password(password)
   – Checks whether the password appears in a well-known list of commonly used
     weak passwords that attackers try first.

3. get_security_tips(topic)
   – Returns actionable security tips for a given topic.
     Valid topics: 'length', 'complexity', 'uniqueness', 'general'.

4. strengthen_password(password)
   – Analyses a password for missing complexity traits and returns three
     stronger password suggestions with explanations.

Rules:
1. When the user asks you to evaluate, check, or rate a password, always call
   check_password_strength first, then call check_common_password to detect
   obvious weak choices.
2. If the evaluation shows the password is weak or common, automatically fetch
   relevant tips using get_security_tips.
3. When the user asks for security tips or advice about passwords, call
   get_security_tips with the most relevant topic.
4. Always base your explanation on the structured data returned by the tools.
   Do not guess or make up strength scores or entropy values.
5. Never store, log, or repeat the exact password back to the user more than
   once. Treat password values as sensitive input.
6. If the user asks to strengthen, improve, fix, or upgrade a password, call
   strengthen_password with that password, then explain the suggestions in
   plain language, highlighting what was wrong with the original and what each
   suggestion fixes.
7. After calling strengthen_password, also call check_password_strength on the
   first suggested improved password to confirm it is now Strong or Very Strong.
8. For casual greetings (hello, hi, how are you), reply briefly. Always return
   to the password security topic if the user has a follow-up question.

Always answer in English. Be concise, clear, and friendly.
"""

WELCOME_MESSAGE = """\
Hello! I am the **Password Security Agent** for Lab 3.

I can help you:
- Evaluate the strength of a password (length, complexity, entropy)
- Check whether a password is dangerously common
- Give you practical tips for creating stronger passwords

Try asking:
- `Check the strength of: Summer2024!`
- `Is "123456" a common password?`
- `Give me tips on password complexity.`

When I use a tool, Chainlit will show the call as an expandable step so you
can see exactly what data was returned.
"""

# ---------------------------
#  Helper
# ---------------------------


def _format_content(content: object) -> str:
    """Serialize content to a string suitable for Chainlit step display."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (dict, list, tuple)):
        return json.dumps(content, ensure_ascii=True, indent=2)
    return str(content)


# ---------------------------
#  Chainlit event handlers
# ---------------------------


@cl.on_chat_start
async def on_chat_start():
    """Create the AG2 assistant and store it in the user session."""
    assistant = ConversableAgent(
        name="password_security_agent",
        system_message=SYSTEM_PROMPT,
        llm_config=llm_config,
        human_input_mode="NEVER",
        functions=[check_password_strength, check_common_password, get_security_tips, strengthen_password],
    )

    cl.user_session.set("assistant", assistant)
    await cl.Message(content=WELCOME_MESSAGE, author="password_security_agent").send()


@cl.on_message
async def on_message(message: cl.Message):
    """Handle each user message using AG2 async single-agent execution."""
    assistant: ConversableAgent = cl.user_session.get("assistant")

    response = await assistant.a_run(
        message=message.content,
        clear_history=False,
        max_turns=8,
        summary_method="last_msg",
        user_input=False,
    )

    # Collect tool inputs so we can pair them with their outputs
    tool_inputs: dict[str, dict[str, str]] = {}

    async for event in response.events:
        if isinstance(event, ExecuteFunctionEvent):
            event_data = event.content
            tool_key = getattr(event_data, "call_id", None) or event_data.func_name
            tool_inputs[tool_key] = {
                "name":  event_data.func_name,
                "input": _format_content(event_data.arguments) or "(no arguments)",
            }
            continue

        if not isinstance(event, ExecutedFunctionEvent):
            continue

        event_data = event.content
        tool_key   = getattr(event_data, "call_id", None) or event_data.func_name
        step_data  = tool_inputs.get(
            tool_key,
            {"name": event_data.func_name, "input": "(no arguments)"},
        )

        # Display the tool call as an expandable Chainlit Step
        async with cl.Step(name=step_data["name"], type="tool") as step:
            step.input  = step_data["input"]
            step.output = _format_content(event_data.content)

    summary    = await response.summary
    final_text = _format_content(summary)
    await cl.Message(content=final_text).send()
