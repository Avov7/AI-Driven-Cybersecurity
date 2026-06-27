# Password Security Agent

## 1. Agent Name

**password-security-agent**

---

## 2. Agent Purpose

The purpose of this agent is to help users evaluate the security of their passwords
and guide them toward better password practices.

The agent is designed to:
- accept a password from the user and analyse its strength,
- check whether the password is a well-known weak or commonly used password,
- return targeted security advice based on the evaluation result.

**Technical task specification (used as the agent system prompt basis):**

> You are a Password Security Agent. Evaluate user-supplied passwords for
> strength and common-password exposure using structured tools, and provide
> clear, actionable security advice based on the tool results.

This agent is intentionally simple and operates entirely in memory. No passwords
are stored, logged, or transmitted beyond the local tool functions.

---

## 3. Agent Tools

This agent uses **three tools**.

---

### 3.1 `check_password_strength(password)`

**Purpose:**
Analyses the structural properties of a password and returns a strength rating.

**Input:**
- `password` (str) — the password string to evaluate.

**Output (structured dict):**
| Field | Description |
|---|---|
| `password_length` | Number of characters |
| `has_uppercase` | True if at least one uppercase letter is present |
| `has_lowercase` | True if at least one lowercase letter is present |
| `has_digits` | True if at least one digit is present |
| `has_special_chars` | True if at least one non-alphanumeric character is present |
| `character_variety_score` | Fraction of character-type criteria met (e.g. `3/4`) |
| `estimated_entropy_bits` | Estimated bit entropy based on length × log₂(charset size) |
| `strength_label` | One of: `Weak`, `Fair`, `Strong`, `Very Strong` |

**Design principle:**
The tool returns all computed metrics so the agent can explain each dimension
of strength individually, rather than just giving a score.

---

### 3.2 `check_common_password(password)`

**Purpose:**
Checks whether the given password appears in a curated list of the most
commonly used and easily guessed passwords.

**Input:**
- `password` (str) — the password to look up.

**Output (structured dict):**
| Field | Description |
|---|---|
| `password_is_common` | True if found in the common-password list |
| `checked_against_list_size` | Number of passwords in the reference list |
| `sample_common_passwords` | A few examples from the list for context |
| `risk_note` | Plain-text explanation of the risk level |

**Design principle:**
Even a technically complex password can be common (e.g., `Passw0rd`). This
tool catches that case independently of the strength calculation.

---

### 3.3 `get_security_tips(topic)`

**Purpose:**
Returns a structured list of security recommendations for a given topic.

**Input:**
- `topic` (str) — must be one of: `length`, `complexity`, `uniqueness`, `general`.

**Output (structured dict):**
| Field | Description |
|---|---|
| `topic` | The requested topic |
| `tips` | List of actionable tip strings |
| `tip_count` | Number of tips returned |

**Design principle:**
The agent calls this tool after detecting a weak dimension in the password
(e.g., if length is too short, it requests `length` tips). This keeps
the agent's advice grounded in tool output rather than free-form generation.

---

## 4. Example Interaction

```
User: Check the strength of the password: Summer2024!

Agent: [calls check_password_strength("Summer2024!")]
       [calls check_common_password("Summer2024!")]

Agent: Here is the analysis for the password you provided:

Strength Report:
  - Length: 11 characters
  - Has uppercase:    ✓
  - Has lowercase:    ✓
  - Has digits:       ✓
  - Has special chars: ✓  (the '!' character)
  - Character variety: 4/4
  - Estimated entropy: ~69.4 bits
  - Strength label:   Strong

Common Password Check:
  - Not found in the common password list. Good.

Overall: This is a **Strong** password. It uses all four character types and
has decent length. To reach "Very Strong", consider extending it to 16+
characters — a passphrase like "Summer!Sun2024Bright" would be even better.
```

---

```
User: Is "123456" a common password?

Agent: [calls check_common_password("123456")]
       [calls get_security_tips("general")]

Agent: Yes — "123456" is one of the most commonly used passwords in the world
and appears at the top of every attacker's dictionary list.

It should never be used as a real password. Here are some general security tips:

  • Enable two-factor authentication (2FA) wherever possible.
  • Never share your password via email, chat, or phone.
  • Change passwords immediately if you suspect a breach.
  • Avoid storing passwords in plain-text files or browser auto-fill on shared devices.
```

---

```
User: Give me tips on creating a long password.

Agent: [calls get_security_tips("length")]

Agent: Here are some tips about password length:

  1. Use at least 12 characters; 16 or more is ideal.
  2. Longer passwords are exponentially harder to crack.
  3. Consider using a passphrase: 4+ random words joined together.
     For example: "CloudPurpleDeskLamp42" is long, memorable, and strong.
```

---

## 5. Tool–Agent Responsibility Split

| Responsibility | Handled by |
|---|---|
| Calculating entropy and character checks | Tool (`check_password_strength`) |
| Looking up the common-password list | Tool (`check_common_password`) |
| Retrieving tip text | Tool (`get_security_tips`) |
| Deciding which tools to call and in what order | Agent (LLM) |
| Interpreting and explaining results in plain language | Agent (LLM) |
| Recommending follow-up actions | Agent (LLM) |

The agent never guesses strength scores. All numerical values and labels
come from tool return values.

---

## 6. Implementation Notes

- Framework: **AG2** (`ConversableAgent`) with the `functions=[...]` tool pattern.
- UI: **Chainlit** — tool calls are displayed as expandable **Steps**.
- All data is in-memory; no external APIs or file I/O are required.
- The common-password list is a hardcoded representative sample (36 entries).
