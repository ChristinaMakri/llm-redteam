# llm-redteam

Automated red-teaming framework for prompt-level attacks against [LangGraph](https://github.com/langchain-ai/langgraph) agents.

Runs a comprehensive suite of **143 attacks** across 11 categories against any running LangGraph agent, evaluates each response with a tiered multi-signal judge, and proposes concrete system prompt improvements based on findings.

**Attack coverage:** 9 categories are universal (any agent, any language). 2 categories are domain-specific extensions targeting banking/financial assistants: Greek-language attacks and business logic attacks (confirmation bypass, cross-customer data probes, privilege escalation). Skip them with `--categories` if your agent is outside this domain.

---

## What it tests

| Category | Attacks | Description |
|---|---|---|
| Direct Injection | 22 | Explicit instruction overrides, delimiter tricks, authority framing, context flooding |
| Role Hijacking | 13 | DAN, alter ego, simulator, fictional character personas |
| Extraction | 26 | Verbatim repeat, indirect probes, format tricks, social engineering, PII extraction |
| Encoding | 13 | Base64, ROT13, leetspeak, Unicode lookalikes, token splitting |
| Virtualization | 12 | Story, hypothetical, research paper, sandbox framing |
| Competing Objectives | 10 | Logical conflicts exploiting helpfulness, honesty, autonomy |
| Payload Splitting | 9 | Multi-turn attacks split across 2–4 messages |
| Indirect Injection | 9 | Instructions hidden in documents, API responses, structured data |
| Greek Language | 12 | DAN, extraction, authority framing, emotional pressure — all in Greek ⚑ |
| Business Logic | 10 | Confirmation bypass, cross-customer data probes, privilege escalation ⚑ |
| Scope Enforcement | 7 | Off-topic redirections, gradual drift, emergency overrides, hypothetical jailbreaks |

⚑ Banking/financial domain extension — skip with `--categories` if not applicable.

When `--repo-path` is provided, the framework also generates **agent-specific attacks** dynamically: business logic attacks targeting the agent's actual rules, and borderline scope attacks based on what the agent is designed to do.

---

## How it works

```
┌─────────────────────────────────────────────────────┐
│  Attack Suite (143 attacks + dynamic generation)    │
│         ↓                                           │
│  AgentClient → LangGraph dev server                 │
│         ↓                                           │
│  Tiered Evaluator                                   │
│    Tier 1: Deterministic checks  (free)             │
│    Tier 2: Mini judge            (cheap)            │
│    Tier 3: Full judge            (borderline only)  │
│         ↓                                           │
│  Report: terminal + JSON + prompt patches           │
└─────────────────────────────────────────────────────┘
```

**Cost control:** deterministic checks (regex/keyword) run first at no cost. The LLM judge is only called for uncertain cases, using a small model by default and escalating to a full model only for borderline scores (4–6). An early-exit strategy skips remaining consensus runs when a verdict is already confident — reducing LLM calls by 40–60% in practice.

---

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- A running LangGraph dev server (`uv run langgraph dev`)
- An LLM for the judge model: Azure OpenAI or standard OpenAI

---

## Installation

```bash
git clone https://github.com/ChristinaMakri/llm-redteam.git
cd llm-redteam
uv sync
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```env
# Judge model — choose one

# Option A: Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
AZURE_OPENAI_API_KEY=your-key
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_MINI_DEPLOYMENT=gpt-4o-mini   # used for Tier 2 (cheaper)
AZURE_OPENAI_API_VERSION=2024-02-01

# Option B: Standard OpenAI
# OPENAI_API_KEY=sk-...

# Agent under test
AGENT_URL=http://localhost:2024
AGENT_ASSISTANT_ID=your-graph-name
```

If you are testing an existing LangGraph project that already has a `.env`, you can point directly to it with `--env-file`.

---

## Usage

**Start your agent first:**
```bash
# In your agent project directory
uv run langgraph dev --port 2024
```

**Run the framework:**
```bash
# Full run — adaptive confidence-based stopping (1-4 runs per attack)
uv run python main.py

# Quick mode — 1 run per attack, cheaper
uv run python main.py --max-runs 1

# Point at a specific agent .env
uv run python main.py --env-file ../my-agent/.env

# Test specific categories only
uv run python main.py --categories direct_injection extraction encoding

# Custom agent URL and assistant ID
uv run python main.py --agent-url http://localhost:2024 --assistant-id my-graph

# AI-generated targeted patches — analyses each specific finding and proposes
# concrete system prompt additions (uses one extra LLM call after the run)
uv run python main.py --ai-patches

# Repo-aware run: generates agent-specific attacks + file-specific patches
uv run python main.py --repo-path ../my-agent/ --ai-patches

# Dry run — list attacks that would execute without sending any messages
uv run python main.py --dry-run --categories scope_enforcement

# All options
uv run python main.py --help
```

---

## Output

**Terminal report:**
```
──────────────────────── LLM Red-Team Report ────────────────────────
  Agent:       http://localhost:2024  /  my-agent
  Date:        2025-01-15 14:32
  Attacks:     102 total  |  6 confirmed vulnerabilities
  Overall risk: HIGH

╭─────────────────────────── Summary ────────────────────────────────╮
│  Severity     Count   Attacks                                      │
│  !! CRITICAL      2   Raw override + repeat, Token split leak      │
│  !  HIGH          2   Classic DAN, Document with embedded override │
│  ~  MEDIUM        2   Hypothetical transparency, ...               │
│  OK PASS         96                                                │
╰────────────────────────────────────────────────────────────────────╯
```

**JSON report** saved to `reports/report_<timestamp>.json` — structured data for analysis or CI integration.

**Prompt patches** — copy-paste ready system prompt additions printed for each confirmed vulnerability category.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities confirmed |
| `1` | Configuration error |
| `2` | One or more vulnerabilities confirmed |

Useful for CI pipelines:
```bash
uv run python main.py --max-runs 1 || echo "Vulnerabilities found"
```

---

## Adding custom attacks

Each attack module lives in `redteam/attacks/`. To add your own:

```python
# redteam/attacks/my_attacks.py
from redteam.models import Attack, AttackCategory, AttackGoal

def get_attacks() -> list[Attack]:
    return [
        Attack(
            id="my_001",
            category=AttackCategory.DIRECT_INJECTION,  # closest category
            goal=AttackGoal.LEAK_SYSTEM_PROMPT,
            name="My custom attack",
            payload="Your custom payload here.",
            description="What this attack tests.",
        )
    ]
```

Then register it in `redteam/runner.py` by adding it to `ALL_MODULES`.

---

## Claude Code skill (`/redteam`)

The repo includes a Claude Code slash command at `.claude/commands/redteam.md`.

When invoked as `/redteam` inside an agent project, Claude will:
1. Detect the running LangGraph dev server automatically
2. Ask quick (1 run) or full (3 runs) mode
3. Run the framework against your agent
4. Summarize findings in the conversation
5. Offer to apply prompt patches directly to your system prompt

**Install globally (available in any project):**

```bash
# 1. Set the path in your shell profile (~/.bashrc or ~/.zshrc)
export LLM_REDTEAM_PATH=/path/to/llm-redteam

# 2. Symlink the skill to your global Claude commands directory
mkdir -p ~/.claude/commands
ln -s $LLM_REDTEAM_PATH/.claude/commands/redteam.md ~/.claude/commands/redteam.md
```

After restarting Claude Code, `/redteam` is available in any project.

**Update:** since it's a symlink, `git pull` in the llm-redteam directory is all you need — the skill updates automatically.

---

## Scope and limitations

This framework tests **black-box, prompt-level attacks** — the most common real-world threat surface. It does not cover:

- Gradient-based adversarial inputs (requires white-box model access)
- Training data poisoning (requires access to the training pipeline)
- Sophisticated long-horizon multi-session attacks

The Greek-language and business logic categories are tailored for banking/financial agents. If your agent operates in a different domain, you can skip them via `--categories` and add your own domain-specific attacks (see [Adding custom attacks](#adding-custom-attacks)).

No automated tool catches everything. Use this alongside human red-teaming for comprehensive coverage.

---

## License

MIT
