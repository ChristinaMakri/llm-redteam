"""
AI-powered patch generator.

With --repo-path: reads the agent's actual prompt files, generates file-specific
patches — exact file, exact location in that file, exact text to insert.

Without --repo-path: generates targeted generic suggestions based on
vulnerability details only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from redteam.evaluator import _build_judge
from redteam.models import AttackResult, RedTeamReport


_PATCHER_SYSTEM = (
    "You are a security consultant specializing in LLM prompt hardening. "
    "Respond ONLY with a JSON object — no extra text."
)

_PATCHER_PROMPT_WITH_REPO = """\
A red-team test confirmed the following vulnerabilities in an AI agent.
You have access to the agent's actual prompt files and configuration below.

For each vulnerability, produce a file-specific patch: identify the exact file
to edit, where in that file to insert the change (reference the actual
section/tag/heading present in the file), and the exact text to add — written
in the same style and language as the surrounding content.

If multiple vulnerabilities map to the same file and location, merge them into
one patch entry.

Agent files:
{repo_context}

Confirmed vulnerabilities:
{findings}

Return JSON:
{{
  "patches": [
    {{
      "attack_id": "<id or comma-separated ids if merged>",
      "attack_name": "<name or merged names>",
      "file": "<relative path to the file to edit>",
      "location": "<where in the file — reference actual section name, XML tag, or heading>",
      "patch_text": "<exact text to insert, preserving the file's style>",
      "reasoning": "<one sentence: why this location fixes the vulnerability>"
    }}
  ]
}}"""

_PATCHER_PROMPT_GENERIC = """\
A red-team test confirmed the following vulnerabilities in an AI agent.
For each vulnerability, write a targeted system prompt addition (2-4 sentences,
imperative voice) that directly addresses the specific failure mode observed.
Be concrete: reference the exact framing technique or trigger that worked.

Confirmed vulnerabilities:
{findings}

Return JSON:
{{
  "patches": [
    {{
      "attack_id": "<id>",
      "attack_name": "<name>",
      "targeted_patch": "<2-4 sentence system prompt addition>"
    }}
  ]
}}"""


# ---------------------------------------------------------------------------
# Repo discovery
# ---------------------------------------------------------------------------

_SKIP_DIRS = {".venv", "__pycache__", "node_modules", ".git", "sandbox", "mynbg-sandbox"}
_MAX_PER_FILE = 5000
_MAX_TOTAL = 18000


def _discover_repo_context(repo_path: str) -> dict[str, str]:
    """
    Scan the repo for everything the agent uses: prompt files, tool definitions,
    config, and structural files. Returns {relative_path: truncated_content}.

    Priority order (each group fills remaining budget):
      1. langgraph.json — graph structure
      2. All .md files outside skip dirs — prompts, docs
      3. Python files with "prompt" or "tool" in their path — tool/prompt definitions
      4. JSON config files (agent_config, settings) outside skip dirs
    """
    root = Path(repo_path)
    found: dict[str, str] = {}
    total = 0

    def _skip(p: Path) -> bool:
        return any(part in _SKIP_DIRS for part in p.parts)

    def _add(path: Path, limit: int = _MAX_PER_FILE) -> None:
        nonlocal total
        if total >= _MAX_TOTAL:
            return
        budget = min(limit, _MAX_TOTAL - total)
        text = path.read_text(encoding="utf-8", errors="replace")[:budget]
        rel = str(path.relative_to(root))
        found[rel] = text
        total += len(text)

    # 1. langgraph.json
    lj = root / "langgraph.json"
    if lj.exists():
        _add(lj, limit=1500)

    # 2. All .md files (prompts, system prompts, guides)
    for f in sorted(root.rglob("*.md")):
        if _skip(f):
            continue
        _add(f)

    # 3. Python files with "prompt" or "tool" in their path
    for f in sorted(root.rglob("*.py")):
        if _skip(f):
            continue
        parts_lower = f.as_posix().lower()
        if "prompt" in parts_lower or "tool" in parts_lower:
            _add(f)

    # 4. JSON config files (agent_config, settings)
    for f in sorted(root.rglob("*.json")):
        if _skip(f):
            continue
        name = f.stem.lower()
        if any(k in name for k in ("agent_config", "settings", "config")):
            _add(f, limit=3000)

    return found


def _format_repo_context(context: dict[str, str]) -> str:
    return "\n\n".join(f"=== {path} ===\n{content}" for path, content in context.items())


# ---------------------------------------------------------------------------
# Findings formatter
# ---------------------------------------------------------------------------

def _format_findings(confirmed: list[AttackResult]) -> str:
    lines = []
    for r in confirmed:
        worst = max(r.runs, key=lambda x: x.evaluation.vulnerability_score)
        lines.append(
            f"- ID: {r.attack.id}\n"
            f"  Name: {r.attack.name}\n"
            f"  Category: {r.attack.category.value}\n"
            f"  Goal: {r.attack.goal.value}\n"
            f"  Severity: {r.consensus_severity.value}  |  Score: {r.avg_score:.1f}/10\n"
            f"  What happened: {worst.evaluation.reasoning}"
        )
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def generate_ai_patches(
    report: RedTeamReport,
    repo_path: str | None = None,
) -> list[dict]:
    """
    Generate targeted patch suggestions for confirmed vulnerabilities.

    With repo_path: reads actual prompt files, returns file-specific patches
    (file, location, patch_text).

    Without repo_path: returns generic targeted suggestions (targeted_patch).
    Falls back to empty list on any error — caller shows generic patches.
    """
    confirmed = report.confirmed_vulnerabilities
    if not confirmed:
        return []

    findings_text = _format_findings(confirmed)

    if repo_path:
        repo_context = _discover_repo_context(repo_path)
        prompt = _PATCHER_PROMPT_WITH_REPO.format(
            repo_context=_format_repo_context(repo_context),
            findings=findings_text,
        )
    else:
        prompt = _PATCHER_PROMPT_GENERIC.format(findings=findings_text)

    judge = _build_judge(full_model=True, max_tokens=1500)

    try:
        result = await judge.ainvoke([
            {"role": "system", "content": _PATCHER_SYSTEM},
            {"role": "user", "content": prompt},
        ])
    except Exception:
        return []

    raw = result.content.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)

    try:
        data = json.loads(raw)
        return data.get("patches", [])
    except (json.JSONDecodeError, AttributeError):
        return []
