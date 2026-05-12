"""
llm-redteam — CLI entry point.

Usage examples:

  # Run all attacks using settings from .env
  uv run python main.py

  # Point at a specific agent
  uv run python main.py --agent-url http://localhost:2024 --assistant-id my-agent

  # Load credentials from an existing agent project's .env
  uv run python main.py --env-file ../agents-customer-subscriptions/.env

  # Run only specific attack categories
  uv run python main.py --categories direct_injection extraction encoding

  # Adaptive confidence threshold (default 0.80, higher = more thorough)
  uv run python main.py --confidence 0.90

  # AI-generated patches based on actual agent prompt files
  uv run python main.py --ai-patches --repo-path ../my-agent/

  # Full run with custom output directory
  uv run python main.py --output reports/
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from rich.console import Console

from redteam.client import AgentClient
from redteam.evaluator import Evaluator
from redteam.models import AttackCategory
from redteam.patcher import generate_ai_patches
from redteam.report import print_report, save_json
from redteam.runner import run_session

app = typer.Typer(add_completion=False, pretty_exceptions_show_locals=False)
console = Console()

VALID_CATEGORIES = [c.value for c in AttackCategory]


@app.command()
def main(
    env_file: Annotated[
        str | None,
        typer.Option("--env-file", help="Path to .env file (default: .env in current directory)"),
    ] = None,
    agent_url: Annotated[
        str | None,
        typer.Option("--agent-url", help="LangGraph dev server URL (overrides AGENT_URL in .env)"),
    ] = None,
    assistant_id: Annotated[
        str | None,
        typer.Option("--assistant-id", help="LangGraph assistant/graph ID (overrides AGENT_ASSISTANT_ID in .env)"),
    ] = None,
    categories: Annotated[
        list[str] | None,
        typer.Option(
            "--categories",
            help=f"Attack categories to run. Valid values: {', '.join(VALID_CATEGORIES)}",
        ),
    ] = None,
    confidence: Annotated[
        float,
        typer.Option("--confidence", min=0.5, max=1.0, help="Stop running an attack when confidence reaches this threshold (default 0.80). Higher = more thorough, lower = cheaper."),
    ] = 0.80,
    max_runs: Annotated[
        int,
        typer.Option("--max-runs", min=1, max=8, help="Hard cap on runs per attack regardless of confidence (default 4)."),
    ] = 4,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", min=1, max=10, help="Max concurrent agent calls (default 3)"),
    ] = 3,
    output: Annotated[
        str,
        typer.Option("--output", help="Directory to save the JSON report (default: reports/)"),
    ] = "reports",
    ai_patches: Annotated[
        bool,
        typer.Option("--ai-patches/--no-ai-patches", help="Generate targeted patch suggestions using the LLM (costs extra tokens)"),
    ] = False,
    repo_path: Annotated[
        str | None,
        typer.Option("--repo-path", help="Path to the agent's repo — enables file-specific patches against actual prompt files"),
    ] = None,
) -> None:
    # Load environment
    env_path = Path(env_file) if env_file else Path(".env")
    if env_path.exists():
        load_dotenv(env_path, override=True)
        console.print(f"[dim]Loaded env from {env_path}[/]")
    else:
        console.print(f"[yellow]Warning: {env_path} not found — relying on shell environment.[/]")

    # Validate categories
    selected_categories: list[AttackCategory] | None = None
    if categories:
        invalid = [c for c in categories if c not in VALID_CATEGORIES]
        if invalid:
            console.print(f"[red]Unknown categories: {', '.join(invalid)}[/]")
            console.print(f"Valid options: {', '.join(VALID_CATEGORIES)}")
            raise typer.Exit(1)
        selected_categories = [AttackCategory(c) for c in categories]

    # Build client
    client = AgentClient.from_env()
    if agent_url:
        client._url = agent_url
    if assistant_id:
        client._assistant_id = assistant_id

    evaluator = Evaluator()

    console.print()
    console.print(f"  Target agent : [cyan]{client._url}[/]  /  [cyan]{client._assistant_id}[/]")
    console.print(f"  Categories   : {', '.join(c.value for c in (selected_categories or list(AttackCategory)))}")
    console.print(f"  Confidence   : {confidence:.0%} threshold  |  max {max_runs} runs  |  concurrency: {concurrency}")
    console.print()

    # Run everything in a single event loop
    report, patches = asyncio.run(
        _run_all(
            client=client,
            evaluator=evaluator,
            selected_categories=selected_categories,
            confidence=confidence,
            max_runs=max_runs,
            concurrency=concurrency,
            ai_patches=ai_patches,
            repo_path=repo_path,
        )
    )

    # Print terminal report
    print_report(report, ai_patches=patches or None)

    # Save JSON
    path = save_json(report, output_dir=output, ai_patches=patches or None)
    console.print(f"\n[dim]Full report saved to: {path}[/]")

    if any(r.vulnerability_confirmed for r in report.results):
        raise typer.Exit(2)


async def _run_all(
    client: AgentClient,
    evaluator: Evaluator,
    selected_categories,
    confidence: float,
    max_runs: int,
    concurrency: int,
    ai_patches: bool,
    repo_path: str | None,
):
    report = await run_session(
        client=client,
        evaluator=evaluator,
        categories=selected_categories,
        confidence_threshold=confidence,
        max_runs=max_runs,
        concurrency=concurrency,
    )

    patches: list[dict] = []
    if ai_patches and report.confirmed_vulnerabilities:
        if repo_path:
            console.print(f"[dim]Generating file-specific patches from {repo_path} ...[/]")
        else:
            console.print("[dim]Generating targeted patch suggestions...[/]")
        patches = await generate_ai_patches(report, repo_path=repo_path)
        if not patches:
            console.print("[yellow]AI patch generation failed — falling back to generic patches.[/]")

    return report, patches


if __name__ == "__main__":
    app()
