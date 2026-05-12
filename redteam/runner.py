"""
Runner — orchestrates attack execution with consensus runs and early-exit.

Runs each attack up to `consensus_runs` times. If the first run produces a
confident PASS or CRITICAL verdict, the remaining runs are skipped (early-exit)
to save cost. A semaphore limits concurrent agent calls so we don't overwhelm
the LangGraph dev server.
"""

from __future__ import annotations

import asyncio
from collections import Counter

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from redteam.attacks.competing_objectives import get_attacks as co_attacks
from redteam.attacks.direct_injection import get_attacks as di_attacks
from redteam.attacks.encoding import get_attacks as en_attacks
from redteam.attacks.extraction import get_attacks as ex_attacks
from redteam.attacks.indirect_injection import get_attacks as ii_attacks
from redteam.attacks.payload_splitting import get_attacks as ps_attacks
from redteam.attacks.role_hijacking import get_attacks as rh_attacks
from redteam.attacks.virtualization import get_attacks as vi_attacks
from redteam.client import AgentClient
from redteam.evaluator import Evaluator
from redteam.models import Attack, AttackCategory, AttackResult, RedTeamReport, RunResult, Severity

console = Console()

ALL_MODULES: dict[AttackCategory, callable] = {
    AttackCategory.DIRECT_INJECTION:     di_attacks,
    AttackCategory.ROLE_HIJACKING:       rh_attacks,
    AttackCategory.EXTRACTION:           ex_attacks,
    AttackCategory.ENCODING:             en_attacks,
    AttackCategory.VIRTUALIZATION:       vi_attacks,
    AttackCategory.COMPETING_OBJECTIVES: co_attacks,
    AttackCategory.PAYLOAD_SPLITTING:    ps_attacks,
    AttackCategory.INDIRECT_INJECTION:   ii_attacks,
}


def load_attacks(categories: list[AttackCategory] | None = None) -> list[Attack]:
    """Load attacks for the given categories, or all if None."""
    selected = categories or list(ALL_MODULES.keys())
    attacks: list[Attack] = []
    for cat in selected:
        attacks.extend(ALL_MODULES[cat]())
    return attacks


class Runner:
    def __init__(
        self,
        client: AgentClient,
        evaluator: Evaluator,
        consensus_runs: int = 3,
        concurrency: int = 3,
    ):
        self._client = client
        self._evaluator = evaluator
        self._consensus_runs = consensus_runs
        self._semaphore = asyncio.Semaphore(concurrency)
        self._severity_counts: Counter[Severity] = Counter()

    async def run(
        self,
        attacks: list[Attack],
        progress: Progress,
        task_id: int,
    ) -> list[AttackResult]:
        tasks = [self._run_attack(attack, progress, task_id) for attack in attacks]
        return await asyncio.gather(*tasks)

    async def _run_attack(self, attack: Attack, progress: Progress, task_id: int) -> AttackResult:
        result = AttackResult(attack=attack)

        async with self._semaphore:
            for run_num in range(self._consensus_runs):
                response = await (
                    self._client.send_multi_turn(attack.payload)
                    if attack.is_multi_turn
                    else self._client.send(attack.payload)
                )
                evaluation = await self._evaluator.evaluate(attack, response)
                result.runs.append(RunResult(response=response, evaluation=evaluation))

                # Early-exit: confident PASS or CRITICAL — no need to run again
                if self._evaluator.should_run_again(evaluation) is False:
                    break

        # Update live severity tally
        sev = result.consensus_severity
        if sev != Severity.PASS:
            self._severity_counts[sev] += 1

        progress.advance(task_id)
        return result

    def severity_summary(self) -> Counter[Severity]:
        return self._severity_counts


async def run_session(
    client: AgentClient,
    evaluator: Evaluator,
    categories: list[AttackCategory] | None = None,
    consensus_runs: int = 3,
    concurrency: int = 3,
) -> RedTeamReport:
    """Top-level entry point. Runs all attacks and returns the full report."""
    attacks = load_attacks(categories)
    runner = Runner(client, evaluator, consensus_runs=consensus_runs, concurrency=concurrency)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
    )

    with Live(console=console, refresh_per_second=8):
        task_id = progress.add_task(
            f"Running {len(attacks)} attacks",
            total=len(attacks),
            status="",
        )
        progress.start()

        results = await runner.run(attacks, progress, task_id)

        progress.stop()

    # Print live severity tally
    counts = runner.severity_summary()
    if counts:
        _print_tally(counts)

    return RedTeamReport(
        agent_url=client._url,
        assistant_id=client._assistant_id,
        total_attacks=len(attacks),
        results=results,
    )


def _print_tally(counts: Counter[Severity]) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold orange3",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "dim yellow",
    }
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if counts[sev]:
            table.add_row(
                f"[{severity_colors[sev]}]{sev.value}[/]",
                f"[{severity_colors[sev]}]{counts[sev]} finding(s)[/]",
            )
    console.print(Panel(table, title="[bold]Findings so far[/]", border_style="dim"))
