"""Tests for redteam/report.py — JSON serialization and structure."""

import json
import pytest
from pathlib import Path
from redteam.client import AgentResponse
from redteam.models import (
    Attack, AttackCategory, AttackGoal, AttackResult,
    EvaluationResult, RedTeamReport, RunResult,
)
from redteam.report import save_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_attack(id: str = "test_001") -> Attack:
    return Attack(
        id=id,
        category=AttackCategory.DIRECT_INJECTION,
        goal=AttackGoal.BREAK_ROLE,
        name="Test Attack",
        payload="test payload",
    )


def make_run(score: int) -> RunResult:
    return RunResult(
        response=AgentResponse(text="agent response"),
        evaluation=EvaluationResult(
            vulnerability_score=score,
            complied_with_attack=score > 5,
            system_prompt_revealed=False,
            role_maintained=score <= 5,
            unintended_tool_called=False,
            reasoning="test reasoning",
        ),
    )


def make_report(scores: list[int]) -> RedTeamReport:
    results = [
        AttackResult(attack=make_attack(f"test_{i:03d}"), runs=[make_run(s)])
        for i, s in enumerate(scores)
    ]
    return RedTeamReport(
        agent_url="http://localhost:2024",
        assistant_id="agent",
        total_attacks=len(results),
        results=results,
    )


# ---------------------------------------------------------------------------
# save_json
# ---------------------------------------------------------------------------

class TestSaveJson:
    def test_creates_file(self, tmp_path):
        report = make_report([0, 9])
        path = save_json(report, output_dir=str(tmp_path))
        assert path.exists()

    def test_filename_starts_with_report(self, tmp_path):
        report = make_report([0])
        path = save_json(report, output_dir=str(tmp_path))
        assert path.name.startswith("report_")
        assert path.suffix == ".json"

    def test_valid_json(self, tmp_path):
        report = make_report([0, 9])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        assert isinstance(data, dict)

    def test_top_level_fields(self, tmp_path):
        report = make_report([0, 9])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        assert data["agent_url"] == "http://localhost:2024"
        assert data["assistant_id"] == "agent"
        assert data["total_attacks"] == 2
        assert "overall_risk" in data
        assert "confirmed_vulnerabilities" in data
        assert "results" in data
        assert "timestamp" in data

    def test_results_count(self, tmp_path):
        report = make_report([0, 9, 4])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        assert len(data["results"]) == 3

    def test_result_structure(self, tmp_path):
        report = make_report([9])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        result = data["results"][0]
        assert "attack" in result
        assert "consensus_severity" in result
        assert "worst_severity" in result
        assert "avg_score" in result
        assert "vulnerability_confirmed" in result
        assert "runs" in result

    def test_attack_fields(self, tmp_path):
        report = make_report([0])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        attack = data["results"][0]["attack"]
        assert attack["id"] == "test_000"
        assert attack["name"] == "Test Attack"
        assert attack["category"] == "direct_injection"
        assert attack["goal"] == "break_role"

    def test_run_fields(self, tmp_path):
        report = make_report([7])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        run = data["results"][0]["runs"][0]
        assert run["vulnerability_score"] == 7
        assert "severity" in run
        assert "complied_with_attack" in run
        assert "system_prompt_revealed" in run
        assert "role_maintained" in run
        assert "unintended_tool_called" in run
        assert "reasoning" in run
        assert run["reasoning"] == "test reasoning"

    def test_confirmed_vulnerabilities_count(self, tmp_path):
        report = make_report([0, 0, 9, 9, 4])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        assert data["confirmed_vulnerabilities"] == len(report.confirmed_vulnerabilities)

    def test_ai_patches_included(self, tmp_path):
        report = make_report([9])
        patches = [{"attack_id": "test_000", "targeted_patch": "Add restriction X."}]
        path = save_json(report, output_dir=str(tmp_path), ai_patches=patches)
        data = json.loads(path.read_text())
        assert data["ai_patches"] == patches

    def test_ai_patches_empty_by_default(self, tmp_path):
        report = make_report([0])
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        assert data["ai_patches"] == []

    def test_creates_output_dir(self, tmp_path):
        new_dir = tmp_path / "nested" / "reports"
        report = make_report([0])
        path = save_json(report, output_dir=str(new_dir))
        assert new_dir.exists()
        assert path.exists()

    def test_utf8_content_preserved(self, tmp_path):
        report = make_report([0])
        report.results[0].runs[0].evaluation.reasoning = "Ελληνικό κείμενο"
        path = save_json(report, output_dir=str(tmp_path))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["results"][0]["runs"][0]["reasoning"] == "Ελληνικό κείμενο"
