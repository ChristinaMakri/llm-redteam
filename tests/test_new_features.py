"""Tests for features added after initial test suite: CostTracker, patch validation, dry-run logic."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from redteam.client import AgentResponse, ToolCallInfo
from redteam.evaluator import CostTracker, Evaluator
from redteam.models import Attack, AttackCategory, AttackGoal, EvaluationResult
from redteam.patcher import _validate_patches
from redteam.report import save_json
from redteam.models import AttackResult, RedTeamReport, RunResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_attack() -> Attack:
    return Attack(
        id="test_001",
        category=AttackCategory.DIRECT_INJECTION,
        goal=AttackGoal.BREAK_ROLE,
        name="Test Attack",
        payload="test payload",
    )


def make_run(score: int) -> RunResult:
    return RunResult(
        response=AgentResponse(text="response"),
        evaluation=EvaluationResult(
            vulnerability_score=score,
            complied_with_attack=score > 5,
            system_prompt_revealed=False,
            role_maintained=score <= 5,
            unintended_tool_called=False,
            reasoning="test",
        ),
    )


# ---------------------------------------------------------------------------
# CostTracker
# ---------------------------------------------------------------------------

class TestCostTracker:
    def test_initial_state(self):
        tracker = CostTracker()
        assert tracker.tier1_exits == 0
        assert tracker.tier2_calls == 0
        assert tracker.tier3_calls == 0
        assert tracker.total_llm_calls == 0

    def test_total_llm_calls_sums_tier2_and_tier3(self):
        tracker = CostTracker(tier1_exits=10, tier2_calls=7, tier3_calls=3)
        assert tracker.total_llm_calls == 10

    def test_tier1_not_counted_as_llm_call(self):
        tracker = CostTracker(tier1_exits=50, tier2_calls=0, tier3_calls=0)
        assert tracker.total_llm_calls == 0

    def test_increments(self):
        tracker = CostTracker()
        tracker.tier1_exits += 1
        tracker.tier2_calls += 2
        tracker.tier3_calls += 1
        assert tracker.total_llm_calls == 3


class TestEvaluatorTracking:
    def test_evaluator_has_tracker(self):
        evaluator = Evaluator()
        assert hasattr(evaluator, "tracker")
        assert isinstance(evaluator.tracker, CostTracker)

    def test_tracker_starts_empty(self):
        evaluator = Evaluator()
        assert evaluator.tracker.total_llm_calls == 0
        assert evaluator.tracker.tier1_exits == 0

    async def test_tier1_exit_counted_on_clean_refusal(self):
        evaluator = Evaluator()
        attack = make_attack()
        response = AgentResponse(text="I'm not able to help with that.")
        result = await evaluator.evaluate(attack, response)
        assert evaluator.tracker.tier1_exits == 1
        assert evaluator.tracker.tier2_calls == 0

    async def test_error_response_not_counted(self):
        evaluator = Evaluator()
        attack = make_attack()
        response = AgentResponse(text="", error="Timeout")
        await evaluator.evaluate(attack, response)
        assert evaluator.tracker.tier1_exits == 0
        assert evaluator.tracker.tier2_calls == 0

    async def test_tool_call_counted_as_tier1(self):
        evaluator = Evaluator()
        attack = make_attack()
        response = AgentResponse(
            text="Processing...",
            tool_calls=[ToolCallInfo(name="transfer_funds", args={})],
        )
        await evaluator.evaluate(attack, response)
        assert evaluator.tracker.tier1_exits == 1
        assert evaluator.tracker.tier2_calls == 0


# ---------------------------------------------------------------------------
# _validate_patches
# ---------------------------------------------------------------------------

class TestValidatePatches:
    def test_existing_file_no_warning(self, tmp_path):
        (tmp_path / "prompts").mkdir()
        (tmp_path / "prompts" / "system.md").write_text("# System prompt")
        patches = [{"attack_id": "t001", "file": "prompts/system.md", "patch_text": "Add this."}]
        result = _validate_patches(patches, str(tmp_path))
        assert "warning" not in result[0]

    def test_missing_file_adds_warning(self, tmp_path):
        patches = [{"attack_id": "t001", "file": "prompts/nonexistent.md", "patch_text": "Add this."}]
        result = _validate_patches(patches, str(tmp_path))
        assert "warning" in result[0]
        assert "nonexistent.md" in result[0]["warning"]

    def test_patch_without_file_key_unchanged(self, tmp_path):
        patches = [{"attack_id": "t001", "targeted_patch": "Add restriction X."}]
        result = _validate_patches(patches, str(tmp_path))
        assert "warning" not in result[0]
        assert result[0] == patches[0]

    def test_multiple_patches_validated_independently(self, tmp_path):
        (tmp_path / "exists.md").write_text("content")
        patches = [
            {"file": "exists.md", "patch_text": "ok"},
            {"file": "missing.md", "patch_text": "not ok"},
        ]
        result = _validate_patches(patches, str(tmp_path))
        assert "warning" not in result[0]
        assert "warning" in result[1]

    def test_patches_not_dropped_when_file_missing(self, tmp_path):
        patches = [{"file": "missing.md", "patch_text": "keep me"}]
        result = _validate_patches(patches, str(tmp_path))
        assert len(result) == 1
        assert result[0]["patch_text"] == "keep me"

    def test_empty_file_field_treated_as_no_file(self, tmp_path):
        patches = [{"file": "", "patch_text": "something"}]
        result = _validate_patches(patches, str(tmp_path))
        assert "warning" not in result[0]


# ---------------------------------------------------------------------------
# save_json with cost field
# ---------------------------------------------------------------------------

class TestSaveJsonWithCost:
    def _make_report(self) -> RedTeamReport:
        result = AttackResult(attack=make_attack(), runs=[make_run(0)])
        return RedTeamReport(
            agent_url="http://localhost:2024",
            assistant_id="agent",
            total_attacks=1,
            results=[result],
        )

    def test_cost_included_in_json(self, tmp_path):
        tracker = CostTracker(tier1_exits=5, tier2_calls=3, tier3_calls=1)
        path = save_json(self._make_report(), output_dir=str(tmp_path), cost=tracker)
        data = json.loads(path.read_text())
        assert data["cost"]["tier1_exits"] == 5
        assert data["cost"]["tier2_calls"] == 3
        assert data["cost"]["tier3_calls"] == 1
        assert data["cost"]["total_llm_calls"] == 4

    def test_cost_none_when_not_provided(self, tmp_path):
        path = save_json(self._make_report(), output_dir=str(tmp_path))
        data = json.loads(path.read_text())
        assert data["cost"] is None
