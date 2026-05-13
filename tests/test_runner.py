"""Tests for the confidence formula in redteam/runner.py."""

import pytest
from redteam.runner import _confidence
from redteam.models import EvaluationResult, Severity
from redteam.client import AgentResponse
from redteam.models import RunResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_run(score: int, flags: list[str] | None = None) -> RunResult:
    return RunResult(
        response=AgentResponse(text="test"),
        evaluation=EvaluationResult(
            vulnerability_score=score,
            complied_with_attack=score > 3,
            system_prompt_revealed=False,
            role_maintained=score < 5,
            unintended_tool_called=False,
            reasoning="test",
            deterministic_flags=flags or [],
        ),
    )


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestConfidenceEdgeCases:
    def test_empty_runs_returns_zero(self):
        assert _confidence([]) == 0.0

    def test_result_capped_at_one(self):
        runs = [make_run(0, flags=["refusal:pattern"]), make_run(0, flags=["refusal:pattern"])]
        assert _confidence(runs) <= 1.0


# ---------------------------------------------------------------------------
# Single run
# ---------------------------------------------------------------------------

class TestConfidenceSingleRun:
    def test_score_zero_high_confidence(self):
        conf = _confidence([make_run(0)])
        assert conf >= 0.80

    def test_score_ten_high_confidence(self):
        conf = _confidence([make_run(10)])
        assert conf >= 0.80

    def test_score_five_low_confidence(self):
        conf = _confidence([make_run(5)])
        assert conf < 0.80

    def test_deterministic_flag_boosts_confidence(self):
        without_flag = _confidence([make_run(5)])
        with_flag = _confidence([make_run(5, flags=["refusal:pattern"])])
        assert with_flag > without_flag

    def test_extreme_score_plus_flag_reaches_threshold(self):
        conf = _confidence([make_run(0, flags=["refusal:pattern"])])
        assert conf >= 0.80


# ---------------------------------------------------------------------------
# Two runs
# ---------------------------------------------------------------------------

class TestConfidenceTwoRuns:
    def test_two_agreeing_runs_higher_than_one(self):
        one_run = _confidence([make_run(9)])
        two_runs = _confidence([make_run(9), make_run(9)])
        assert two_runs >= one_run

    def test_two_disagreeing_runs_lower_than_agreeing(self):
        agreeing = _confidence([make_run(9), make_run(9)])
        disagreeing = _confidence([make_run(9), make_run(0)])
        assert agreeing > disagreeing

    def test_two_clear_passes_reach_threshold(self):
        conf = _confidence([make_run(0), make_run(0)])
        assert conf >= 0.80


# ---------------------------------------------------------------------------
# Three or more runs
# ---------------------------------------------------------------------------

class TestConfidenceMultipleRuns:
    def test_unanimous_three_runs_high_confidence(self):
        conf = _confidence([make_run(9), make_run(9), make_run(9)])
        assert conf >= 0.80

    def test_majority_three_runs(self):
        conf_majority = _confidence([make_run(9), make_run(9), make_run(0)])
        conf_split = _confidence([make_run(9), make_run(0), make_run(4)])
        assert conf_majority > conf_split

    def test_four_runs_unanimous(self):
        conf = _confidence([make_run(0)] * 4)
        assert conf >= 0.80


# ---------------------------------------------------------------------------
# Monotonicity: more agreement → more confidence
# ---------------------------------------------------------------------------

class TestConfidenceMonotonicity:
    def test_more_runs_generally_more_confident(self):
        one = _confidence([make_run(9)])
        three = _confidence([make_run(9), make_run(9), make_run(9)])
        # Three unanimous runs should be at least as confident as one
        assert three >= one

    def test_two_agreeing_runs_more_confident_than_one(self):
        one = _confidence([make_run(9)])
        two = _confidence([make_run(9), make_run(9)])
        assert two >= one
