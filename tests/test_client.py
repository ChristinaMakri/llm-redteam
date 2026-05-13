"""Tests for message extraction in redteam/client.py."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from redteam.client import AgentClient, AgentResponse


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    c = AgentClient(url="http://localhost:9999", assistant_id="test")
    c._client = MagicMock()
    return c


def state_with(messages: list[dict]) -> dict:
    return {"values": {"messages": messages}}


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------

class TestTextExtraction:
    async def test_simple_string_content(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "human", "content": "hello"},
            {"type": "ai", "content": "I can help with your account."},
        ]))
        response = await client._extract_response("thread_1")
        assert response.text == "I can help with your account."

    async def test_list_content_blocks(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": [
                {"type": "text", "text": "Hello "},
                {"type": "text", "text": "world"},
            ]},
        ]))
        response = await client._extract_response("thread_1")
        assert "Hello" in response.text
        assert "world" in response.text

    async def test_ignores_non_text_content_blocks(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": [
                {"type": "tool_use", "text": ""},
                {"type": "text", "text": "Here is your balance."},
            ]},
        ]))
        response = await client._extract_response("thread_1")
        assert response.text == "Here is your balance."

    async def test_last_ai_message_wins(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": "First response."},
            {"type": "human", "content": "follow-up"},
            {"type": "ai", "content": "Second response."},
        ]))
        response = await client._extract_response("thread_1")
        assert response.text == "Second response."

    async def test_no_ai_message_returns_empty(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "human", "content": "hello"},
        ]))
        response = await client._extract_response("thread_1")
        assert response.text == ""

    async def test_empty_messages_returns_empty(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([]))
        response = await client._extract_response("thread_1")
        assert response.text == ""
        assert response.tool_calls == []


# ---------------------------------------------------------------------------
# Tool call extraction
# ---------------------------------------------------------------------------

class TestToolCallExtraction:
    async def test_single_tool_call(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": "", "tool_calls": [
                {"name": "get_subscriptions", "args": {"customer_id": "123"}},
            ]},
        ]))
        response = await client._extract_response("thread_1")
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].name == "get_subscriptions"
        assert response.tool_calls[0].args == {"customer_id": "123"}

    async def test_multiple_tool_calls(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": "", "tool_calls": [
                {"name": "get_subscriptions", "args": {}},
                {"name": "get_transactions", "args": {}},
            ]},
        ]))
        response = await client._extract_response("thread_1")
        assert len(response.tool_calls) == 2
        assert "get_subscriptions" in response.triggered_tools
        assert "get_transactions" in response.triggered_tools

    async def test_no_tool_calls(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": "Here is your info."},
        ]))
        response = await client._extract_response("thread_1")
        assert response.tool_calls == []
        assert response.triggered_tools == []

    async def test_tool_call_with_none_args_defaults_to_empty_dict(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": "", "tool_calls": [
                {"name": "some_tool", "args": None},
            ]},
        ]))
        response = await client._extract_response("thread_1")
        assert response.tool_calls[0].args == {}

    async def test_tool_call_without_name_is_ignored(self, client):
        client._client.threads.get_state = AsyncMock(return_value=state_with([
            {"type": "ai", "content": "", "tool_calls": [
                {"name": "", "args": {}},
            ]},
        ]))
        response = await client._extract_response("thread_1")
        assert response.tool_calls == []


# ---------------------------------------------------------------------------
# AgentResponse properties
# ---------------------------------------------------------------------------

class TestAgentResponse:
    def test_triggered_tools(self):
        from redteam.client import ToolCallInfo
        response = AgentResponse(
            text="test",
            tool_calls=[
                ToolCallInfo(name="tool_a", args={}),
                ToolCallInfo(name="tool_b", args={"x": 1}),
            ]
        )
        assert response.triggered_tools == ["tool_a", "tool_b"]

    def test_error_response(self):
        response = AgentResponse(text="", error="Timed out")
        assert response.error == "Timed out"
        assert response.text == ""
