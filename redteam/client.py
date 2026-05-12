"""LangGraph agent client — sends attack messages and captures responses + tool calls."""

import asyncio
import os
from dataclasses import dataclass, field

from langgraph_sdk import get_client
from langgraph_sdk.client import LangGraphClient


@dataclass
class ToolCallInfo:
    name: str
    args: dict


@dataclass
class AgentResponse:
    text: str
    tool_calls: list[ToolCallInfo] = field(default_factory=list)
    error: str | None = None

    @property
    def triggered_tools(self) -> list[str]:
        return [tc.name for tc in self.tool_calls]


class AgentClient:
    """
    Wraps the LangGraph dev server REST API.
    Each call to send() creates a fresh thread so attacks don't bleed into each other.
    """

    def __init__(self, url: str, assistant_id: str, timeout: float = 60.0):
        self._url = url
        self._assistant_id = assistant_id
        self._timeout = timeout
        self._client: LangGraphClient = get_client(url=url)

    @classmethod
    def from_env(cls) -> "AgentClient":
        url = os.environ.get("AGENT_URL", "http://localhost:2024")
        assistant_id = os.environ.get("AGENT_ASSISTANT_ID", "agent")
        return cls(url=url, assistant_id=assistant_id)

    async def send(self, message: str) -> AgentResponse:
        """Send a single message on a fresh thread and return the agent's response."""
        try:
            return await asyncio.wait_for(self._run(message), timeout=self._timeout)
        except asyncio.TimeoutError:
            return AgentResponse(text="", error=f"Timed out after {self._timeout}s")
        except Exception as e:
            return AgentResponse(text="", error=str(e))

    async def send_multi_turn(self, messages: list[str]) -> AgentResponse:
        """Send a sequence of messages on the same thread (for multi-turn attacks)."""
        try:
            return await asyncio.wait_for(self._run_multi(messages), timeout=self._timeout)
        except asyncio.TimeoutError:
            return AgentResponse(text="", error=f"Timed out after {self._timeout}s")
        except Exception as e:
            return AgentResponse(text="", error=str(e))

    async def _run(self, message: str) -> AgentResponse:
        thread = await self._client.threads.create()
        thread_id = thread["thread_id"]
        await self._wait_for_run(thread_id, message)
        return await self._extract_response(thread_id)

    async def _run_multi(self, messages: list[str]) -> AgentResponse:
        thread = await self._client.threads.create()
        thread_id = thread["thread_id"]
        for message in messages:
            await self._wait_for_run(thread_id, message)
        return await self._extract_response(thread_id)

    async def _wait_for_run(self, thread_id: str, message: str) -> None:
        run = await self._client.runs.create(
            thread_id,
            self._assistant_id,
            input={"messages": [{"role": "human", "content": message}]},
        )
        await self._client.runs.join(thread_id, run["run_id"])

    async def _extract_response(self, thread_id: str) -> AgentResponse:
        state = await self._client.threads.get_state(thread_id)
        messages = state.values.get("messages", [])

        text = ""
        tool_calls: list[ToolCallInfo] = []

        for msg in messages:
            msg_type = msg.get("type") if isinstance(msg, dict) else getattr(msg, "type", None)

            if msg_type == "ai":
                content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", "")
                if isinstance(content, str) and content:
                    text = content
                elif isinstance(content, list):
                    text = " ".join(
                        block.get("text", "") if isinstance(block, dict) else getattr(block, "text", "")
                        for block in content
                        if (block.get("type") if isinstance(block, dict) else getattr(block, "type", "")) == "text"
                    )

                raw_tool_calls = (
                    msg.get("tool_calls") if isinstance(msg, dict)
                    else getattr(msg, "tool_calls", [])
                ) or []

                for tc in raw_tool_calls:
                    name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "")
                    args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})
                    if name:
                        tool_calls.append(ToolCallInfo(name=name, args=args or {}))

        return AgentResponse(text=text, tool_calls=tool_calls)
