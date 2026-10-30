"""Adapter from the gauntlet to a real tool-use loop on the Messages API.

Not run live by this repository. There was no API key where it was written, so its only
test drives it with a scripted fake client. Treat it as a starting point and check the
first results by hand. Running it spends tokens.

    pip install anthropic
    injection-gauntlet run --agent examples/messages_api_agent.py:agent --show-fired
"""

from __future__ import annotations

from typing import Any

from injection_gauntlet.harness import Agent, AgentRequest


def make_agent(
    client: Any = None, model: str = "claude-opus-5-5", max_tokens: int = 16000, max_turns: int = 8
) -> Agent:
    def run(request: AgentRequest) -> str:
        sdk = client
        if sdk is None:
            import anthropic

            sdk = anthropic.Anthropic()
        tools = [tool.to_messages_api() for tool in request.tools]
        messages: list[dict[str, Any]] = [{"role": "user", "content": request.task}]
        for _ in range(max_turns):
            response = sdk.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=request.system,
                tools=tools,
                messages=messages,
            )
            if response.stop_reason != "tool_use":
                return "".join(b.text for b in response.content if b.type == "text")
            messages.append({"role": "assistant", "content": response.content})
            results = [
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": request.call_tool(block.name, dict(block.input)),
                }
                for block in response.content
                if block.type == "tool_use"
            ]
            messages.append({"role": "user", "content": results})
        raise RuntimeError(f"no final answer after {max_turns} turns")

    return run


agent = make_agent()
