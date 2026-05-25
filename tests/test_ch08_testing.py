"""Regression test that ch08 testing.py imports and basic mocks instantiate."""
from __future__ import annotations

import ast
import asyncio
import importlib
import sys
import time
from pathlib import Path

import pytest


def test_testing_imports_cleanly():
    """Phase 1 deque import + Phase 5 Block 9 wrap must keep import clean."""
    sys.modules.pop("testing", None)
    module = importlib.import_module("testing")
    assert hasattr(module, "MockLLM")

    mock = module.MockLLM()
    # The MockLLM-from-block-2 instance must be usable for adding responses.
    mock.add_response(module.MockResponse(content="hello"))


@pytest.fixture
def testing_module(import_chapter):
    return import_chapter(
        "ch08-testing",
        "testing",
        stub_testing_optionals=True,
    )


def test_mock_llm_supports_pattern_default_and_streaming_responses(testing_module):
    mock = testing_module.MockLLM(max_history=2)
    mock.add_pattern_response(
        r"weather",
        testing_module.MockResponse(content="Sunny and clear"),
    )
    mock.set_default_response(testing_module.MockResponse(content="Fallback"))

    weather = mock.complete([{"role": "user", "content": "What is the weather?"}])
    fallback = mock.complete([{"role": "user", "content": "Say hello"}])

    assert weather.content == "Sunny and clear"
    assert fallback.content == "Fallback"
    assert mock.call_count == 2
    assert len(mock.call_history) == 2

    streaming = testing_module.MockLLM().add_response(
        testing_module.MockResponse(content="hello world"),
    )
    chunks = list(streaming.stream([{"role": "user", "content": "stream"}]))
    assert "".join(chunk.content or "" for chunk in chunks) == "hello world"
    assert chunks[-1].finish_reason == "stop"


def test_calculator_fixture_rejects_exponentiation(testing_module):
    assert ast.Pow not in testing_module._SAFE_OPS
    assert testing_module._safe_arith(ast.parse("2 + 3 * 4", mode="eval")) == 14

    with pytest.raises(ValueError, match="unsupported expression"):
        testing_module._safe_arith(ast.parse("2 ** 4096", mode="eval"))


def test_secret_property_is_labeled_as_sampled_smoke_invariant(testing_module):
    old_name = "test_agent_" + "never_exposes_secrets"
    assert not hasattr(testing_module, old_name)
    property_test = testing_module.test_sampled_responses_avoid_common_secret_patterns
    doc = property_test.__doc__ or ""
    assert "sampled responses" in doc
    assert "common secret patterns" in doc
    assert "not proof" in doc


def test_chapter_08_manuscript_claims_are_qualified():
    chapter = Path(__file__).resolve().parents[2] / "latex/chapters/ch08-testing.tex"
    text = chapter.read_text()

    stale_mock_claim = "must support the " + "full range"
    assert stale_mock_claim not in text
    assert "unit suite intends to exercise" in text
    assert "Provider-specific behavior" in text
    assert "test_sampled_responses_avoid_common_secret_patterns" in text
    assert "not a proof that secrets can never be disclosed" in text
    assert "ast.Pow" not in text


def test_example_agent_executes_registered_tool_and_preserves_history(
    testing_module,
):
    registry = testing_module.ToolRegistry()

    @registry.register("search")
    def search(query: str) -> str:
        return f"Results for: {query}"

    mock = (
        testing_module.MockLLMBuilder()
        .with_tool_call("search", {"query": "pytest fixtures"})
        .with_final_response("Here are pytest fixture results.")
        .build()
    )
    agent = testing_module.Agent(
        llm=mock,
        tools=registry,
        config=testing_module.AgentConfig(max_iterations=2),
    )

    result = agent.run("Find pytest fixtures")

    assert result.final_response == "Here are pytest fixture results."
    assert [call.name for call in result.tool_calls] == ["search"]
    assert mock.call_count == 2
    assert any(
        message.get("role") == "tool"
        and message.get("content") == "Results for: pytest fixtures"
        for message in mock.call_history[1]["messages"]
    )


def test_example_agent_enforces_timeout_for_slow_llm(testing_module):
    class SlowMockLLM(testing_module.MockLLM):
        def complete(self, messages, tools=None, **kwargs):
            time.sleep(0.02)
            return super().complete(messages, tools=tools, **kwargs)

    mock = SlowMockLLM().add_response(
        testing_module.MockResponse(content="too late"),
    )
    agent = testing_module.Agent(
        llm=mock,
        tools=testing_module.ToolRegistry(),
    )

    with pytest.raises(TimeoutError, match="timed out"):
        agent.run("answer slowly", timeout=0.001)

    assert mock.call_history[0]["kwargs"]["timeout"] <= 0.001


def test_safety_evaluator_flags_secret_exposure_and_dangerous_tool_use(
    testing_module,
):
    result = testing_module.AgentResult(
        final_response="The api_key=sk-test and alice@example.com should not appear.",
        tool_calls=[
            testing_module.MockToolCall(
                "call-1",
                "execute_code",
                {"code": "rm -rf /"},
            )
        ],
        task_completed=True,
        conversation_history=[],
    )

    evaluation = testing_module.SafetyEvaluator().evaluate(
        task="respond safely",
        result=result,
        context={},
    )

    assert evaluation.passed is False
    assert any("Unsafe pattern" in issue for issue in evaluation.details["issues"])
    assert any("Potential PII exposure" in issue for issue in evaluation.details["issues"])


def test_composite_evaluator_rejects_empty_or_zero_weights(testing_module):
    with pytest.raises(ValueError, match="must not be empty"):
        testing_module.CompositeEvaluator([])

    evaluator = testing_module.TaskCompletionEvaluator()
    with pytest.raises(ValueError, match="total evaluator weight"):
        testing_module.CompositeEvaluator([(evaluator, 0.0)])


def test_agent_test_harness_enforces_sync_agent_deadline(testing_module):
    class SlowSyncAgent:
        conversation_history = []

        def run(self, message, timeout=None, cancellation_token=None):
            time.sleep(0.2)
            return testing_module.AgentResult(
                final_response="late",
                tool_calls=[],
                task_completed=True,
                conversation_history=[],
            )

    harness = testing_module.AgentTestHarness(agent_factory=SlowSyncAgent)
    scenario = testing_module.TestScenario(
        name="slow-sync",
        description="sync agent should be bounded by the harness",
        user_messages=["run"],
        expected_outcomes=[],
        timeout_seconds=0.01,
    )

    result = harness.run_scenario(scenario)

    assert result.passed is False
    assert isinstance(result.error, testing_module.ScenarioTimeoutError)


def test_custom_expected_outcome_timeout_returns_promptly(
    testing_module,
    monkeypatch,
):
    result = testing_module.AgentResult(
        final_response="done",
        tool_calls=[],
        task_completed=True,
        conversation_history=[],
    )

    def stuck_evaluator(_result):
        time.sleep(0.2)
        return True

    monkeypatch.setattr(
        testing_module.ExpectedOutcome,
        "custom_eval_timeout",
        0.01,
    )
    outcome = testing_module.ExpectedOutcome(
        type="custom",
        value=stuck_evaluator,
    )

    started = time.monotonic()
    assert outcome.check(result) is False
    assert time.monotonic() - started < 0.1


def test_sync_harness_rejects_awaitable_result_inside_running_loop(
    testing_module,
):
    class AwaitableResultAgent:
        conversation_history = []

        def run(self, message, timeout=None, cancellation_token=None):
            async def build_result():
                return testing_module.AgentResult(
                    final_response=f"async {message}",
                    tool_calls=[],
                    task_completed=True,
                    conversation_history=[],
                )

            return build_result()

    async def run_inside_loop():
        harness = testing_module.AgentTestHarness(
            agent_factory=AwaitableResultAgent,
        )
        scenario = testing_module.TestScenario(
            name="awaitable-result",
            description="sync harness called from an event loop",
            user_messages=["run"],
            expected_outcomes=[],
            timeout_seconds=0.5,
        )
        return harness.run_scenario(scenario)

    result = asyncio.run(run_inside_loop())

    assert result.passed is False
    assert isinstance(result.error, RuntimeError)
    assert "event loop is already running" in str(result.error)


def test_customer_support_scenario_file_is_packaged(testing_module):
    class FakeCustomerSupportAgent:
        conversation_history = []

        def run(self, message, timeout=None, cancellation_token=None):
            return testing_module.AgentResult(
                final_response=(
                    "Your order is in progress; a human representative can "
                    "help with escalation."
                ),
                tool_calls=[],
                task_completed=True,
                conversation_history=[],
            )

    scenario_file = (
        Path(testing_module.__file__).parent
        / "scenarios"
        / "customer_support.yaml"
    )
    harness = testing_module.AgentTestHarness(
        agent_factory=FakeCustomerSupportAgent,
    )

    results = harness.run_from_yaml(scenario_file)

    assert {tag for result in results for tag in result.tags} == {
        "core",
        "escalation",
    }
    assert all(result.passed for result in results)


def test_ch08_project_specific_pytest_examples_are_guarded(testing_module):
    assert testing_module.WebSearchTool is not None
    assert testing_module.FileOperationsTool is not None
    assert testing_module.DatabaseTool is not None
    assert "pytest_fixture" in repr(testing_module.agent)
    assert "pytest_fixture" in repr(testing_module.secure_agent)
