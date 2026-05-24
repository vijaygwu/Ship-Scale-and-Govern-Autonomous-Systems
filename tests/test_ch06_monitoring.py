"""Regression tests for ch06 monitoring.py covering Phases 4 and 7."""
from __future__ import annotations

import io
import importlib
import json
import logging
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def monitoring_mod():
    sys.modules.pop("monitoring", None)
    module = importlib.import_module("monitoring")
    yield module
    sys.modules.pop("monitoring", None)


def test_no_tasks_processed_alert_windowed(monitoring_mod):
    """Phase 7 fix #2: the no_tasks_processed rule reads _last_task_at.

    Setting the last task far enough in the past with zero active tasks must
    fire the condition; resetting it to ``now`` must clear it.
    """
    metrics = monitoring_mod.AgentMetrics(agent_id="unit-test")
    detector = monitoring_mod.AgentAnomalyDetector()
    slo_manager = monitoring_mod.AgentSLOManager()

    rules = monitoring_mod.create_standard_agent_alerts(
        metrics=metrics,
        anomaly_detector=detector,
        slo_manager=slo_manager,
    )
    rule = next(r for r in rules if r.name == "no_tasks_processed")

    # No active tasks, last completion 20 minutes ago -> condition fires.
    metrics._active_tasks = 0
    metrics._last_task_at = datetime.now(timezone.utc) - timedelta(minutes=20)
    assert rule.condition() is True

    # Last completion is now -> condition should not fire.
    metrics._last_task_at = datetime.now(timezone.utc)
    assert rule.condition() is False


def test_agent_anomaly_detector_o1_eviction(monitoring_mod):
    """Phase 4 fix: AgentAnomalyDetector uses OrderedDict for O(1) LRU eviction.

    Recording N+1 distinct metrics into a detector capped at N entries should
    evict the oldest metric and retain the newest, without touching others.
    """
    from collections import OrderedDict

    detector = monitoring_mod.AgentAnomalyDetector(max_metrics=3, min_samples=1)
    assert isinstance(detector._access_order, OrderedDict)

    for name in ("a", "b", "c"):
        detector.record_and_check(name, 1.0)

    assert set(detector._baselines.keys()) == {"a", "b", "c"}

    # One more triggers an eviction of the LRU entry ``a``.
    detector.record_and_check("d", 1.0)
    assert "a" not in detector._baselines
    assert "d" in detector._baselines
    assert set(detector._baselines.keys()) == {"b", "c", "d"}


def test_anomaly_and_drift_detectors_reject_non_positive_caps(monitoring_mod):
    with pytest.raises(ValueError, match="max_metrics"):
        monitoring_mod.AgentAnomalyDetector(max_metrics=0)

    with pytest.raises(ValueError, match="window_size"):
        monitoring_mod.BehaviorDriftDetector(window_size=0)

    with pytest.raises(ValueError, match="max_metrics"):
        monitoring_mod.BehaviorDriftDetector(max_metrics=0)


@pytest.fixture
def monitoring(import_chapter):
    return import_chapter("ch06-monitoring", "monitoring")


class _FakeStatus:
    def __init__(self, code, description=None):
        self.code = code
        self.description = description


class _FakeStatusCode:
    OK = "OK"
    ERROR = "ERROR"


class _FakeSpan:
    def __init__(self, name, attributes=None):
        self.name = name
        self.attributes = dict(attributes or {})
        self.status = None
        self.exceptions = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def set_status(self, status):
        self.status = status

    def record_exception(self, exc):
        self.exceptions.append(exc)


class _FakeTracer:
    def __init__(self):
        self.spans = []

    def start_as_current_span(self, name, attributes=None):
        span = _FakeSpan(name, attributes)
        self.spans.append(span)
        return span


class _FakeTrace:
    def __init__(self, tracer):
        self._tracer = tracer

    def get_tracer(self, name):
        return self._tracer


class _FakeCounter:
    def __init__(self, name):
        self.name = name
        self.calls = []

    def add(self, amount, attributes=None):
        self.calls.append((amount, dict(attributes or {})))


class _FakeMeter:
    def __init__(self):
        self.counters = {}

    def create_counter(self, name, **kwargs):
        del kwargs
        counter = self.counters.setdefault(name, _FakeCounter(name))
        return counter


class _FakeMetrics:
    def __init__(self):
        self.meter = _FakeMeter()

    def get_meter(self, name):
        del name
        return self.meter


def _install_fake_otel(monitoring, monkeypatch):
    tracer = _FakeTracer()
    fake_metrics = _FakeMetrics()
    monkeypatch.setattr(monitoring, "trace", _FakeTrace(tracer))
    monkeypatch.setattr(monitoring, "metrics", fake_metrics)
    monkeypatch.setattr(monitoring, "Status", _FakeStatus)
    monkeypatch.setattr(monitoring, "StatusCode", _FakeStatusCode)
    return tracer, fake_metrics


def test_agent_logger_redacts_sensitive_tool_arguments(monitoring):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    agent_logger = monitoring.AgentLogger(
        agent_id="redaction-test",
        service_name="unit-test",
    )
    agent_logger.logger.handlers = [handler]
    agent_logger.logger.propagate = False

    try:
        agent_logger.log_tool_invocation(
            task_id="task-1",
            step=2,
            tool_name="search",
            arguments={
                "query": "incident status",
                "api_key": "sk-secret",
                "raw_document": "do not log this",
            },
            result={"content": "sensitive body", "score": 0.99},
            duration_ms=12.5,
            allowed_argument_keys={"query", "api_key"},
        )
    finally:
        agent_logger.logger.handlers = []

    payload = json.loads(stream.getvalue())
    arguments = payload["context"]["arguments"]

    assert arguments["allowed_values"]["query"] == "incident status"
    assert arguments["allowed_values"]["api_key"] == monitoring.REDACTED
    assert "raw_document" in arguments["omitted_keys"]
    assert payload["context"]["result"] == {
        "type": "dict",
        "keys": ["content", "score"],
        "item_count": 2,
    }
    assert "sensitive body" not in stream.getvalue()
    assert "sk-secret" not in stream.getvalue()


def test_metrics_server_uses_bounded_loopback_server(monitoring):
    metrics = monitoring.PrometheusAgentMetrics(namespace="unit")

    server_cls = monitoring.BoundedThreadingHTTPServer
    assert issubclass(server_cls, monitoring.ThreadingHTTPServer)

    class FakeBoundedThreadingHTTPServer:
        daemon_threads = True

        def __init__(
            self,
            server_address,
            handler,
            connection_timeout,
            request_queue_size,
        ):
            self.server_address = server_address
            self.handler = handler
            self.connection_timeout = connection_timeout
            self.request_queue_size = request_queue_size
            self.was_shutdown = False
            self.was_closed = False

        def serve_forever(self):
            return None

        def shutdown(self):
            self.was_shutdown = True

        def server_close(self):
            self.was_closed = True

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        monitoring,
        "BoundedThreadingHTTPServer",
        FakeBoundedThreadingHTTPServer,
    )

    handle = monitoring.start_metrics_server(
        metrics,
        port=0,
        host="127.0.0.1",
        request_queue_size=4,
        connection_timeout=0.25,
    )

    try:
        assert isinstance(handle.server, monitoring.BoundedThreadingHTTPServer)
        assert handle.server.daemon_threads is True
        assert handle.server.request_queue_size == 4
        assert handle.server.connection_timeout == 0.25
        assert handle.server.server_address[0] == "127.0.0.1"
    finally:
        handle.shutdown(timeout=1.0)
        monkeypatch.undo()


def test_task_metrics_and_token_budget_enforce_core_limits(monitoring):
    metrics = monitoring.TaskSuccessMetrics()
    metrics.record_result(
        monitoring.TaskResult(
            task_id="1",
            outcome=monitoring.TaskOutcome.SUCCESS,
            duration_seconds=1.0,
            reasoning_steps=2,
            total_tokens=100,
            tools_used=["search"],
        ),
        task_type="research",
    )
    metrics.record_result(
        monitoring.TaskResult(
            task_id="2",
            outcome=monitoring.TaskOutcome.PARTIAL_SUCCESS,
            duration_seconds=2.0,
            reasoning_steps=3,
            total_tokens=200,
            tools_used=[],
        ),
        task_type="research",
    )
    metrics.record_result(
        monitoring.TaskResult(
            task_id="3",
            outcome=monitoring.TaskOutcome.FAILURE,
            duration_seconds=3.0,
            reasoning_steps=1,
            total_tokens=50,
            tools_used=["calculator"],
            error_message="tool failed",
        ),
        task_type="research",
    )

    assert metrics.success_rate() == pytest.approx(2 / 3)
    assert metrics.success_rate(include_partial=False) == pytest.approx(1 / 3)
    assert metrics.success_rate_by_type("research") == pytest.approx(2 / 3)
    assert metrics.percentile_duration(50) == pytest.approx(2.0)

    budget = monitoring.TokenBudget(
        daily_limit=50,
        hourly_limit=30,
        per_task_limit=20,
    )
    assert budget.check_and_consume(15) is True
    assert budget.check_and_consume(21) is False
    assert budget.check_and_consume(15) is True
    assert budget.check_and_consume(1) is False
    assert budget.remaining_hourly == 0
    assert budget.remaining_daily == 20


def test_anomaly_detector_scores_against_prior_baseline_before_appending(
    monitoring,
):
    detector = monitoring.AgentAnomalyDetector(
        baseline_window=10,
        sensitivity=2.0,
        min_samples=3,
    )
    for value in [10.0, 12.0, 14.0]:
        assert detector.record_and_check("latency_ms", value) is None

    result = detector.record_and_check("latency_ms", 100.0)

    assert result is not None
    assert result.is_anomaly is True
    assert result.expected_value == pytest.approx(12.0)
    assert result.score == pytest.approx(44.0)
    assert list(detector._baselines["latency_ms"]) == [10.0, 12.0, 14.0, 100.0]


def test_anomaly_detector_uses_hourly_baseline_when_available(monitoring):
    detector = monitoring.AgentAnomalyDetector(
        baseline_window=50,
        sensitivity=100.0,
        min_samples=3,
    )
    for value in [100.0, 105.0, 95.0]:
        assert detector.record_and_check("latency_ms", value, hour=1) is None
    for value in [10.0, 12.0, 14.0]:
        assert detector.record_and_check("latency_ms", value, hour=9) is None

    detector.sensitivity = 2.0
    result = detector.record_and_check("latency_ms", 30.0, hour=9)

    assert result is not None
    assert result.expected_value == pytest.approx(12.0)
    assert result.score == pytest.approx(9.0)
    assert list(detector._hourly_baselines["latency_ms"][9]) == [12.0, 14.0, 30.0]


def test_error_rate_anomaly_scores_prior_baseline_before_appending(monitoring):
    detector = monitoring.AgentAnomalyDetector(
        baseline_window=10,
        sensitivity=2.0,
        min_samples=3,
    )
    for value in [0.01, 0.02, 0.03]:
        assert detector.check_error_rate_anomaly(value, "model") is None

    result = detector.check_error_rate_anomaly(0.20, "model")

    assert result is not None
    assert result.metric_name == "error_rate_model"
    assert result.expected_value == pytest.approx(0.02)
    assert result.score == pytest.approx(18.0)
    assert list(detector._baselines["error_rate_model"]) == [
        0.01,
        0.02,
        0.03,
        0.20,
    ]


def test_trace_agent_request_propagates_deadlines_and_retries_tool_failure(
    monitoring,
    monkeypatch,
):
    tracer, fake_metrics = _install_fake_otel(monitoring, monkeypatch)

    class ModelClient:
        def __init__(self):
            self.calls = []

        def complete(self, prompt, *, timeout, deadline):
            self.calls.append(
                {"prompt": prompt, "timeout": timeout, "deadline": deadline}
            )
            return {
                "tool_name": "search",
                "tool_args": {"query": prompt},
                "prompt_tokens": 7,
                "completion_tokens": 11,
            }

    class ToolRegistry:
        def __init__(self):
            self.calls = []

        def invoke(self, tool_name, tool_args, *, timeout, deadline):
            self.calls.append(
                {
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "timeout": timeout,
                    "deadline": deadline,
                }
            )
            if len(self.calls) == 1:
                raise ConnectionError("transient tool outage")
            return {"answer": "ok"}

    model_client = ModelClient()
    tool_registry = ToolRegistry()

    result = monitoring.trace_agent_request_example(
        request_id="req-1",
        prompt="status?",
        model_client=model_client,
        tool_registry=tool_registry,
        request_timeout_seconds=5.0,
        model_timeout_seconds=1.0,
        tool_timeout_seconds=1.0,
        max_attempts=2,
        retry_backoff_seconds=0.0,
    )

    assert result == "{'answer': 'ok'}"
    assert len(model_client.calls) == 1
    assert 0 < model_client.calls[0]["timeout"] <= 1.0
    assert len(tool_registry.calls) == 2
    assert all(0 < call["timeout"] <= 1.0 for call in tool_registry.calls)
    assert (
        tool_registry.calls[0]["deadline"]
        == pytest.approx(model_client.calls[0]["deadline"])
    )

    request_span = next(span for span in tracer.spans if span.name == "agent.request")
    tool_span = next(span for span in tracer.spans if span.name == "tool.call")
    assert request_span.status.code == "OK"
    assert tool_span.attributes["tool.call.attempt"] == 2

    retry_counter = fake_metrics.meter.counters["agent.external_call.retries"]
    assert retry_counter.calls == [
        (
            1,
            {
                "operation": "tool.call",
                "attempt": 1,
                "error.type": "ConnectionError",
            },
        )
    ]


def test_trace_agent_request_records_timeout_failure(monitoring, monkeypatch):
    tracer, fake_metrics = _install_fake_otel(monitoring, monkeypatch)

    class SlowModelClient:
        def complete(self, prompt, *, timeout, deadline):
            del prompt, timeout, deadline
            time.sleep(0.02)
            return {"prompt_tokens": 0, "completion_tokens": 0}

    class ToolRegistry:
        def invoke(self, *args, **kwargs):
            raise AssertionError("tool should not run after model timeout")

    with pytest.raises(TimeoutError, match="model.call timed out"):
        monitoring.trace_agent_request_example(
            request_id="req-timeout",
            prompt="status?",
            model_client=SlowModelClient(),
            tool_registry=ToolRegistry(),
            request_timeout_seconds=1.0,
            model_timeout_seconds=0.001,
            tool_timeout_seconds=1.0,
            max_attempts=1,
            retry_backoff_seconds=0.0,
        )

    request_span = next(span for span in tracer.spans if span.name == "agent.request")
    model_span = next(span for span in tracer.spans if span.name == "model.call")
    assert request_span.status.code == "ERROR"
    assert model_span.status.code == "ERROR"
    assert request_span.attributes["error.type"] == "TimeoutError"
    assert model_span.exceptions

    timeout_counter = fake_metrics.meter.counters["agent.external_call.timeouts"]
    assert timeout_counter.calls[0][1]["operation"] == "model.call"
    request_counter = fake_metrics.meter.counters["agent.request.outcomes"]
    assert request_counter.calls[-1][1] == {
        "status": "error",
        "error.type": "TimeoutError",
    }


def test_agent_tracer_exporter_failure_does_not_override_result(monitoring):
    def failing_exporter(span) -> None:
        raise RuntimeError(f"export failed for {span.name}")

    tracer = monitoring.AgentTracer(
        service_name="unit-test",
        exporter=failing_exporter,
    )

    @tracer.trace("business-op")
    def business_op() -> str:
        return "business-result"

    assert business_op() == "business-result"
    assert tracer._active_spans == {}


def test_slo_manager_prefers_windowed_buckets_over_unwindowed_query_sample(
    monitoring,
):
    manager = monitoring.AgentSLOManager()
    slo = monitoring.SLO(
        name="availability",
        description="windowed availability",
        sli=monitoring.SLI(
            name="availability",
            description="external cumulative counters",
            unit="events",
            good_event_query=lambda: 0,
            total_event_query=lambda: 100,
        ),
        target_percentage=99.0,
        window_days=30,
    )
    manager.register_slo(slo)
    manager.record_event("availability", is_good=True)

    state = manager.get_state("availability")

    assert state.good_events == 1
    assert state.total_events == 1
    assert state.current_percentage == pytest.approx(100.0)


def test_agent_metrics_backend_failures_do_not_abort_or_inflate_active(
    monitoring,
):
    class FailingPrometheus:
        def record_task_start(self, *args, **kwargs) -> None:
            raise RuntimeError("start backend down")

        def record_task_complete(self, *args, **kwargs) -> None:
            raise RuntimeError("complete backend down")

    class FailingTrace:
        def __enter__(self):
            raise RuntimeError("trace backend down")

        def __exit__(self, *args):
            raise RuntimeError("trace backend down")

    class FailingOtel:
        def trace_task(self, *args, **kwargs):
            return FailingTrace()

    metrics = monitoring.AgentMetrics(
        agent_id="unit-test",
        prometheus_metrics=FailingPrometheus(),
        otel_instrumentation=FailingOtel(),
    )
    metrics.add_callback(
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("callback down")
        )
    )

    with metrics.track_task("task-1", task_type="research") as task:
        task.add_tokens(12)
        task.increment_steps()

    with pytest.raises(ValueError, match="business failure"):
        with metrics.track_task("task-2", task_type="research"):
            raise ValueError("business failure")

    assert metrics.wait_for_callbacks(timeout=1.0)
    snapshot = metrics.get_snapshot()

    assert snapshot.tasks_completed == 1
    assert snapshot.tasks_failed == 1
    assert snapshot.active_tasks == 0
    assert snapshot.total_tokens == 12
    assert snapshot.callback_errors == 2
    metrics.close()


def test_agent_metrics_callback_registry_is_bounded(monitoring):
    metrics = monitoring.AgentMetrics(
        agent_id="unit-test",
        max_metric_callbacks=1,
    )
    try:
        callback_id = metrics.add_callback(lambda *_args: None)

        with pytest.raises(RuntimeError, match="registry is full"):
            metrics.add_callback(lambda *_args: None)

        assert metrics.remove_callback(callback_id) is True
        assert metrics.remove_callback(callback_id) is False
    finally:
        metrics.close()


def test_agent_metrics_callbacks_do_not_block_task_completion(monitoring):
    metrics = monitoring.AgentMetrics(agent_id="unit-test")
    started = threading.Event()
    release = threading.Event()

    def slow_callback(_metric_name, _value):
        started.set()
        release.wait(timeout=1.0)

    metrics.add_callback(slow_callback)

    try:
        begin = time.perf_counter()
        with metrics.track_task("task-1"):
            pass
        elapsed = time.perf_counter() - begin

        assert elapsed < 0.1
        assert started.wait(timeout=1.0)
        release.set()
        assert metrics.wait_for_callbacks(timeout=1.0)
    finally:
        release.set()
        metrics.close()


def test_agent_metrics_callback_queue_drops_when_full(monitoring):
    metrics = monitoring.AgentMetrics(
        agent_id="unit-test",
        callback_queue_size=1,
    )
    started = threading.Event()
    release = threading.Event()

    def slow_callback(_metric_name, _value):
        started.set()
        release.wait(timeout=1.0)

    metrics.add_callback(slow_callback)

    try:
        with metrics.track_task("task-1"):
            pass
        assert started.wait(timeout=1.0)

        with metrics.track_task("task-2"):
            pass
        with metrics.track_task("task-3"):
            pass

        snapshot = metrics.get_snapshot()
        assert snapshot.callback_notifications_dropped >= 1
    finally:
        release.set()
        metrics.close()


def test_agent_metrics_tool_and_model_backend_failures_do_not_leak(
    monitoring,
):
    class FailingPrometheus:
        def record_tool_call(self, *args, **kwargs) -> None:
            raise RuntimeError("tool backend down")

        def record_model_call(self, *args, **kwargs) -> None:
            raise RuntimeError("model backend down")

    metrics = monitoring.AgentMetrics(
        agent_id="unit-test",
        prometheus_metrics=FailingPrometheus(),
    )

    with metrics.track_tool("search"):
        pass

    with metrics.track_model_call("frontier-model"):
        pass

    with pytest.raises(ValueError, match="tool business failure"):
        with metrics.track_tool("search"):
            raise ValueError("tool business failure")

    with pytest.raises(ValueError, match="model business failure"):
        with metrics.track_model_call("frontier-model"):
            raise ValueError("model business failure")

    snapshot = metrics.get_snapshot()

    assert snapshot.tool_calls == 2
    assert snapshot.tool_error_rate == pytest.approx(0.5)
    assert snapshot.model_calls == 2
    assert snapshot.model_error_rate == pytest.approx(0.5)


def test_agent_metrics_cost_backend_failure_does_not_leak(monitoring):
    class FailingPrometheus:
        def record_cost(self, *args, **kwargs) -> None:
            raise RuntimeError("cost backend down")

    metrics = monitoring.AgentMetrics(
        agent_id="unit-test",
        prometheus_metrics=FailingPrometheus(),
    )

    def business_path() -> str:
        metrics.record_cost(0.42, model="frontier-model", task_type="research")
        return "business-result"

    assert business_path() == "business-result"
    assert metrics.get_snapshot().estimated_cost_usd == pytest.approx(0.42)


def test_snapshot_p95_uses_percentile_for_small_samples(monitoring):
    metrics = monitoring.AgentMetrics(agent_id="unit-test")

    with metrics._lock:
        metrics._tasks_completed = 3
        metrics._task_durations.extend([1.0, 2.0, 100.0])

    snapshot = metrics.get_snapshot()

    assert snapshot.avg_duration_ms == pytest.approx((1.0 + 2.0 + 100.0) / 3)
    assert snapshot.p95_duration_ms == pytest.approx(90.2)
