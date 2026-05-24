"""Regression tests for ch07 error_handling.py covering Phases 5 and 6."""
from __future__ import annotations

import importlib
import asyncio
import concurrent.futures
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest


class HalfOpenProbeAbort(BaseException):
    """Non-cancellation BaseException used to exercise cleanup paths."""


@pytest.fixture
def eh_mod():
    sys.modules.pop("error_handling", None)
    module = importlib.import_module("error_handling")
    yield module
    sys.modules.pop("error_handling", None)


def test_error_handling_imports_cleanly(eh_mod):
    """Phase 5 fix: Blocks 3/8/15/16 are wrapped under __main__ so import works."""
    assert hasattr(eh_mod, "CircuitBreaker")
    assert hasattr(eh_mod, "CircuitBreakerConfig")
    assert hasattr(eh_mod, "CircuitState")


def test_circuit_breaker_half_open_slot_released_on_success(eh_mod):
    """Phase 6 fix: HALF_OPEN slot counter decrements so the breaker can close.

    Force the breaker directly into HALF_OPEN and drive successes through
    it. The Phase 6 fix is the post-success slot release; without it,
    ``_half_open_calls`` would grow past ``half_open_max_calls`` and wedge.
    """
    config = eh_mod.CircuitBreakerConfig(
        failure_threshold=5,
        success_threshold=2,
        half_open_max_calls=3,
        minimum_calls=5,
        timeout=timedelta(milliseconds=1),
    )
    breaker = eh_mod.CircuitBreaker("unit-test", config=config)
    breaker._state = eh_mod.CircuitState.HALF_OPEN
    breaker._half_open_calls = 0
    breaker._half_open_successes = 0

    for _ in range(config.half_open_max_calls + 2):
        if breaker._state == eh_mod.CircuitState.CLOSED:
            break
        breaker.execute_sync(lambda: "ok")
        # Slot counter must never exceed the cap; this is the Phase 6 invariant.
        assert breaker._half_open_calls <= config.half_open_max_calls

    assert breaker._state in (
        eh_mod.CircuitState.CLOSED,
        eh_mod.CircuitState.HALF_OPEN,
    )


@pytest.mark.parametrize("exc_type", [asyncio.CancelledError, HalfOpenProbeAbort])
def test_circuit_breaker_async_half_open_slot_released_on_base_exception(
    eh_mod,
    run_async,
    exc_type,
):
    config = eh_mod.CircuitBreakerConfig(
        failure_threshold=5,
        success_threshold=2,
        half_open_max_calls=1,
        minimum_calls=1,
        timeout=timedelta(milliseconds=1),
    )
    breaker = eh_mod.CircuitBreaker("unit-test-async", config=config)
    breaker._state = eh_mod.CircuitState.HALF_OPEN
    breaker._half_open_calls = 0
    breaker._half_open_successes = 0

    async def interrupted_probe():
        raise exc_type()

    async def successful_probe():
        return "ok"

    async def scenario():
        with pytest.raises(exc_type):
            await breaker.execute_async(interrupted_probe)

        assert breaker._state == eh_mod.CircuitState.HALF_OPEN
        assert breaker._half_open_calls == 0
        assert await breaker.execute_async(successful_probe) == "ok"
        assert breaker._half_open_calls == 0

    run_async(scenario())


@pytest.fixture
def errors(import_chapter):
    return import_chapter("ch07-error-handling", "error_handling")


def test_error_classifier_and_retry_policy_retry_transient_tool_failure(
    errors,
    monkeypatch,
):
    class NoBackoff(errors.BackoffStrategy):
        def calculate_delay(self, attempt: int, base_delay: float) -> float:
            return 0.0

    monkeypatch.setattr(errors.time, "sleep", lambda delay: None)
    attempts = []
    retries = []

    def flaky_tool():
        attempts.append("call")
        if len(attempts) == 1:
            raise ConnectionError("temporary network blip")
        return "ok"

    policy = errors.RetryPolicy(
        max_retries=2,
        base_delay=1.0,
        backoff_strategy=NoBackoff(),
        on_retry=lambda error, attempt: retries.append((error, attempt)),
    )

    assert policy.execute_sync(flaky_tool, component="search-tool") == "ok"
    assert len(attempts) == 2
    assert retries[0][0].category == errors.ErrorCategory.TOOL_FAILURE
    assert retries[0][0].severity == errors.ErrorSeverity.MEDIUM
    assert retries[0][1] == 0


def test_retry_policy_does_not_retry_sync_timeout_if_worker_still_running(
    errors,
):
    started = threading.Event()
    attempts = []

    def slow_operation():
        attempts.append("call")
        started.set()
        time.sleep(0.05)
        return "late"

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    policy = errors.RetryPolicy(
        max_retries=2,
        attempt_timeout=0.01,
        sync_timeout_executor=executor,
    )

    try:
        with pytest.raises(errors.SyncAttemptStillRunningError):
            policy.execute_sync(slow_operation)
        assert started.wait(timeout=0.1)
    finally:
        executor.shutdown(wait=True)

    assert attempts == ["call"]


def test_circuit_breaker_opens_and_uses_fallback(errors):
    breaker = errors.CircuitBreaker(
        "llm-primary",
        config=errors.CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=1,
            timeout=timedelta(seconds=30),
            minimum_calls=2,
        ),
    )

    def fail():
        raise RuntimeError("upstream unavailable")

    with pytest.raises(RuntimeError):
        breaker.execute_sync(fail)
    with pytest.raises(RuntimeError):
        breaker.execute_sync(fail)

    assert breaker.state == errors.CircuitState.OPEN
    assert breaker.execute_sync(lambda: "primary", fallback=lambda: "fallback") == "fallback"

    metrics = breaker.get_metrics()
    assert metrics["state"] == "OPEN"
    assert metrics["total_failures"] == 2
    assert metrics["total_rejections"] == 1


def test_circuit_breaker_opens_on_slow_success_when_latency_threshold_configured(
    errors,
):
    breaker = errors.CircuitBreaker(
        "slow-primary",
        config=errors.CircuitBreakerConfig(
            failure_threshold=5,
            minimum_calls=1,
            latency_threshold=timedelta(milliseconds=1),
            latency_percentile=1.0,
            timeout=timedelta(seconds=30),
        ),
    )

    def slow_success():
        time.sleep(0.005)
        return "ok"

    assert breaker.execute_sync(slow_success) == "ok"
    assert breaker.state == errors.CircuitState.OPEN
    assert breaker.get_metrics()["total_successes"] == 1


def test_fallback_chain_default_timeout_skips_hanging_provider(
    errors,
    run_async,
    monkeypatch,
):
    monkeypatch.setattr(errors, "DEFAULT_PROVIDER_TIMEOUT_SECONDS", 0.01)

    class HangingProvider(errors.FallbackProvider[str]):
        @property
        def name(self):
            return "hung_primary"

        @property
        def priority(self):
            return 0

        async def execute(self, request):
            await asyncio.Event().wait()
            return "never"

        def is_available(self):
            return True

    class FastFallbackProvider(errors.FallbackProvider[str]):
        @property
        def name(self):
            return "fast_fallback"

        @property
        def priority(self):
            return 10

        async def execute(self, request):
            return "fallback-result"

        def is_available(self):
            return True

    chain = errors.FallbackChain([
        HangingProvider(),
        FastFallbackProvider(),
    ])

    async def scenario():
        started = time.monotonic()
        result = await chain.execute({"messages": []})
        return result, time.monotonic() - started

    result, elapsed = run_async(scenario())

    assert elapsed < 0.5
    assert result.value == "fallback-result"
    assert result.provider_used == "fast_fallback"
    assert result.providers_tried == ["hung_primary", "fast_fallback"]
    assert result.degraded is True

    metrics = chain.get_metrics()
    assert metrics["provider_timeout_counts"]["hung_primary"] == 1
    assert metrics["fallback_counts"]["hung_primary"] == 1
    assert metrics["provider_usage"]["fast_fallback"] == 1


def test_fallback_chain_requires_explicit_unbounded_wait_opt_in(errors):
    class FastProvider(errors.FallbackProvider[str]):
        @property
        def name(self):
            return "fast"

        @property
        def priority(self):
            return 0

        async def execute(self, request):
            return "ok"

        def is_available(self):
            return True

    provider = FastProvider()

    with pytest.raises(ValueError, match="allow_unbounded_provider_waits"):
        errors.FallbackChain(
            [provider],
            default_provider_timeout=None,
        )

    chain = errors.FallbackChain(
        [provider],
        default_provider_timeout=None,
        allow_unbounded_provider_waits=True,
    )
    assert chain.default_provider_timeout is None


def test_degradation_manager_rejects_dependency_cycles(errors):
    manager = errors.DegradationManager()
    manager.register_capability(errors.SystemCapability(
        name="search",
        minimum_level=errors.DegradationLevel.FULL,
        dependencies={"llm"},
    ))

    with pytest.raises(ValueError, match="dependency cycle"):
        manager.register_capability(errors.SystemCapability(
            name="llm",
            minimum_level=errors.DegradationLevel.FULL,
            dependencies={"search"},
        ))

    assert "llm" not in manager._capabilities


def test_degradation_manager_reports_existing_dependency_cycle(errors):
    manager = errors.DegradationManager()
    manager.register_capability(errors.SystemCapability(
        name="search",
        minimum_level=errors.DegradationLevel.FULL,
    ))
    manager.register_capability(errors.SystemCapability(
        name="llm",
        minimum_level=errors.DegradationLevel.FULL,
        dependencies={"search"},
    ))
    manager._capabilities["search"].dependencies.add("llm")

    with pytest.raises(ValueError, match="search -> llm -> search"):
        manager.is_available("search")


def test_dlq_processor_times_out_awaitable_reprocessor(errors, run_async):
    dlq = errors.DeadLetterQueue(max_reprocess_attempts=2)
    entry = dlq.add({"task": "hung-async"})

    async def hung_reprocess(_request):
        await asyncio.sleep(60)

    processor = errors.DLQProcessor(
        dlq,
        hung_reprocess,
        batch_size=1,
        reprocess_timeout=timedelta(milliseconds=10),
    )

    async def scenario():
        started = time.monotonic()
        await processor._process_batch()
        elapsed = time.monotonic() - started
        await processor.stop()
        return elapsed

    assert run_async(scenario()) < 0.5
    assert entry.attempt_count == 1
    assert entry.status == errors.DLQEntryStatus.PENDING
    assert entry.processing_deadline is None


def test_dlq_processor_times_out_blocking_reprocessor(errors, run_async):
    dlq = errors.DeadLetterQueue(max_reprocess_attempts=2)
    entry = dlq.add({"task": "hung-sync"})

    def blocking_reprocess(_request):
        time.sleep(0.3)

    processor = errors.DLQProcessor(
        dlq,
        blocking_reprocess,
        batch_size=1,
        reprocess_timeout=timedelta(milliseconds=10),
        max_blocking_workers=1,
    )

    async def scenario():
        started = time.monotonic()
        await processor._process_batch()
        elapsed = time.monotonic() - started
        await processor.stop()
        return elapsed

    assert run_async(scenario()) < 0.2
    assert entry.attempt_count == 1
    assert entry.status == errors.DLQEntryStatus.PENDING
    assert entry.processing_deadline is None


@pytest.mark.parametrize(
    "terminal_action, expected_status",
    [
        ("resolve", "RESOLVED"),
        ("discard", "DISCARDED"),
        ("failed", "DISCARDED"),
    ],
)
def test_dlq_terminal_entries_leave_active_queue(
    errors,
    terminal_action,
    expected_status,
):
    dlq = errors.DeadLetterQueue(max_size=1, max_reprocess_attempts=1)
    entry = dlq.add({"task": terminal_action})

    if terminal_action == "resolve":
        assert dlq.mark_resolved(entry.id, "done")
    elif terminal_action == "discard":
        assert dlq.discard(entry.id, "operator rejected")
    else:
        assert dlq.mark_processing(entry.id)
        assert dlq.mark_failed(entry.id)

    assert entry.status == getattr(errors.DLQEntryStatus, expected_status)
    assert dlq.get(entry.id) is None
    assert dlq.get_metrics()["total_entries"] == 0

    replacement = dlq.add({"task": "replacement"})

    assert dlq.get(replacement.id) is replacement
    assert entry.status == getattr(errors.DLQEntryStatus, expected_status)
    assert dlq.get_metrics()["total_entries"] == 1


def test_dlq_stale_processing_terminal_discard_leaves_active_queue(errors):
    dlq = errors.DeadLetterQueue(
        max_size=1,
        max_reprocess_attempts=1,
        processing_lease=timedelta(seconds=30),
    )
    entry = dlq.add({"task": "stale"})
    assert dlq.mark_processing(entry.id)
    entry.processing_deadline = datetime.now(timezone.utc) - timedelta(seconds=1)

    assert dlq.recover_stale_processing() == 1

    assert entry.status == errors.DLQEntryStatus.DISCARDED
    assert dlq.get(entry.id) is None
    assert dlq.get_metrics()["total_entries"] == 0

    replacement = dlq.add({"task": "replacement"})

    assert dlq.get(replacement.id) is replacement
    assert entry.status == errors.DLQEntryStatus.DISCARDED


def test_decorrelated_jitter_resets_previous_delay_for_new_sequence(
    errors,
    monkeypatch,
):
    calls = []

    def fake_uniform(low: float, high: float) -> float:
        calls.append((low, high))
        return high

    monkeypatch.setattr(errors.random, "uniform", fake_uniform)
    jitter = errors.DecorrelatedJitter(max_delay=100.0)

    assert jitter.calculate_delay(attempt=0, base_delay=2.0) == 6.0
    assert jitter.calculate_delay(attempt=1, base_delay=2.0) == 18.0
    assert jitter.calculate_delay(attempt=0, base_delay=2.0) == 6.0
    assert calls == [(2.0, 6.0), (2.0, 18.0), (2.0, 6.0)]
