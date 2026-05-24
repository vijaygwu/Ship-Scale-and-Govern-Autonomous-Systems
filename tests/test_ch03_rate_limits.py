import importlib.util
import sys
import threading
import time
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "ch03-rate-limits"
    / "rate_limits.py"
)
SPEC = importlib.util.spec_from_file_location("ch03_rate_limits", MODULE_PATH)
rate_limits = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rate_limits
SPEC.loader.exec_module(rate_limits)


def _make_governor(request_limit=1, daily_budget=1.0):
    return rate_limits.AgentCostGovernor.create_default(
        global_token_limit_per_minute=10_000,
        global_request_limit_per_minute=request_limit,
        global_daily_budget=daily_budget,
    )


def _request():
    return {
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": "summarize"}],
        "estimated_input_tokens": 100,
        "estimated_output_tokens": 50,
    }


def _global_daily_status(governor):
    return governor.budget_manager.get_budget_status(
        "global",
        "system",
    )["daily"]


def _global_request_capacity(governor):
    return governor.rate_limiter._request_limiters[
        "global"
    ].get_remaining_capacity()


def _token_bucket_state(limiter):
    return tuple(
        (bucket._tokens, bucket._last_refill)
        for bucket in (
            limiter._input_bucket,
            limiter._output_bucket,
            limiter._total_bucket,
        )
    )


def _token_bucket_tokens(limiter):
    return tuple(
        bucket._tokens
        for bucket in (
            limiter._input_bucket,
            limiter._output_bucket,
            limiter._total_bucket,
        )
    )


def test_wait_for_capacity_clamps_sleep_to_remaining_timeout(monkeypatch):
    class FakeTime:
        def __init__(self):
            self.now = 100.20
            self.time_values = [100.0, 100.20, 100.20, 100.20]
            self.sleeps = []

        def time(self):
            if self.time_values:
                return self.time_values.pop(0)
            return self.now

        def sleep(self, seconds):
            self.sleeps.append(seconds)
            self.now += seconds

    fake_time = FakeTime()
    monkeypatch.setattr(rate_limits, "time", fake_time)
    limiter = rate_limits.RequestRateLimiter(
        max_requests=1,
        window_seconds=10.0,
    )
    limiter._timestamps.append(100.20)

    assert limiter.wait_for_capacity(timeout=0.25) is False
    assert fake_time.sleeps == pytest.approx([0.05])
    assert fake_time.now == pytest.approx(100.25)


def test_governed_call_refunds_budget_and_rate_capacity_on_failure():
    governor = _make_governor(request_limit=1)

    with pytest.raises(RuntimeError):
        with governor.governed_call(
            _request(),
            org_id="org-1",
            user_id="user-1",
        ) as result:
            assert result["approved"] is True
            assert _global_daily_status(governor)["reserved"] > 0
            assert _global_request_capacity(governor) == 0
            raise RuntimeError("downstream failure")

    assert _global_daily_status(governor)["reserved"] == pytest.approx(0.0)
    assert _global_request_capacity(governor) == 1


def test_governed_call_refunds_downgraded_request_on_exception():
    governor = _make_governor(request_limit=1, daily_budget=0.0002)

    with pytest.raises(RuntimeError):
        with governor.governed_call(
            _request(),
            org_id="org-1",
            user_id="user-1",
        ) as result:
            assert result["success"] is True
            assert result["strategy"] == "downgrade_model"
            assert result["downgraded_model"] == "claude-3-haiku"
            assert result["modified_request"]["governance"] == result["governance"]
            assert result["governance"]["budget_reservation_id"]
            assert _global_daily_status(governor)["reserved"] > 0
            assert _global_request_capacity(governor) == 0
            raise RuntimeError("degraded downstream failure")

    assert _global_daily_status(governor)["reserved"] == pytest.approx(0.0)
    assert _global_request_capacity(governor) == 1


def test_governed_call_refunds_quality_reduction_with_nested_governance():
    governor = _make_governor(request_limit=1, daily_budget=0.02)
    governor.degradation_manager.config.strategies = [
        rate_limits.DegradationStrategy.REDUCE_QUALITY
    ]
    request = {
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": "summarize"}],
        "max_tokens": 5000,
        "estimated_input_tokens": 100,
        "estimated_output_tokens": 5000,
    }

    with governor.governed_call(
        request,
        org_id="org-1",
        user_id="user-1",
    ) as result:
        assert result["success"] is True
        assert result["strategy"] == "reduce_quality"
        assert result["reduced_max_tokens"] == 1000
        nested_governance = result["modified_request"]["governance"]
        result.pop("governance")
        assert nested_governance["budget_reservation_id"]
        assert _global_daily_status(governor)["reserved"] > 0
        assert _global_request_capacity(governor) == 0

    assert _global_daily_status(governor)["reserved"] == pytest.approx(0.0)
    assert _global_request_capacity(governor) == 1


def test_record_failure_does_not_double_refund_after_success():
    governor = _make_governor(request_limit=2)
    result = governor.process_request(
        _request(),
        org_id="org-1",
        user_id="user-1",
    )
    governance = result["governance"]

    assert result["approved"] is True
    assert _global_request_capacity(governor) == 1
    assert _global_daily_status(governor)["reserved"] > 0

    governor.record_completion(
        org_id="org-1",
        user_id="user-1",
        model="claude-3-sonnet",
        input_tokens=100,
        output_tokens=50,
        metadata={"governance": governance},
    )
    after_success_capacity = _global_request_capacity(governor)
    after_success_status = _global_daily_status(governor)

    assert after_success_capacity == 1
    assert after_success_status["reserved"] == pytest.approx(0.0)
    assert after_success_status["spent"] > 0

    assert governor.record_failure(governance) is False
    assert _global_request_capacity(governor) == after_success_capacity
    assert _global_daily_status(governor)["spent"] == pytest.approx(
        after_success_status["spent"]
    )


def test_token_rate_limiter_rejects_negative_counts_before_bucket_touch():
    limiter = rate_limits.TokenRateLimiter(
        max_input_tokens_per_minute=100,
        max_output_tokens_per_minute=100,
        max_total_tokens_per_minute=200,
    )
    before = _token_bucket_state(limiter)

    with pytest.raises(ValueError, match="estimated_input_tokens"):
        limiter.check_capacity(-1, 0)
    with pytest.raises(ValueError, match="output_tokens"):
        limiter.try_acquire(0, -1)
    with pytest.raises(ValueError, match="actual_input"):
        limiter.record_actual_usage(0, 0, -1, 0)
    with pytest.raises(ValueError, match="input_tokens"):
        limiter.refund(-1, 0)

    assert _token_bucket_state(limiter) == before


def test_process_queue_timeout_does_not_refund_running_processor():
    rate_limiter = rate_limits.HierarchicalRateLimiter(
        global_config=rate_limits.RateLimitConfig(
            max_requests_per_minute=1,
            max_tokens_per_minute=1000,
        )
    )
    budget_manager = rate_limits.BudgetManager()
    budget_manager.allocate_budget(
        "global",
        "system",
        rate_limits.BudgetPeriod.DAILY,
        0.00025,
    )
    manager = rate_limits.GracefulDegradationManager(
        config=rate_limits.DegradationConfig(
            strategies=[rate_limits.DegradationStrategy.QUEUE],
            queue_item_timeout_seconds=0.1,
            notify_user=False,
        ),
        rate_limiter=rate_limiter,
        budget_manager=budget_manager,
    )

    def queued_request(label):
        return {
            "model": "claude-3-sonnet",
            "messages": [{"role": "user", "content": label}],
            "estimated_input_tokens": 10,
            "estimated_output_tokens": 10,
            "scopes": [(rate_limits.LimitScope.USER, "user-1")],
            "budget_scopes": [("global", "system")],
        }

    assert manager.handle_rate_limit(
        queued_request("slow"),
        "global",
        "limited",
    )["success"]
    assert manager.handle_rate_limit(
        queued_request("fast"),
        "global",
        "limited",
    )["success"]

    def processor(request):
        label = request["messages"][0]["content"]
        if label == "slow":
            time.sleep(0.3)
        return {"success": True, "label": label}

    try:
        results = manager.process_queue(processor)
    finally:
        manager.shutdown_queue_processor(wait=True)

    assert [result["timed_out"] for result in results] == [True]
    assert results[0]["result"] == {
        "success": False,
        "error": "queue_item_timeout",
        "timeout_seconds": 0.1,
        "capacity_refunded": False,
    }
    assert results[0]["request"]["deadline_at"] <= time.time()
    assert len(manager._request_queue) == 1
    assert (
        manager._request_queue[0]["request"]["messages"][0]["content"]
        == "fast"
    )
    assert manager.get_degradation_stats()["queue_timeout"] == 1


def test_hierarchical_rate_limiter_rejects_non_positive_scope_cap():
    with pytest.raises(ValueError, match="max_scopes"):
        rate_limits.HierarchicalRateLimiter(
            global_config=rate_limits.RateLimitConfig(),
            max_scopes=0,
        )


def test_hierarchical_rate_limiter_evicts_oldest_dynamic_scope():
    limiter = rate_limits.HierarchicalRateLimiter(
        global_config=rate_limits.RateLimitConfig(max_requests_per_minute=10),
        max_scopes=1,
        scope_ttl_seconds=60,
    )

    limiter.configure_scope(
        rate_limits.LimitScope.USER,
        "user-1",
        rate_limits.RateLimitConfig(max_requests_per_minute=10),
    )
    limiter.configure_scope(
        rate_limits.LimitScope.USER,
        "user-2",
        rate_limits.RateLimitConfig(max_requests_per_minute=10),
    )

    assert "user:user-1" not in limiter._configs
    assert "user:user-2" in limiter._configs


def test_hierarchical_rate_limiter_enforces_configured_parent_from_child_scope():
    limiter = rate_limits.HierarchicalRateLimiter(
        global_config=rate_limits.RateLimitConfig(max_requests_per_minute=10)
    )
    limiter.configure_scope(
        rate_limits.LimitScope.ORGANIZATION,
        "org-1",
        rate_limits.RateLimitConfig(max_requests_per_minute=1),
    )
    limiter.configure_scope(
        rate_limits.LimitScope.USER,
        "user-1",
        rate_limits.RateLimitConfig(max_requests_per_minute=10),
        parent_scope=rate_limits.LimitScope.ORGANIZATION,
        parent_identifier="org-1",
    )

    assert limiter.acquire(
        [(rate_limits.LimitScope.USER, "user-1")],
        0,
        0,
    ) == (True, None, None)

    allowed, blocked_scope, reason = limiter.check_all_limits(
        [(rate_limits.LimitScope.USER, "user-1")],
        0,
        0,
    )

    assert allowed is False
    assert blocked_scope == "organization:org-1"
    assert reason == "Request rate limit exceeded"
    assert (
        limiter._request_limiters["user:user-1"].get_remaining_capacity()
        == 9
    )


def test_hierarchical_acquire_rolls_back_parent_tokens_when_child_fails():
    limiter = rate_limits.HierarchicalRateLimiter(
        global_config=rate_limits.RateLimitConfig(max_tokens_per_minute=1000)
    )
    limiter.configure_scope(
        rate_limits.LimitScope.ORGANIZATION,
        "org-1",
        rate_limits.RateLimitConfig(max_tokens_per_minute=1000),
    )
    limiter.configure_scope(
        rate_limits.LimitScope.USER,
        "user-1",
        rate_limits.RateLimitConfig(max_tokens_per_minute=100),
        parent_scope=rate_limits.LimitScope.ORGANIZATION,
        parent_identifier="org-1",
    )

    before_global = _token_bucket_tokens(limiter._limiters["global"])
    before_parent = _token_bucket_tokens(limiter._limiters["organization:org-1"])
    before_child = _token_bucket_tokens(limiter._limiters["user:user-1"])

    success, blocked_scope, reason = limiter.acquire(
        [(rate_limits.LimitScope.USER, "user-1")],
        80,
        10,
    )

    assert success is False
    assert blocked_scope == "user:user-1"
    assert reason == "Input token limit exceeded"
    assert _token_bucket_tokens(limiter._limiters["global"]) == pytest.approx(
        before_global
    )
    assert _token_bucket_tokens(
        limiter._limiters["organization:org-1"]
    ) == pytest.approx(before_parent)
    assert _token_bucket_tokens(limiter._limiters["user:user-1"]) == pytest.approx(
        before_child
    )


def test_hierarchical_acquire_rolls_back_global_tokens_when_parent_fails():
    limiter = rate_limits.HierarchicalRateLimiter(
        global_config=rate_limits.RateLimitConfig(max_tokens_per_minute=1000)
    )
    limiter.configure_scope(
        rate_limits.LimitScope.ORGANIZATION,
        "org-1",
        rate_limits.RateLimitConfig(max_tokens_per_minute=100),
    )
    limiter.configure_scope(
        rate_limits.LimitScope.USER,
        "user-1",
        rate_limits.RateLimitConfig(max_tokens_per_minute=1000),
        parent_scope=rate_limits.LimitScope.ORGANIZATION,
        parent_identifier="org-1",
    )

    before_global = _token_bucket_tokens(limiter._limiters["global"])
    before_parent = _token_bucket_tokens(limiter._limiters["organization:org-1"])
    before_child = _token_bucket_tokens(limiter._limiters["user:user-1"])

    success, blocked_scope, reason = limiter.acquire(
        [(rate_limits.LimitScope.USER, "user-1")],
        80,
        10,
    )

    assert success is False
    assert blocked_scope == "organization:org-1"
    assert reason == "Input token limit exceeded"
    assert _token_bucket_tokens(limiter._limiters["global"]) == pytest.approx(
        before_global
    )
    assert _token_bucket_tokens(
        limiter._limiters["organization:org-1"]
    ) == pytest.approx(before_parent)
    assert _token_bucket_tokens(limiter._limiters["user:user-1"]) == pytest.approx(
        before_child
    )


def test_process_queue_preserves_queue_when_timeout_workers_are_saturated():
    manager = rate_limits.GracefulDegradationManager(
        config=rate_limits.DegradationConfig(
            strategies=[rate_limits.DegradationStrategy.QUEUE],
            queue_item_timeout_seconds=0.05,
            queue_processor_workers=1,
            notify_user=False,
        )
    )
    started = threading.Event()

    def queued_request(label):
        return {
            "model": "claude-3-sonnet",
            "messages": [{"role": "user", "content": label}],
            "estimated_input_tokens": 10,
            "estimated_output_tokens": 10,
        }

    assert manager.handle_rate_limit(
        queued_request("slow"),
        "global",
        "limited",
    )["success"]
    assert manager.handle_rate_limit(
        queued_request("waiting"),
        "global",
        "limited",
    )["success"]

    def processor(request):
        started.set()
        time.sleep(0.2)
        return {"success": True}

    try:
        results = manager.process_queue(processor)
        assert started.wait(timeout=0.2)
    finally:
        manager.shutdown_queue_processor(wait=True)

    assert len(results) == 1
    assert results[0]["timed_out"] is True
    assert len(manager._request_queue) == 1
    assert (
        manager._request_queue[0]["request"]["messages"][0]["content"]
        == "waiting"
    )
    stats = manager.get_degradation_stats()
    assert stats["queue_timeout"] == 1
    assert stats["queue_processor_saturated"] == 1
