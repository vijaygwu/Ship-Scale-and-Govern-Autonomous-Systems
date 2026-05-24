from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel
import pytest

DEPLOYMENT_MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "ch05-deployment"
    / "deployment.py"
)


def _needs_stub(name: str, required_attrs: tuple[str, ...] = ()) -> bool:
    try:
        __import__(name)
    except ImportError:
        return True

    module = sys.modules.get(name)
    return not isinstance(module, types.ModuleType) or any(
        not hasattr(module, attr) for attr in required_attrs
    )


def _install_import_stubs() -> None:
    """Provide minimal stubs for unrelated runtime deps absent in smoke envs."""
    if _needs_stub("pydantic_settings", ("BaseSettings", "SettingsConfigDict")):
        pydantic_settings = types.ModuleType("pydantic_settings")
        pydantic_settings.BaseSettings = BaseModel
        pydantic_settings.SettingsConfigDict = dict
        sys.modules["pydantic_settings"] = pydantic_settings

    if _needs_stub("sqlalchemy") or _needs_stub(
        "sqlalchemy.ext.asyncio",
        ("AsyncEngine",),
    ):
        sqlalchemy = types.ModuleType("sqlalchemy")
        sqlalchemy.text = lambda query: query
        sqlalchemy_ext = types.ModuleType("sqlalchemy.ext")
        sqlalchemy_asyncio = types.ModuleType("sqlalchemy.ext.asyncio")
        sqlalchemy_asyncio.AsyncEngine = type("AsyncEngine", (), {})
        sys.modules["sqlalchemy"] = sqlalchemy
        sys.modules["sqlalchemy.ext"] = sqlalchemy_ext
        sys.modules["sqlalchemy.ext.asyncio"] = sqlalchemy_asyncio

    if _needs_stub("structlog", ("get_logger",)):
        structlog = types.ModuleType("structlog")
        structlog.get_logger = CapturingLogger
        sys.modules["structlog"] = structlog


def _load_deployment_module():
    _install_import_stubs()
    module_name = "ch05_deployment_under_test"
    spec = importlib.util.spec_from_file_location(module_name, DEPLOYMENT_MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def deployment():
    return _load_deployment_module()


class CapturingLogger:
    def __init__(self) -> None:
        self.infos = []
        self.warnings = []
        self.errors = []

    def info(self, event, **kwargs) -> None:
        self.infos.append((event, kwargs))

    def warning(self, event, **kwargs) -> None:
        self.warnings.append((event, kwargs))

    def error(self, event, **kwargs) -> None:
        self.errors.append((event, kwargs))


class FailingBackend:
    def get_flag(self, name):
        raise RuntimeError("backend offline")

    def set_flag(self, name, value) -> None:
        pass


class StaticBackend:
    def __init__(self, value) -> None:
        self.value = value

    def get_flag(self, name):
        return self.value

    def set_flag(self, name, value) -> None:
        pass


class TargetingBackend:
    def __init__(self) -> None:
        self.calls = []

    def get_flag(self, name, user_id=None, context=None):
        self.calls.append((name, user_id, context))
        if user_id == "enabled-user":
            return "true"
        if context and context.get("account_tier") == "enterprise":
            return "true"
        return "false"

    def set_flag(self, name, value) -> None:
        pass


class FakePrometheusResponse:
    def __init__(self, value: str = "0.99") -> None:
        self.value = value

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return {
            "status": "success",
            "data": {
                "result": [
                    {
                        "value": [123.0, self.value],
                    }
                ],
            },
        }


class FlakyPrometheusClient:
    def __init__(self, httpx_module) -> None:
        self.is_closed = False
        self.calls = 0
        self.httpx_module = httpx_module

    def get(self, url, params):
        del url, params
        self.calls += 1
        if self.calls == 1:
            raise self.httpx_module.RequestError("temporary network failure")
        return FakePrometheusResponse("0.97")

    def close(self) -> None:
        self.is_closed = True


def test_feature_flag_backend_failure_uses_next_backend_and_default(
    deployment,
    monkeypatch,
) -> None:
    logger = CapturingLogger()
    monkeypatch.setattr(deployment, "logger", logger)

    manager = deployment.FeatureFlagManager(
        [FailingBackend(), StaticBackend("false")],
        cache_ttl_seconds=0,
    )
    assert manager.get("advanced_reasoning") is False

    default_manager = deployment.FeatureFlagManager(
        [FailingBackend()],
        cache_ttl_seconds=0,
    )
    assert default_manager.get("max_tool_calls") == 10

    assert len(logger.warnings) == 2
    assert all(
        warning_fields["backend"].endswith("FailingBackend")
        for _, warning_fields in logger.warnings
    )


def test_feature_flag_manager_passes_targeting_context_to_backend(
    deployment,
) -> None:
    backend = TargetingBackend()
    manager = deployment.FeatureFlagManager([backend], cache_ttl_seconds=0)

    assert manager.get("advanced_reasoning", user_id="enabled-user") is True
    assert manager.get("advanced_reasoning", user_id="disabled-user") is False

    context = {"user_id": "context-user", "account_tier": "enterprise"}
    assert manager.get("advanced_reasoning", context=context) is True

    assert backend.calls == [
        ("advanced_reasoning", "enabled-user", None),
        ("advanced_reasoning", "disabled-user", None),
        ("advanced_reasoning", "context-user", context),
    ]


def test_canary_analyzer_retries_transient_prometheus_request_error(
    deployment,
    monkeypatch,
) -> None:
    analyzer = deployment.CanaryAnalyzer(
        "https://prometheus.example",
        query_max_attempts=2,
        query_backoff_seconds=0,
    )
    fake_client = FlakyPrometheusClient(deployment.httpx)
    analyzer._client = fake_client
    monkeypatch.setattr(deployment.time, "sleep", lambda _seconds: None)

    assert analyzer.query_prometheus("up") == 0.97
    assert fake_client.calls == 2


def test_graceful_shutdown_times_out_hung_callback_and_continues(
    deployment,
    monkeypatch,
    caplog,
) -> None:
    async def run_test() -> None:
        stdlib_logger = logging.getLogger(
            f"{deployment.__name__}.graceful_shutdown_test"
        )
        monkeypatch.setattr(deployment, "logger", stdlib_logger)
        shutdown = deployment.GracefulShutdown(
            shutdown_timeout=1,
            drain_timeout=0,
            callback_timeout=0.01,
        )
        calls = []

        async def hung_callback() -> None:
            calls.append("hung-started")
            await asyncio.sleep(60)

        async def after_callback() -> None:
            calls.append("after")

        shutdown.register_callback(hung_callback)
        shutdown.register_callback(after_callback)

        start = time.monotonic()
        with caplog.at_level(logging.INFO, logger=stdlib_logger.name):
            await asyncio.wait_for(shutdown.initiate_shutdown(), timeout=0.5)

        assert time.monotonic() - start < 0.5
        assert calls == ["hung-started", "after"]
        timeout_records = [
            record for record in caplog.records
            if record.getMessage().startswith("Shutdown callback timed out")
        ]
        assert timeout_records
        assert timeout_records[0].structured_fields["callback"].endswith(
            "hung_callback"
        )

    asyncio.run(run_test())


def test_graceful_shutdown_counts_duplicate_request_ids(deployment) -> None:
    async def run_test() -> None:
        shutdown = deployment.GracefulShutdown(
            shutdown_timeout=1,
            drain_timeout=0,
            callback_timeout=0.01,
        )

        first = shutdown.track_request("same-id")
        second = shutdown.track_request("same-id")

        async with first:
            async with second:
                assert shutdown.active_request_count() == 2
            assert shutdown.active_request_count() == 1
        assert shutdown.active_request_count() == 0

    asyncio.run(run_test())


def test_blue_green_deployer_uses_configured_desired_replicas(
    deployment,
    monkeypatch,
) -> None:
    config = deployment.DeploymentConfig(
        namespace="agents",
        service_name="agent-service",
        blue_deployment="agent-blue",
        green_deployment="agent-green",
        health_endpoint="http://health",
        validation_endpoint="http://{version}/validate",
        health_check_interval=1,
        stabilization_seconds=1,
        desired_replicas=5,
    )
    deployer = deployment.BlueGreenDeployer(config)
    scale_calls = []

    monkeypatch.setattr(deployer, "get_inactive_version", lambda: "green")
    monkeypatch.setattr(deployer, "get_active_version", lambda: "blue")
    monkeypatch.setattr(
        deployer,
        "scale_deployment",
        lambda version, replicas: scale_calls.append((version, replicas)),
    )
    monkeypatch.setattr(deployer, "wait_for_ready", lambda version: True)
    monkeypatch.setattr(deployer, "validate_deployment", lambda endpoint: True)
    monkeypatch.setattr(deployer, "switch_traffic", lambda version: None)
    monkeypatch.setattr(deployer, "wait_for_inflight_drain", lambda version: True)
    monkeypatch.setattr(deployment.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(deployment.time, "sleep", lambda seconds: None)

    assert deployer.deploy("repo/agent:new") is True
    assert ("green", 5) in scale_calls
    assert ("blue", 0) in scale_calls


def test_blue_green_deployer_waits_for_old_color_to_drain(
    deployment,
    monkeypatch,
) -> None:
    config = deployment.DeploymentConfig(
        namespace="agents",
        service_name="agent-service",
        blue_deployment="agent-blue",
        green_deployment="agent-green",
        health_endpoint="http://health",
        validation_endpoint="http://{version}/validate",
        health_check_interval=1,
        stabilization_seconds=3,
        desired_replicas=2,
    )
    deployer = deployment.BlueGreenDeployer(config)
    events = []
    inflight_counts = iter([2, 1, 0])

    monkeypatch.setattr(deployer, "get_inactive_version", lambda: "green")
    monkeypatch.setattr(deployer, "get_active_version", lambda: "blue")
    monkeypatch.setattr(
        deployer,
        "scale_deployment",
        lambda version, replicas: events.append(("scale", version, replicas)),
    )
    monkeypatch.setattr(deployer, "wait_for_ready", lambda version: True)
    monkeypatch.setattr(deployer, "validate_deployment", lambda endpoint: True)
    monkeypatch.setattr(
        deployer,
        "switch_traffic",
        lambda version: events.append(("switch", version)),
    )

    def get_inflight(version: str) -> int:
        count = next(inflight_counts)
        events.append(("inflight", version, count))
        return count

    monkeypatch.setattr(deployer, "get_inflight_requests", get_inflight)
    monkeypatch.setattr(deployment.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(deployment.subprocess, "run", lambda *args, **kwargs: None)

    assert deployer.deploy("repo/agent:new") is True

    zero_seen = events.index(("inflight", "blue", 0))
    old_scaled_down = events.index(("scale", "blue", 0))
    assert zero_seen < old_scaled_down
    assert ("switch", "green") in events


def test_canary_zero_duration_stage_runs_post_shift_analysis(deployment) -> None:
    class StubAnalyzer:
        def __init__(self) -> None:
            self.thresholds = []

        def analyze(self, success_threshold):
            self.thresholds.append(success_threshold)
            return deployment.CanaryStatus.FAILED

    async def run_test() -> None:
        analyzer = StubAnalyzer()
        traffic_weights = []
        rollback_calls = []
        config = deployment.CanaryConfig(
            stages=[
                deployment.CanaryStage(
                    weight=100,
                    duration_minutes=0,
                    success_threshold=0.98,
                )
            ],
            rollback_on_failure=True,
        )
        controller = deployment.CanaryController(
            config,
            analyzer,
            traffic_weights.append,
            lambda: rollback_calls.append("rollback"),
        )

        assert await controller.run() is False
        assert traffic_weights == [100]
        assert analyzer.thresholds == [0.98]
        assert rollback_calls == ["rollback"]

    assert deployment.CanaryConfig().stages[-1].duration_minutes > 0
    asyncio.run(run_test())


def test_canary_main_awaits_cancelled_monitor_cleanup(
    deployment,
    monkeypatch,
) -> None:
    async def run_test() -> None:
        cleanup_finished = False

        class FastController:
            async def run(self) -> bool:
                return True

        async def monitor(controller, pager_check, budget_check) -> None:
            nonlocal cleanup_finished
            del controller, pager_check, budget_check
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0)
                cleanup_finished = True

        monkeypatch.setattr(deployment, "external_monitor", monitor)

        result = await deployment.main(
            FastController(),
            lambda: False,
            lambda: False,
        )

        assert result is True
        assert cleanup_finished is True

    asyncio.run(run_test())


def test_liveness_runs_only_critical_checks(deployment) -> None:
    async def run_test() -> None:
        calls = []
        checker = deployment.HealthChecker(check_timeout_s=0.01)

        async def critical_check():
            calls.append("critical")
            return deployment.CheckResult(
                name="critical",
                status=deployment.HealthStatus.HEALTHY,
                message="ok",
                duration_ms=0,
                timestamp=datetime.now(timezone.utc),
            )

        async def readiness_only_check():
            calls.append("readiness-only")
            raise AssertionError("readiness-only check ran during liveness")

        checker.register("critical", critical_check, critical=True)
        checker.register("readiness-only", readiness_only_check, critical=False)
        checker.mark_startup_complete()

        is_live, payload = await checker.is_live()

        assert is_live is True
        assert payload == {
            "status": "healthy",
            "checks": {"critical": "healthy"},
        }
        assert calls == ["critical"]

    asyncio.run(run_test())


def test_health_router_repeated_app_factories_do_not_accumulate_routes(
    deployment,
) -> None:
    def build_app():
        checker = deployment.HealthChecker(check_timeout_s=0.01)
        router = deployment.create_health_router(checker)
        app = deployment.FastAPI()
        if hasattr(app, "include_router"):
            app.include_router(router)
            return app
        return router

    def health_paths(app_or_router) -> list[str]:
        return sorted(
            route.path
            for route in getattr(app_or_router, "routes", [])
            if route.path.startswith("/health/")
        )

    expected_paths = [
        "/health/detailed",
        "/health/live",
        "/health/ready",
    ]

    first_app = build_app()
    second_app = build_app()

    assert health_paths(first_app) == expected_paths
    assert health_paths(second_app) == expected_paths


def test_httpx_imports_use_optional_dependency_guard() -> None:
    source = DEPLOYMENT_MODULE_PATH.read_text(encoding="utf-8")

    assert "import httpx" not in source
    assert source.count("httpx = optional_import(") == 4
