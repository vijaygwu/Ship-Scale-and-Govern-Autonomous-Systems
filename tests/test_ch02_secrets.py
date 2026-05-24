"""Regression tests for ch02 secrets.py covering Phase 5 sync-stub fix."""
from __future__ import annotations

import inspect
import logging
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def test_secrets_imports_cleanly(secrets_module):
    """Loading the chapter file under ``book2_secrets`` should succeed end-to-end."""
    assert hasattr(secrets_module, "send_to_siem")
    assert hasattr(secrets_module, "SIEMAuditLogger")
    assert hasattr(secrets_module, "AuditEvent")


def test_send_to_siem_is_sync_and_siem_logger_delivers_in_background(
    secrets_module,
):
    """Phase 5 fix: send_to_siem is a regular sync function, not a coroutine.

    A coroutine return value would be silently discarded by
    the background worker, dropping audit events. The sync signature also has
    to accept the (endpoint, event, *, sender=...) shape so the worker's
    keyword passthrough works.
    """
    fn = secrets_module.send_to_siem
    assert not inspect.iscoroutinefunction(fn)
    assert not inspect.isasyncgenfunction(fn)

    calls: list[tuple[str, dict]] = []

    def fake_sender(endpoint, event, connect_timeout, read_timeout):
        calls.append((endpoint, event))
        return 200

    direct_result = fn(
        "https://siem.example/ingest",
        {"event_type": "unit-test"},
        sender=fake_sender,
        max_retries=0,
    )
    assert direct_result.delivered is True
    assert direct_result.status_code == 200

    calls.clear()

    logger = secrets_module.SIEMAuditLogger(
        siem_endpoint="https://siem.example/ingest",
        client_id="unit-test",
        sender=fake_sender,
    )

    # AuditEvent in ch02 is a dataclass with positional fields; pass kwargs
    # for clarity. ``__dict__`` is used internally by SIEMAuditLogger.log so
    # any dataclass instance works.
    from datetime import datetime, timezone
    event = secrets_module.AuditEvent(
        timestamp=datetime.now(timezone.utc),
        event_type="secret_access",
        secret_id="prod/openai/api-key",
        secret_version="v1",
        agent_id="agent-7",
        agent_role="research",
        operation="read",
        result="success",
        context={"task_id": "t1"},
    )

    try:
        result = logger.log(event)
        assert result.queued is True
        assert result.delivered is False
        assert result.attempts == 0
        assert logger.flush(timeout=1.0) is True
    finally:
        logger.close(timeout=1.0)

    assert len(calls) == 1
    assert calls[0][0] == "https://siem.example/ingest"
    assert calls[0][1]["client_id"] == "unit-test"


class CaptureAuditLogger:
    def __init__(self) -> None:
        self.events = []

    def log(self, event) -> None:
        self.events.append(event)


def make_siem_event(secrets_module, secret_id: str, result: str = "success"):
    return secrets_module.AuditEvent(
        timestamp=datetime.now(timezone.utc),
        event_type="secret_access",
        secret_id=secret_id,
        secret_version="v1",
        agent_id="agent-7",
        agent_role="research",
        operation="read",
        result=result,
        context={"correlation_id": f"corr-{secret_id}"},
    )


def wait_until(predicate, timeout: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def secrets_module(import_chapter):
    return import_chapter("ch02-api-keys", "secrets")


def test_stdlib_secrets_alias_does_not_self_import_from_chapter_dir(
    import_chapter,
    code_root,
    monkeypatch,
):
    chapter_dir = code_root / "ch02-api-keys"
    chapter_file = chapter_dir / "secrets.py"

    monkeypatch.delitem(sys.modules, "secrets", raising=False)
    monkeypatch.syspath_prepend(str(chapter_dir))

    module = import_chapter("ch02-api-keys", "secrets")

    imported_secrets = sys.modules.get("secrets")
    if imported_secrets is not None:
        imported_file = getattr(imported_secrets, "__file__", None)
        assert imported_file is None or Path(imported_file).resolve() != chapter_file

    stdlib_file = Path(module._stdlib_secrets.__file__).resolve()
    assert stdlib_file != chapter_file
    assert isinstance(module._stdlib_secrets.token_urlsafe(8), str)


def test_aws_rotation_catches_bound_botocore_exceptions_namespace(
    import_chapter,
    monkeypatch,
):
    client_error = type("ClientError", (Exception,), {})
    wrong_client_error = type("WrongClientError", (Exception,), {})

    fake_botocore = types.ModuleType("botocore")
    fake_botocore.__path__ = []
    fake_exceptions = types.ModuleType("botocore.exceptions")
    fake_exceptions.ClientError = client_error
    fake_exceptions.exceptions = types.SimpleNamespace(ClientError=wrong_client_error)

    monkeypatch.setitem(sys.modules, "botocore", fake_botocore)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", fake_exceptions)

    module = import_chapter("ch02-api-keys", "secrets")

    assert module.botocore_exceptions is fake_exceptions
    assert "botocore" not in module.__dict__

    class FakeClient:
        class exceptions:
            ResourceNotFoundException = type(
                "ResourceNotFoundException",
                (Exception,),
                {},
            )
            AccessDeniedException = type("AccessDeniedException", (Exception,), {})

        def rotate_secret(self, SecretId):
            raise client_error(f"failed to rotate {SecretId}")

    provider = module.AWSSecretsManagerProvider(region_name="us-east-1")
    provider._client = FakeClient()

    with pytest.raises(module.SecretRotationError, match="Failed to rotate prod/key"):
        provider.rotate_secret("prod/key")


def test_aws_rotation_polls_version_stages_not_rotation_in_progress(
    secrets_module,
    monkeypatch,
):
    monkeypatch.setattr(secrets_module.time, "sleep", lambda delay: None)
    monkeypatch.setattr(secrets_module.random, "uniform", lambda start, end: 0)

    class FakeClient:
        class exceptions:
            ResourceNotFoundException = type(
                "ResourceNotFoundException",
                (Exception,),
                {},
            )
            AccessDeniedException = type("AccessDeniedException", (Exception,), {})

        def __init__(self):
            self.describe_calls = 0

        def rotate_secret(self, SecretId):
            return {"VersionId": "v2"}

        def describe_secret(self, SecretId):
            self.describe_calls += 1
            stages = (
                {"v2": ["AWSPENDING"]}
                if self.describe_calls == 1
                else {"v2": ["AWSCURRENT"]}
            )
            return {
                "VersionIdsToStages": stages,
                "Tags": [],
                "NextRotationDate": None,
            }

        def get_secret_value(self, **kwargs):
            return {
                "SecretString": "rotated",
                "VersionId": "v2",
                "CreatedDate": datetime.now(timezone.utc),
            }

    provider = secrets_module.AWSSecretsManagerProvider(region_name="us-east-1")
    fake_client = FakeClient()
    provider._client = fake_client

    value, metadata = provider.rotate_secret("prod/key")

    assert value == "rotated"
    assert metadata.version == "v2"
    assert fake_client.describe_calls >= 2


def test_environment_secret_manager_caches_and_audits_reads(
    secrets_module,
    monkeypatch,
):
    audit = CaptureAuditLogger()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_RESEARCH_OPENAI_API_KEY", "first-value")
    manager = secrets_module.SecretManager(
        agent_id="agent-test",
        agent_role="research",
        backend=secrets_module.SecretBackend.ENVIRONMENT,
        backend_config={"prefix": "SECRET_"},
        allowed_secret_patterns=["research/*"],
        default_cache_ttl=60,
        audit_logger=audit,
        rotation_check_interval=3600,
    )

    try:
        first = manager.get_secret(
            "research/openai-api-key",
            context={"purpose": "unit-test"},
        )
        monkeypatch.setenv("SECRET_RESEARCH_OPENAI_API_KEY", "second-value")
        cached = manager.get_secret("research/openai-api-key")
        fresh = manager.get_secret("research/openai-api-key", bypass_cache=True)
    finally:
        manager.shutdown()

    assert first == "first-value"
    assert cached == "first-value"
    assert fresh == "second-value"

    successful_reads = [event for event in audit.events if event.result == "success"]
    assert [event.context["cache_hit"] for event in successful_reads] == [
        False,
        True,
        False,
    ]
    assert all(not hasattr(event, "value") for event in audit.events)


def test_environment_backend_rejected_in_production_without_override(
    secrets_module,
    monkeypatch,
    caplog,
):
    audit = CaptureAuditLogger()
    monkeypatch.setenv("ENVIRONMENT", "production")

    with caplog.at_level(logging.WARNING):
        with pytest.raises(
            secrets_module.SecretAccessDeniedError,
            match="development-only",
        ):
            secrets_module.SecretManager(
                agent_id="agent-test",
                agent_role="research",
                backend=secrets_module.SecretBackend.ENVIRONMENT,
                backend_config={"prefix": "SECRET_"},
                allowed_secret_patterns=["research/*"],
                audit_logger=audit,
                rotation_check_interval=3600,
            )

    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.event_type == "secret_backend_configuration"
    assert event.secret_id == "backend/environment"
    assert event.operation == "configure"
    assert event.result == "denied"
    assert event.context == {
        "backend": "env",
        "environment": "production",
        "development_override": False,
    }
    assert event.error_message is not None
    assert "development-only" in event.error_message
    assert any(
        "Denied environment secret backend" in record.getMessage()
        for record in caplog.records
    )


def test_environment_backend_production_override_is_explicit(
    secrets_module,
    monkeypatch,
):
    audit = CaptureAuditLogger()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_RESEARCH_OPENAI_API_KEY", "dev-only-value")

    manager = secrets_module.SecretManager(
        agent_id="agent-test",
        agent_role="research",
        backend=secrets_module.SecretBackend.ENVIRONMENT,
        backend_config={
            "prefix": "SECRET_",
            "allow_environment_backend_in_production": True,
        },
        allowed_secret_patterns=["research/*"],
        audit_logger=audit,
        rotation_check_interval=3600,
    )

    try:
        value = manager.get_secret("research/openai-api-key")
    finally:
        manager.shutdown()

    assert value == "dev-only-value"
    assert audit.events[-1].operation == "read"
    assert audit.events[-1].result == "success"


def test_secret_scope_denial_is_fail_closed_and_audited(
    secrets_module,
    monkeypatch,
):
    audit = CaptureAuditLogger()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_FINANCE_PAYMENT_KEY", "payment-secret")
    manager = secrets_module.SecretManager(
        agent_id="agent-test",
        agent_role="research",
        backend=secrets_module.SecretBackend.ENVIRONMENT,
        backend_config={"prefix": "SECRET_"},
        allowed_secret_patterns=["research/*"],
        audit_logger=audit,
        rotation_check_interval=3600,
    )

    try:
        with pytest.raises(secrets_module.SecretAccessDeniedError):
            manager.get_secret("finance/payment-key")
    finally:
        manager.shutdown()

    assert audit.events[-1].operation == "read"
    assert audit.events[-1].result == "denied"
    assert audit.events[-1].error_message == "Access denied by scope policy"


def test_vault_provider_short_ttl_sets_future_refresh_deadline(
    secrets_module,
    monkeypatch,
):
    class FakeAppRole:
        def login(self, role_id, secret_id):
            return {"auth": {"lease_duration": 30}}

    class FakeClient:
        def __init__(self, **kwargs):
            self.auth = types.SimpleNamespace(approle=FakeAppRole())

    fake_hvac = types.SimpleNamespace(Client=FakeClient)
    monkeypatch.setitem(sys.modules, "hvac", fake_hvac)

    provider = secrets_module.HashiCorpVaultProvider(
        vault_addr="https://vault.example",
        role_id="role",
        secret_id="secret",
        max_retries=0,
    )

    before = datetime.now(timezone.utc)
    provider._get_client()

    assert provider._token_expiry is not None
    assert before + timedelta(seconds=1) <= provider._token_expiry
    assert provider._token_expiry <= before + timedelta(seconds=30)
    assert provider._is_token_expired() is False


def test_secret_manager_rotation_monitor_is_lazy_and_context_managed(
    secrets_module,
    monkeypatch,
):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_RESEARCH_OPENAI_API_KEY", "secret-value")
    manager = secrets_module.SecretManager(
        agent_id="agent-test",
        agent_role="research",
        backend=secrets_module.SecretBackend.ENVIRONMENT,
        backend_config={"prefix": "SECRET_"},
        allowed_secret_patterns=["research/*"],
        rotation_check_interval=3600,
    )

    assert manager._rotation_monitor_thread is None

    with manager as active_manager:
        assert active_manager is manager
        active_manager.register_rotation_callback(
            "research/openai-api-key",
            lambda _secret_id, _version: None,
        )
        assert active_manager._rotation_monitor_thread is not None
        assert active_manager._rotation_monitor_thread.is_alive()

    assert manager._shutdown_event.is_set()
    assert not manager._rotation_monitor_thread.is_alive()

    with pytest.raises(RuntimeError, match="SecretManager is closed"):
        manager.get_secret("research/openai-api-key")


def test_secret_manager_rotation_monitor_can_be_disabled(
    secrets_module,
    monkeypatch,
):
    monkeypatch.setenv("ENVIRONMENT", "development")
    manager = secrets_module.SecretManager(
        agent_id="agent-test",
        agent_role="research",
        backend=secrets_module.SecretBackend.ENVIRONMENT,
        backend_config={"prefix": "SECRET_"},
        allowed_secret_patterns=["research/*"],
        rotation_check_interval=None,
    )

    try:
        manager.register_rotation_callback(
            "research/openai-api-key",
            lambda _secret_id, _version: None,
        )
        assert manager._rotation_monitor_thread is None
    finally:
        manager.close()


def test_siem_audit_logger_log_returns_before_siem_delivery(
    secrets_module,
):
    entered_sender = threading.Event()
    release_sender = threading.Event()
    calls: list[dict] = []

    def blocking_sender(endpoint, event, connect_timeout, read_timeout):
        calls.append(event)
        entered_sender.set()
        release_sender.wait()
        return 200

    siem_logger = secrets_module.SIEMAuditLogger(
        siem_endpoint="https://siem.example/ingest",
        client_id="unit-test",
        sender=blocking_sender,
        max_retries=0,
        delivery_queue_size=1,
    )

    try:
        started = time.perf_counter()
        result = siem_logger.log(
            make_siem_event(secrets_module, "research/openai-key")
        )
        elapsed = time.perf_counter() - started

        assert result.queued is True
        assert result.delivered is False
        assert result.attempts == 0
        assert elapsed < 0.5
        assert entered_sender.wait(timeout=1.0)

        release_sender.set()
        assert siem_logger.flush(timeout=1.0) is True
        assert siem_logger.metrics.delivered_total == 1
        assert calls[0]["client_id"] == "unit-test"
    finally:
        release_sender.set()
        siem_logger.close(timeout=1.0)


def test_siem_audit_logger_reports_delivery_queue_backpressure(
    secrets_module,
    caplog,
):
    entered_sender = threading.Event()
    release_sender = threading.Event()

    def blocking_sender(endpoint, event, connect_timeout, read_timeout):
        entered_sender.set()
        release_sender.wait()
        return 200

    siem_logger = secrets_module.SIEMAuditLogger(
        siem_endpoint="https://siem.example/ingest",
        client_id="unit-test",
        sender=blocking_sender,
        max_retries=0,
        delivery_queue_size=1,
    )

    try:
        first = siem_logger.log(
            make_siem_event(secrets_module, "research/first-key")
        )
        assert first.queued is True
        assert entered_sender.wait(timeout=1.0)

        second = siem_logger.log(
            make_siem_event(secrets_module, "research/second-key")
        )
        assert second.queued is True

        with caplog.at_level(logging.ERROR):
            third = siem_logger.log(
                make_siem_event(secrets_module, "research/third-key")
            )

        assert third.queued is False
        assert third.delivered is False
        assert third.error == "SIEM audit delivery queue full"
        assert third.dropped_queue_full_total == 1
        assert siem_logger.metrics.dropped_queue_full_total == 1

        drop_records = [
            record for record in caplog.records
            if "SIEM audit queue full" in record.getMessage()
        ]
        assert len(drop_records) == 1
        assert drop_records[0].secret_id == "research/third-key"
        assert not hasattr(drop_records[0], "context")
    finally:
        release_sender.set()
        siem_logger.close(timeout=1.0)


def test_siem_audit_logger_circuit_breaker_pauses_next_delivery_attempt(
    secrets_module,
):
    calls: list[str] = []

    def failing_sender(endpoint, event, connect_timeout, read_timeout):
        calls.append(event["secret_id"])
        return 503

    siem_logger = secrets_module.SIEMAuditLogger(
        siem_endpoint="https://siem.example/ingest",
        client_id="unit-test",
        sender=failing_sender,
        max_retries=0,
        backoff_seconds=0,
        delivery_queue_size=2,
        circuit_failure_threshold=1,
        circuit_reset_seconds=60,
    )

    try:
        first = siem_logger.log(
            make_siem_event(
                secrets_module,
                "research/first-key",
                result="failure",
            )
        )
        assert first.queued is True
        assert wait_until(lambda: siem_logger.metrics.circuit_open)
        assert calls == ["research/first-key"]

        second = siem_logger.log(
            make_siem_event(
                secrets_module,
                "research/second-key",
                result="failure",
            )
        )
        assert second.queued is True
        time.sleep(0.05)

        assert calls == ["research/first-key"]
        assert siem_logger.metrics.circuit_open_total == 1
        assert siem_logger.metrics.failed_delivery_total == 1

        redelivery = siem_logger.drain_failed_events(max_events=1)
        assert redelivery[0].attempts == 0
        assert redelivery[0].circuit_open is True
    finally:
        siem_logger.close(timeout=1.0)


def test_siem_audit_logger_tracks_evicted_failed_events(
    secrets_module,
    caplog,
):
    def failing_sender(endpoint, event, connect_timeout, read_timeout):
        return 503

    siem_logger = secrets_module.SIEMAuditLogger(
        siem_endpoint="https://siem.example/ingest",
        client_id="unit-test",
        sender=failing_sender,
        max_retries=0,
        backoff_seconds=0,
        circuit_failure_threshold=10,
        failure_buffer_size=1,
    )

    try:
        with caplog.at_level(logging.ERROR):
            first = siem_logger.log(
                make_siem_event(
                    secrets_module,
                    "research/first-key",
                    result="failure",
                )
            )
            assert first.queued is True
            assert siem_logger.flush(timeout=1.0) is True

            second = siem_logger.log(
                make_siem_event(
                    secrets_module,
                    "research/second-key",
                    result="failure",
                )
            )
            assert second.queued is True
            assert siem_logger.flush(timeout=1.0) is True

        assert siem_logger.dropped_failed_events_total == 1
        assert siem_logger.metrics.buffered_failed_events == 1
        assert len(siem_logger.failed_events) == 1
        assert siem_logger.failed_events[0]["event"]["secret_id"] == (
            "research/second-key"
        )
    finally:
        siem_logger.close(timeout=1.0)

    drop_records = [
        record for record in caplog.records
        if "dropping oldest event metadata" in record.getMessage()
    ]
    assert len(drop_records) == 1
    assert drop_records[0].evicted_secret_id == "research/first-key"
    assert drop_records[0].dropped_failed_events_total == 1
    assert not hasattr(drop_records[0], "evicted_context")
