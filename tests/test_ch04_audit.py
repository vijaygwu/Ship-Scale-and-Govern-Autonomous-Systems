"""Regression tests for ch04 audit.py covering Phases 1 and 7."""
from __future__ import annotations

import importlib
import logging
import re
import sys
import threading
import time
from datetime import timezone
from uuid import UUID

import pytest


@pytest.fixture
def audit_mod():
    sys.modules.pop("audit", None)
    module = importlib.import_module("audit")
    yield module
    sys.modules.pop("audit", None)


def test_time_range_tz_aware(audit_mod):
    """Phase 7 fix #1: TimeRange.last_hours returns tz-aware UTC datetimes."""
    tr = audit_mod.TimeRange.last_hours(1)
    assert tr.start.tzinfo is not None
    assert tr.end.tzinfo is not None
    # Compare offsets rather than identity: both must represent UTC.
    assert tr.start.utcoffset() == timezone.utc.utcoffset(tr.start)
    assert tr.end.utcoffset() == timezone.utc.utcoffset(tr.end)


def test_hash_chain_round_trip(audit_mod, tmp_path):
    """Phase 1 fix: events written via AuditLogger verify via IntegrityVerifier.

    The serializer must produce a canonical form that ``IntegrityVerifier``
    can re-derive bit-for-bit; a regression here surfaces as a hash mismatch.
    """
    sink = audit_mod.FileSink(base_path=tmp_path, durable=True)
    logger = audit_mod.AuditLogger(
        agent_id="unit-test-agent",
        agent_version="0.0.0",
        sinks=[sink],
    )

    with logger.session() as session:
        session.log_event(
            event_type=audit_mod.EventType.DECISION,
            severity=audit_mod.Severity.INFO,
            payload={"goal": "smoke-test", "selection": "go"},
        )
        session.log_event(
            event_type=audit_mod.EventType.DECISION,
            severity=audit_mod.Severity.INFO,
            payload={"goal": "smoke-test-2", "selection": "stop"},
        )

    logger.close()

    log_files = sorted(tmp_path.glob("audit_*.jsonl"))
    assert log_files, "expected at least one rotated audit log file"

    verifier = audit_mod.IntegrityVerifier()
    report = verifier.verify_file(log_files[0])
    assert report.is_valid, f"chain reported anomalies: {report.anomalies}"
    assert report.events_checked >= 2


class MemorySink:
    def __init__(self) -> None:
        self.events = []
        self.flush_count = 0
        self.closed = False

    def write(self, event) -> None:
        self.events.append(event)

    def flush(self) -> None:
        self.flush_count += 1

    def close(self) -> None:
        self.closed = True


class BlockingSink(MemorySink):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def write(self, event) -> None:
        self.entered.set()
        if not self.release.wait(timeout=2):
            raise TimeoutError("test sink was not released")
        super().write(event)


class FailingSink(MemorySink):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def write(self, event) -> None:
        self.attempts += 1
        raise RuntimeError("sink down")


class EmailDetector:
    _pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    def detect(self, text: str):
        return [
            (match.start(), match.end(), "EMAIL")
            for match in self._pattern.finditer(text)
        ]


@pytest.fixture
def audit_module(import_chapter):
    return import_chapter("ch04-audit-trails", "audit")


def test_audit_session_writes_tokenized_tamper_evident_chain(audit_module):
    sink = MemorySink()
    tokenizer = audit_module.PIITokenizer(detector=EmailDetector())
    logger = audit_module.AuditLogger(
        agent_id="agent-audit-test",
        agent_version="1.0.0",
        sinks=[sink],
        pii_tokenizer=tokenizer,
        max_retries=1,
        initial_backoff_seconds=0,
    )

    with logger.session(session_id=UUID(int=1), trace_id=UUID(int=2)) as session:
        decision = session.log_decision(
            goal="Approve refund",
            options=[{"action": "approve", "score": 0.9}],
            selection="approve",
            rationale="Customer alice@example.com is eligible",
            confidence=0.4,
        )

    event_dicts = [event.to_dict() for event in sink.events]
    decision_payload = decision.to_dict()["payload"]

    assert decision.severity == audit_module.Severity.WARNING
    assert "alice@example.com" not in decision_payload["rationale"]
    assert "[PII:EMAIL:" in decision_payload["rationale"]
    assert [event["integrity"]["sequence_num"] for event in event_dicts] == [1, 2, 3]
    assert event_dicts[0]["integrity"]["previous_hash"] == "genesis"
    assert (
        event_dicts[1]["integrity"]["previous_hash"]
        == event_dicts[0]["integrity"]["event_hash"]
    )
    assert (
        event_dicts[2]["integrity"]["previous_hash"]
        == event_dicts[1]["integrity"]["event_hash"]
    )

    report = audit_module.IntegrityVerifier().verify_events(event_dicts)
    assert report.is_valid is True
    assert sink.flush_count >= 1


def test_audit_logger_rejects_empty_sink_list_by_default(audit_module):
    with pytest.raises(ValueError, match="requires at least one audit sink"):
        audit_module.AuditLogger(
            agent_id="agent-audit-test",
            agent_version="1.0.0",
            sinks=[],
        )


def test_audit_logger_explicit_no_sink_mode_warns_and_counts_drops(
    audit_module,
    caplog,
):
    context = audit_module.EventContext(
        session_id=UUID(int=1),
        agent_id="agent-audit-test",
        agent_version="1.0.0",
    )

    with caplog.at_level(logging.WARNING):
        logger = audit_module.AuditLogger(
            agent_id="agent-audit-test",
            agent_version="1.0.0",
            sinks=[],
            allow_no_sinks=True,
        )
        event = logger._log_event(
            event_type=audit_module.EventType.DECISION,
            severity=audit_module.Severity.INFO,
            context=context,
            payload={"goal": "explicit no-op audit mode"},
        )

    assert event.payload["goal"] == "explicit no-op audit mode"
    assert logger.dropped_event_count == 1
    assert "initialized without sinks" in caplog.text
    assert "audit_dropped_events_total=1" in caplog.text


def test_audit_logger_does_not_hold_sequence_lock_during_sink_write(audit_module):
    sink = BlockingSink()
    logger = audit_module.AuditLogger(
        agent_id="agent-audit-test",
        agent_version="1.0.0",
        sinks=[sink],
        max_retries=1,
        initial_backoff_seconds=0,
        sink_io_deadline_seconds=1,
    )
    context = audit_module.EventContext(
        session_id=UUID(int=1),
        agent_id="agent-audit-test",
        agent_version="1.0.0",
    )
    errors = []

    def log_event() -> None:
        try:
            logger._log_event(
                event_type=audit_module.EventType.DECISION,
                severity=audit_module.Severity.INFO,
                context=context,
                payload={"goal": "hold lock check"},
            )
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    worker = threading.Thread(target=log_event)
    worker.start()

    assert sink.entered.wait(timeout=1)
    lock_acquired = logger._sequence_lock.acquire(timeout=0.05)
    condition_acquired = logger._sink_chain_states[0].condition.acquire(timeout=0.05)
    try:
        assert lock_acquired
        assert condition_acquired
        assert logger._sink_chain_states[0].sequence_num == 0
    finally:
        if condition_acquired:
            logger._sink_chain_states[0].condition.release()
        if lock_acquired:
            logger._sequence_lock.release()
        sink.release.set()
        worker.join(timeout=1)

    assert not worker.is_alive()
    assert errors == []
    assert logger._sink_chain_states[0].sequence_num == 1
    assert len(sink.events) == 1


def test_audit_sink_deadline_bounds_blocking_write_without_condition(
    audit_module,
):
    sink = BlockingSink()
    logger = audit_module.AuditLogger(
        agent_id="agent-audit-test",
        agent_version="1.0.0",
        sinks=[sink],
        max_retries=1,
        initial_backoff_seconds=0,
        sink_io_deadline_seconds=0.05,
    )
    context = audit_module.EventContext(
        session_id=UUID(int=1),
        agent_id="agent-audit-test",
        agent_version="1.0.0",
    )

    started = time.monotonic()
    try:
        logger._log_event(
            event_type=audit_module.EventType.DECISION,
            severity=audit_module.Severity.INFO,
            context=context,
            payload={"goal": "blocked deadline check"},
        )
    finally:
        sink.release.set()
    elapsed = time.monotonic() - started

    assert elapsed < 0.25
    assert logger._sink_chain_states[0].condition.acquire(timeout=0.05)
    try:
        assert logger._sink_chain_states[0].sequence_num == 0
        assert logger._sink_chain_states[0].disabled_reason is not None
    finally:
        logger._sink_chain_states[0].condition.release()
    assert logger.failure_counts["write"] == 1
    assert len(logger.dead_letter_queue) == 1


def test_audit_sink_deadline_bounds_retry_sleep_without_committing(
    audit_module,
):
    sink = FailingSink()
    logger = audit_module.AuditLogger(
        agent_id="agent-audit-test",
        agent_version="1.0.0",
        sinks=[sink],
        max_retries=5,
        initial_backoff_seconds=0.2,
        sink_io_deadline_seconds=0.05,
    )
    context = audit_module.EventContext(
        session_id=UUID(int=1),
        agent_id="agent-audit-test",
        agent_version="1.0.0",
    )

    started = time.monotonic()
    logger._log_event(
        event_type=audit_module.EventType.DECISION,
        severity=audit_module.Severity.INFO,
        context=context,
        payload={"goal": "deadline check"},
    )
    elapsed = time.monotonic() - started

    assert elapsed < 0.18
    assert sink.attempts == 1
    assert logger._sink_chain_states[0].sequence_num == 0
    assert logger.failure_counts["write"] == 1
    assert len(logger.dead_letter_queue) == 1


def test_decision_trail_exception_outcome_redacts_raw_exception_text(
    audit_module,
):
    sink = MemorySink()
    logger = audit_module.AuditLogger(
        agent_id="agent-audit-test",
        agent_version="1.0.0",
        sinks=[sink],
        max_retries=1,
        initial_backoff_seconds=0,
    )
    session = audit_module.AuditSession(
        logger,
        audit_module.EventContext(
            session_id=UUID(int=1),
            agent_id="agent-audit-test",
            agent_version="1.0.0",
        ),
    )
    capture = audit_module.DecisionTrailCapture(session)

    with pytest.raises(ValueError, match="secret-token"):
        with capture.trail("sanitize failure outcome"):
            raise ValueError("secret-token-123")

    trail_payloads = [
        event.payload["trail"]
        for event in sink.events
        if event.payload.get("trail_type") == "decision_trail"
    ]
    assert len(trail_payloads) == 1
    trail = trail_payloads[0]
    assert trail["outcome"] == "Failed: ValueError"
    assert "secret-token" not in trail["outcome"]
    assert trail["steps"][-1]["rationale_summary"].startswith(
        "Trail terminated due to an exception"
    )


def test_audit_query_condition_matches_nested_values(audit_module):
    event = {
        "event_type": "decision",
        "payload": {"confidence": 0.42, "rationale": "manual review"},
        "context": {"agent_id": "agent-audit-test"},
    }

    assert audit_module.QueryCondition(
        "payload.confidence",
        audit_module.QueryOperator.LESS_THAN,
        0.5,
    ).matches(event)
    assert audit_module.QueryCondition(
        "context.agent_id",
        audit_module.QueryOperator.EQUALS,
        "agent-audit-test",
    ).matches(event)
    assert not audit_module.QueryCondition(
        "payload.missing",
        audit_module.QueryOperator.CONTAINS,
        "anything",
    ).matches(event)


def test_query_regex_is_bounded_and_rejects_nested_repetition(audit_module):
    event = {"payload": {"rationale": "manual review required"}}
    audit_module._compile_query_regex.cache_clear()

    assert audit_module.QueryCondition(
        "payload.rationale",
        audit_module.QueryOperator.REGEX,
        r"manual\s+review",
    ).matches(event)
    assert audit_module.QueryCondition(
        "payload.rationale",
        audit_module.QueryOperator.REGEX,
        r"manual\s+review",
    ).matches(event)
    assert audit_module._compile_query_regex.cache_info().hits >= 1

    assert not audit_module.QueryCondition(
        "payload.rationale",
        audit_module.QueryOperator.REGEX,
        r"[unterminated",
    ).matches(event)

    condition = audit_module.QueryCondition(
        "payload.rationale",
        audit_module.QueryOperator.REGEX,
        r"(a+)+$",
    )
    with pytest.raises(ValueError, match="nested"):
        condition.matches(event)


def test_periodic_checkpointer_preserves_interval_count(audit_module):
    checkpointer = audit_module.PeriodicCheckpointer(checkpoint_interval=2)

    assert checkpointer.record_event("hash-1", 1) is None
    checkpoint = checkpointer.record_event("hash-2", 2)

    assert checkpoint is not None
    assert checkpoint["sequence_num"] == 2
    assert checkpoint["events_in_interval"] == 2
    assert checkpointer.record_event("hash-3", 3) is None
