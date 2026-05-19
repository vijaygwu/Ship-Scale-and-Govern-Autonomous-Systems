from __future__ import annotations

"""
Audit Trails and Compliance

Code listings from Chapter 04, Book 2:
"Agentic AI in Production: Ship, Scale, and Govern Autonomous Systems"
by Dr. Vijay Raghavan

This file faithfully reproduces every code listing from the chapter, in book
order, with section banners showing the block number. Most listings are
runnable Python that builds incrementally; some are illustrative fragments
(log output, file trees, Dockerfile snippets, JSON examples) preserved as
docstrings so this file always remains valid Python.

To use a particular class or function, copy it into your own project and
provide the surrounding context (imports, dependencies) as needed.
"""


# ============================================================================
# Block 1 (chapter listing #1)
# ============================================================================

# What they actually logged
{"timestamp": "2024-03-15T14:22:31Z", "level": "INFO",
 "message": "Account action completed", "account_id": "12345"}

# ============================================================================
# Block 2 (chapter block #2) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_2_listing = r"""
filter @message like /event_type.*decision/
| parse @message '"confidence":*,' as confidence
| stats count(*) by bin(1h), 
    case(confidence < 0.5, 'low', 
         confidence < 0.8, 'medium', 
         true, 'high') as confidence_tier
"""

# ============================================================================
# Block 3 (chapter block #3) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_3_listing = r"""
fields @timestamp, @message
| filter event_type = 'decision'
| filter payload.confidence < 0.5
| sort @timestamp desc
| limit 100
"""

# ============================================================================
# Block 4 (chapter listing #4)
# ============================================================================

Original: "Customer John Smith (ID: 12345) requested refund"
Tokenized: "Customer [PII:CUST:abc123] requested refund"

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

"""
audit_logger.py - Production audit logging for AI agents

This module provides a comprehensive audit logging system designed for
AI agents operating in regulated environments. It implements structured
logging, tamper-evident chains, and privacy-preserving features.

Code Navigation (line numbers are approximate):
- Event Types & Severity Enums ... ~30
- Data Models (EventContext, IntegrityData, AuditEvent) ... ~50
- PII Detection & Tokenization ... ~140
- Audit Sinks (ABC, FileSink) ... ~200
- AuditLogger (main class) ... ~280
- AuditSession (context manager) ... ~470
"""


import hashlib
import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, TypeVar
from uuid import UUID, uuid4


class EventType(Enum):
    """Categories of audit events for AI agents."""
    DECISION = "decision"
    TOOL_CALL = "tool_call"
    DATA_ACCESS = "data_access"
    ERROR = "error"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    POLICY_CHECK = "policy_check"
    HUMAN_OVERRIDE = "human_override"


class Severity(Enum):
    """Event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class EventContext:
    """
    Contextual information linking events within and across sessions.
    
    The context enables tracing individual events back to their session,
    distributed trace, and parent operation. This is essential for
    reconstructing agent behavior during incident investigation.
    """
    session_id: UUID
    agent_id: str
    agent_version: str
    trace_id: UUID | None = None
    span_id: UUID | None = None
    parent_span_id: UUID | None = None
    environment: str = "production"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": str(self.session_id),
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "trace_id": str(self.trace_id) if self.trace_id else None,
            "span_id": str(self.span_id) if self.span_id else None,
            "parent_span_id": str(self.parent_span_id) if self.parent_span_id else None,
            "environment": self.environment,
        }


@dataclass
class IntegrityData:
    """
    Cryptographic integrity information for tamper-evident logging.
    
    Each event includes a hash of its contents and a reference to the
    previous event's hash, creating a chain that makes tampering detectable.
    """
    sequence_num: int
    previous_hash: str
    event_hash: str = ""
    
    def to_dict(self) -> dict[str, str | int]:
        return {
            "sequence_num": self.sequence_num,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
        }


@dataclass
class AuditEvent:
    """
    A single audit event capturing agent behavior.
    
    Events are the fundamental unit of the audit log. Each event is
    self-contained with all information needed to understand what
    happened, when, why, and in what context.
    """
    event_id: UUID
    timestamp: datetime
    event_type: EventType
    severity: Severity
    context: EventContext
    payload: dict[str, Any]
    integrity: IntegrityData
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "context": self.context.to_dict(),
            "payload": self.payload,
            "integrity": self.integrity.to_dict(),
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


class PIIDetector(Protocol):
    """Protocol for PII detection implementations."""
    
    def detect(self, text: str) -> list[tuple[int, int, str]]:
        """
        Detect PII in text.
        
        Returns list of (start, end, pii_type) tuples.
        """
        ...


class PIITokenizer:
    """
    Tokenizes PII for privacy-preserving logging.
    
    Replaces detected PII with tokens that can be resolved through
    a separate, access-controlled mapping service.
    """
    
    def __init__(self, detector: PIIDetector | None = None):
        self._detector = detector
        # Bounded LRU keeps the in-process plaintext->token map from growing
        # without bound. In production, persist this mapping (encrypted) in
        # the access-controlled service described in the class docstring and
        # look up on demand rather than retaining plaintext PII in memory.
        from cachetools import LRUCache
        self._token_map: LRUCache = LRUCache(maxsize=10000)
        self._lock = threading.Lock()
    
    def tokenize(self, value: str) -> str:
        """Replace PII with tokens."""
        if not self._detector:
            return value
        
        detections = self._detector.detect(value)
        if not detections:
            return value
        
        # Process detections in reverse order to preserve positions
        result = value
        for start, end, pii_type in sorted(detections, reverse=True):
            original = value[start:end]
            token = self._get_or_create_token(original, pii_type)
            result = result[:start] + token + result[end:]
        
        return result
    
    def _get_or_create_token(self, original: str, pii_type: str) -> str:
        """Get existing token or create new one for PII value."""
        with self._lock:
            if original not in self._token_map:
                token_id = hashlib.sha256(
                    f"{original}:{uuid4()}".encode()
                ).hexdigest()[:12]
                self._token_map[original] = f"[PII:{pii_type}:{token_id}]"
            return self._token_map[original]


class AuditSink(ABC):
    """
    Abstract base for audit log destinations.
    
    Sinks receive audit events and persist them. Different sinks
    can write to different destinations (files, databases, cloud
    services) while maintaining consistent event format.
    """
    
    @abstractmethod
    def write(self, event: AuditEvent) -> None:
        """Write an event to the sink."""
        pass
    
    @abstractmethod
    def flush(self) -> None:
        """Ensure all buffered events are persisted."""
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close the sink and release resources."""
        pass


class FileSink(AuditSink):
    """
    Writes audit events to append-only log files.
    
    Files are rotated based on size or time. Each line contains
    a complete JSON event for easy parsing and streaming.
    """
    
    def __init__(
        self,
        base_path: str,
        max_size_bytes: int = 100 * 1024 * 1024,  # 100MB
        buffer_size: int = 100,
    ):
        self._base_path = base_path
        self._max_size = max_size_bytes
        self._buffer_size = buffer_size
        self._buffer: list[AuditEvent] = []
        self._current_file: Any = None
        self._current_size = 0
        self._lock = threading.Lock()
        self._file_counter = 0
        
        self._open_new_file()
    
    def _open_new_file(self) -> None:
        """Open a new log file."""
        if self._current_file:
            self._current_file.close()
        
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{self._base_path}/audit_{timestamp}_{self._file_counter}.jsonl"
        # Explicit UTF-8 encoding (the audit log carries JSON with potentially
        # non-ASCII PII); line buffering so each event is durable on flush even
        # if the writer dies mid-buffer.
        self._current_file = open(filename, "a", encoding="utf-8", buffering=1)
        self._current_size = 0
        self._file_counter += 1
    
    def write(self, event: AuditEvent) -> None:
        """Buffer and write event to file."""
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self._buffer_size:
                self._flush_buffer()
    
    def _flush_buffer(self) -> None:
        """Write buffered events to file."""
        for event in self._buffer:
            line = event.to_json() + "\n"
            line_bytes = len(line.encode("utf-8"))
            
            if self._current_size + line_bytes > self._max_size:
                self._open_new_file()
            
            self._current_file.write(line)
            self._current_size += line_bytes
        
        self._buffer.clear()
        self._current_file.flush()
    
    def flush(self) -> None:
        """Flush buffer to disk."""
        with self._lock:
            self._flush_buffer()
    
    def close(self) -> None:
        """Close the sink."""
        self.flush()
        if self._current_file:
            self._current_file.close()


class AuditLogger:
    """
    Production audit logger for AI agents.
    
    This class provides the main interface for recording audit events.
    It handles event creation, integrity chain maintenance, PII
    tokenization, and delivery to configured sinks.
    
    Example usage:
        
        logger = AuditLogger(
            agent_id="customer-service-v2",
            agent_version="2.3.1",
            sinks=[FileSink("/var/log/agent-audit")],
        )
        
        with logger.session() as session:
            session.log_decision(
                goal="Process refund request",
                options=[
                    {"action": "approve", "score": 0.9},
                    {"action": "deny", "score": 0.1},
                ],
                selection="approve",
                rationale="Order was delivered late",
                confidence=0.92,
            )
    """
    
    def __init__(
        self,
        agent_id: str,
        agent_version: str,
        sinks: list[AuditSink],
        pii_tokenizer: PIITokenizer | None = None,
        environment: str = "production",
        max_retries: int = 3,
        initial_backoff_seconds: float = 0.1,
        dlq_capacity: int = 1000,
    ):
        self._agent_id = agent_id
        self._agent_version = agent_version
        self._sinks = sinks
        self._pii_tokenizer = pii_tokenizer
        self._environment = environment
        self._sequence_lock = threading.Lock()
        self._sequence_num = 0
        self._previous_hash = "genesis"

        # Reliability primitives for the audit pipeline. Losing audit events is
        # a security event in itself, so failures here are handled with bounded
        # retries, a dead-letter queue, and explicit failure counters that
        # operations should alert on. In a more complete system, replace these
        # with chapter 7's RetryPolicy and a durable DLQ (e.g., S3, SQS).
        self._max_retries = max_retries
        self._initial_backoff_seconds = initial_backoff_seconds
        # Bounded deque so a sustained outage cannot exhaust memory. Older
        # un-replayed events are dropped first; the failure counter still
        # captures the total loss count for alerting.
        self._dead_letter_queue: deque[tuple[str, AuditEvent, str]] = deque(
            maxlen=dlq_capacity
        )
        self._dlq_lock = threading.Lock()
        # Prometheus-style counter: audit_write_failures_total{op="write|flush|close"}.
        # Operators MUST page on a non-zero rate here.
        self._failure_counts: dict[str, int] = {
            "write": 0,
            "flush": 0,
            "close": 0,
        }
    
    @contextmanager
    def session(
        self,
        session_id: UUID | None = None,
        trace_id: UUID | None = None,
    ) -> Iterator[AuditSession]:
        """
        Create an audit session for a unit of agent work.
        
        Sessions group related events and manage the integrity chain
        within that group. Use a new session for each agent task,
        conversation, or transaction.
        """
        session_id = session_id or uuid4()
        trace_id = trace_id or uuid4()
        
        context = EventContext(
            session_id=session_id,
            agent_id=self._agent_id,
            agent_version=self._agent_version,
            trace_id=trace_id,
            environment=self._environment,
        )
        
        session = AuditSession(
            logger=self,
            context=context,
        )
        
        # Log session start
        session.log_event(
            event_type=EventType.SESSION_START,
            severity=Severity.INFO,
            payload={"message": "Audit session started"},
        )
        
        try:
            yield session
        finally:
            # Log session end
            session.log_event(
                event_type=EventType.SESSION_END,
                severity=Severity.INFO,
                payload={
                    "message": "Audit session ended",
                    "event_count": session.event_count,
                },
            )
            self._flush_all()
    
    def _create_event(
        self,
        event_type: EventType,
        severity: Severity,
        context: EventContext,
        payload: dict[str, Any],
    ) -> AuditEvent:
        """Create an audit event with integrity chain."""
        # Tokenize PII in payload
        if self._pii_tokenizer:
            payload = self._tokenize_payload(payload)
        
        with self._sequence_lock:
            self._sequence_num += 1
            sequence_num = self._sequence_num
            previous_hash = self._previous_hash
        
        # Create event without hash first
        integrity = IntegrityData(
            sequence_num=sequence_num,
            previous_hash=previous_hash,
        )
        
        event = AuditEvent(
            event_id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            severity=severity,
            context=context,
            payload=payload,
            integrity=integrity,
        )
        
        # Calculate event hash over a canonical serialization that excludes
        # the event_hash field itself, so the hash is independent of dict
        # ordering and self-referential fields.
        payload = event.to_dict()
        payload.get("integrity", {}).pop("event_hash", None)
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str
        )
        event_hash = hashlib.sha256(canonical.encode()).hexdigest()
        event.integrity.event_hash = event_hash
        
        # Update chain
        with self._sequence_lock:
            self._previous_hash = event_hash
        
        return event
    
    def _tokenize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Recursively tokenize PII in payload."""
        result = {}
        for key, value in payload.items():
            if isinstance(value, str):
                result[key] = self._pii_tokenizer.tokenize(value)
            elif isinstance(value, dict):
                result[key] = self._tokenize_payload(value)
            elif isinstance(value, list):
                result[key] = [
                    self._tokenize_payload(item) if isinstance(item, dict)
                    else self._pii_tokenizer.tokenize(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result
    
    def _retry_with_backoff(
        self,
        op_name: str,
        func: Any,
        event: AuditEvent | None = None,
    ) -> bool:
        """
        Run ``func`` with bounded exponential backoff retries.

        Returns ``True`` on success, ``False`` if every retry failed. On final
        failure, the event (if any) is appended to the dead-letter queue, the
        per-op failure counter is incremented, and the failure is logged at
        CRITICAL because audit-pipeline loss is itself a security event.
        """
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                func()
                return True
            except Exception as e:  # noqa: BLE001 -- intentional broad catch
                last_error = e
                if attempt < self._max_retries - 1:
                    # Exponential backoff: 0.1s, 0.2s, 0.4s, ...
                    backoff = self._initial_backoff_seconds * (2 ** attempt)
                    logging.warning(
                        "Audit %s attempt %d/%d failed: %s; retrying in %.2fs",
                        op_name, attempt + 1, self._max_retries, e, backoff,
                    )
                    time.sleep(backoff)

        # All retries exhausted -- record the failure for forensics + alerting.
        with self._dlq_lock:
            self._failure_counts[op_name] = self._failure_counts.get(op_name, 0) + 1
            if event is not None:
                self._dead_letter_queue.append(
                    (op_name, event, repr(last_error))
                )
        logging.critical(
            "Audit %s failed after %d retries; event diverted to DLQ. "
            "audit_write_failures_total{op=%s}=%d. Last error: %s",
            op_name, self._max_retries, op_name,
            self._failure_counts[op_name], last_error,
        )
        return False

    def _write_event(self, event: AuditEvent) -> None:
        """Write event to all configured sinks with bounded retry + DLQ."""
        for sink in self._sinks:
            self._retry_with_backoff(
                "write", lambda s=sink: s.write(event), event=event
            )

    def _flush_all(self) -> None:
        """Flush all sinks with bounded retry."""
        for sink in self._sinks:
            self._retry_with_backoff("flush", sink.flush)

    def close(self) -> None:
        """Close the logger and all sinks with bounded retry."""
        self._flush_all()
        for sink in self._sinks:
            self._retry_with_backoff("close", sink.close)

    @property
    def dead_letter_queue(self) -> tuple[tuple[str, AuditEvent, str], ...]:
        """Snapshot of events that failed to persist after all retries."""
        with self._dlq_lock:
            return tuple(self._dead_letter_queue)

    @property
    def failure_counts(self) -> dict[str, int]:
        """Per-operation failure counters for monitoring."""
        with self._dlq_lock:
            return dict(self._failure_counts)


class AuditSession:
    """
    An audit session for a unit of agent work.
    
    Sessions provide convenience methods for logging common event
    types and manage context like span IDs for operation tracing.
    """
    
    def __init__(self, logger: AuditLogger, context: EventContext):
        self._logger = logger
        self._context = context
        self._event_count = 0
        self._span_stack: list[UUID] = []
    
    @property
    def event_count(self) -> int:
        return self._event_count
    
    @property
    def session_id(self) -> UUID:
        return self._context.session_id
    
    @contextmanager
    def span(self, name: str) -> Iterator[UUID]:
        """
        Create a span for tracing an operation.
        
        Spans nest to form a tree representing the operation hierarchy.
        """
        span_id = uuid4()
        parent_span_id = self._span_stack[-1] if self._span_stack else None
        
        # Push span onto stack
        self._span_stack.append(span_id)
        original_span = self._context.span_id
        original_parent = self._context.parent_span_id
        self._context.span_id = span_id
        self._context.parent_span_id = parent_span_id
        
        try:
            yield span_id
        finally:
            # Pop span from stack
            self._span_stack.pop()
            self._context.span_id = original_span
            self._context.parent_span_id = original_parent
    
    def log_event(
        self,
        event_type: EventType,
        severity: Severity,
        payload: dict[str, Any],
    ) -> AuditEvent:
        """Log a generic audit event."""
        event = self._logger._create_event(
            event_type=event_type,
            severity=severity,
            context=self._context,
            payload=payload,
        )
        self._logger._write_event(event)
        self._event_count += 1
        return event
    
    def log_decision(
        self,
        goal: str,
        options: list[dict[str, Any]],
        selection: str,
        rationale: str,
        confidence: float,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Log an agent decision.
        
        Decision logging is critical for explainability and compliance.
        Capture the goal, all options considered, the selection made,
        and the reasoning behind it.
        
        Args:
            goal: What the agent was trying to accomplish
            options: List of options considered with scores
            selection: The option selected
            rationale: Human-readable explanation of the decision
            confidence: Confidence score (0.0 to 1.0)
            metadata: Additional context
        """
        payload = {
            "goal": goal,
            "options_considered": options,
            "selection": selection,
            "rationale": rationale,
            "confidence": confidence,
        }
        if metadata:
            payload["metadata"] = metadata
        
        severity = (
            Severity.WARNING if confidence < 0.5
            else Severity.INFO
        )
        
        return self.log_event(
            event_type=EventType.DECISION,
            severity=severity,
            payload=payload,
        )
    
    def log_tool_call(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        result: Any,
        duration_ms: float,
        success: bool = True,
        error: str | None = None,
    ) -> AuditEvent:
        """
        Log an external tool call.
        
        Tool calls represent agent interactions with external systems.
        Logging captures what was requested, what was returned, and
        performance characteristics.
        """
        payload = {
            "tool_name": tool_name,
            "parameters": parameters,
            "result_summary": self._summarize_result(result),
            "duration_ms": duration_ms,
            "success": success,
        }
        if error:
            payload["error"] = error
        
        severity = Severity.ERROR if not success else Severity.INFO
        
        return self.log_event(
            event_type=EventType.TOOL_CALL,
            severity=severity,
            payload=payload,
        )
    
    def log_data_access(
        self,
        source: str,
        query: str,
        purpose: str,
        data_subjects: list[str] | None = None,
        record_count: int | None = None,
    ) -> AuditEvent:
        """
        Log a data access event.
        
        Data access logging is essential for privacy compliance,
        particularly under GDPR and similar regulations. Capture
        what data was accessed and why.
        """
        payload = {
            "source": source,
            "query": query,
            "purpose": purpose,
        }
        if data_subjects:
            payload["data_subjects"] = data_subjects
        if record_count is not None:
            payload["record_count"] = record_count
        
        return self.log_event(
            event_type=EventType.DATA_ACCESS,
            severity=Severity.INFO,
            payload=payload,
        )
    
    def log_error(
        self,
        error_type: str,
        message: str,
        context: dict[str, Any] | None = None,
        recovery_action: str | None = None,
        stack_trace: str | None = None,
    ) -> AuditEvent:
        """
        Log an error event.
        
        Error logging captures failures and how the agent responded.
        Include enough context for debugging without exposing
        sensitive information.
        """
        payload = {
            "error_type": error_type,
            "message": message,
        }
        if context:
            payload["error_context"] = context
        if recovery_action:
            payload["recovery_action"] = recovery_action
        if stack_trace:
            # Truncate stack traces to avoid log bloat
            payload["stack_trace"] = stack_trace[:2000]
        
        return self.log_event(
            event_type=EventType.ERROR,
            severity=Severity.ERROR,
            payload=payload,
        )
    
    def log_policy_check(
        self,
        policy_name: str,
        action_requested: str,
        decision: str,
        reason: str,
    ) -> AuditEvent:
        """
        Log a policy enforcement check.
        
        Policy checks record when guardrails or policies were
        evaluated and their outcomes.
        """
        payload = {
            "policy_name": policy_name,
            "action_requested": action_requested,
            "decision": decision,
            "reason": reason,
        }
        
        severity = (
            Severity.WARNING if decision == "denied"
            else Severity.INFO
        )
        
        return self.log_event(
            event_type=EventType.POLICY_CHECK,
            severity=severity,
            payload=payload,
        )
    
    def log_human_override(
        self,
        original_decision: str,
        override_decision: str,
        operator_id: str,
        reason: str,
    ) -> AuditEvent:
        """
        Log a human override of agent behavior.
        
        Human overrides are important accountability events that
        should always be captured.
        """
        payload = {
            "original_decision": original_decision,
            "override_decision": override_decision,
            "operator_id": operator_id,
            "reason": reason,
        }
        
        return self.log_event(
            event_type=EventType.HUMAN_OVERRIDE,
            severity=Severity.WARNING,
            payload=payload,
        )
    
    def _summarize_result(self, result: Any) -> Any:
        """Create a summary of a result for logging."""
        if result is None:
            return None
        if isinstance(result, (bool, int, float)):
            return result
        if isinstance(result, str):
            if len(result) > 500:
                return f"{result[:500]}... (truncated, {len(result)} chars)"
            return result
        if isinstance(result, dict):
            return {"_type": "dict", "_keys": list(result.keys())}
        if isinstance(result, list):
            return {"_type": "list", "_length": len(result)}
        return {"_type": type(result).__name__}

# ============================================================================
# Block 6 (chapter listing #6)
# ============================================================================

"""
decision_trail.py - Capture complete agent decision trails

Decision trails provide a complete record of how an agent arrived
at a conclusion, including all intermediate reasoning steps, data
consulted, and alternatives considered.
"""


from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

# AuditSession, EventType, Severity are defined earlier in this same module
# (Block 1 and Block 2). Earlier drafts imported them from a hypothetical
# separate `audit_logger` package; that import is dropped here because the
# symbols are already in scope when the chapter file is run end-to-end.


class ReasoningStepType(Enum):
    """Types of reasoning steps in a decision trail."""
    GOAL_FORMATION = "goal_formation"
    INFORMATION_GATHERING = "information_gathering"
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    HYPOTHESIS_EVALUATION = "hypothesis_evaluation"
    CONSTRAINT_CHECK = "constraint_check"
    OPTION_GENERATION = "option_generation"
    OPTION_EVALUATION = "option_evaluation"
    SELECTION = "selection"
    CONFIDENCE_ASSESSMENT = "confidence_assessment"


@dataclass
class ReasoningStep:
    """A single step in the agent's reasoning process."""
    step_id: UUID
    step_type: ReasoningStepType
    timestamp: datetime
    input_state: dict[str, Any]
    output_state: dict[str, Any]
    reasoning: str
    confidence: float | None = None
    duration_ms: float | None = None


@dataclass
class DecisionTrail:
    """
    Complete record of the reasoning process for a decision.
    
    A decision trail captures the full chain of reasoning that led
    to an agent decision. This is essential for:
    - Explaining decisions to stakeholders
    - Debugging unexpected behavior
    - Compliance with explainability requirements
    - Improving agent performance through analysis
    """
    trail_id: UUID
    goal: str
    started_at: datetime
    completed_at: datetime | None = None
    steps: list[ReasoningStep] = field(default_factory=list)
    final_decision: str | None = None
    final_confidence: float | None = None
    outcome: str | None = None
    
    def add_step(
        self,
        step_type: ReasoningStepType,
        input_state: dict[str, Any],
        output_state: dict[str, Any],
        reasoning: str,
        confidence: float | None = None,
        duration_ms: float | None = None,
    ) -> ReasoningStep:
        """Add a reasoning step to the trail."""
        step = ReasoningStep(
            step_id=uuid4(),
            step_type=step_type,
            timestamp=datetime.now(timezone.utc),
            input_state=input_state,
            output_state=output_state,
            reasoning=reasoning,
            confidence=confidence,
            duration_ms=duration_ms,
        )
        self.steps.append(step)
        return step
    
    def complete(
        self,
        decision: str,
        confidence: float,
        outcome: str | None = None,
    ) -> None:
        """Mark the decision trail as complete."""
        self.completed_at = datetime.now(timezone.utc)
        self.final_decision = decision
        self.final_confidence = confidence
        self.outcome = outcome
    
    def to_dict(self) -> dict[str, Any]:
        """Convert trail to dictionary for logging."""
        return {
            "trail_id": str(self.trail_id),
            "goal": self.goal,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "step_count": len(self.steps),
            "steps": [
                {
                    "step_id": str(step.step_id),
                    "step_type": step.step_type.value,
                    "timestamp": step.timestamp.isoformat(),
                    "reasoning": step.reasoning,
                    "confidence": step.confidence,
                    "duration_ms": step.duration_ms,
                }
                for step in self.steps
            ],
            "final_decision": self.final_decision,
            "final_confidence": self.final_confidence,
            "outcome": self.outcome,
        }


class DecisionTrailCapture:
    """
    Captures decision trails during agent execution.
    
    This class integrates with the audit logger to capture and
    persist complete decision trails.
    
    Example usage:
        
        capture = DecisionTrailCapture(audit_session)
        
        with capture.trail("Determine refund eligibility") as trail:
            # Information gathering
            trail.add_step(
                step_type=ReasoningStepType.INFORMATION_GATHERING,
                input_state={"customer_id": "12345"},
                output_state={"order_history": [...], "refund_history": [...]},
                reasoning="Retrieved customer order and refund history",
            )
            
            # Decision logic...
            
            trail.complete(
                decision="approve_refund",
                confidence=0.95,
            )
    """
    
    def __init__(self, session: AuditSession):
        self._session = session
        self._active_trails: dict[UUID, DecisionTrail] = {}
    
    def trail(self, goal: str) -> DecisionTrailContext:
        """Create a new decision trail context manager."""
        trail = DecisionTrail(
            trail_id=uuid4(),
            goal=goal,
            started_at=datetime.now(timezone.utc),
        )
        return DecisionTrailContext(self, trail)
    
    def _register_trail(self, trail: DecisionTrail) -> None:
        """Register an active trail."""
        self._active_trails[trail.trail_id] = trail
    
    def _finalize_trail(self, trail: DecisionTrail) -> None:
        """Finalize and log a completed trail."""
        if trail.trail_id in self._active_trails:
            del self._active_trails[trail.trail_id]
        
        # Log the complete trail
        self._session.log_event(
            event_type=EventType.DECISION,
            severity=(
                Severity.WARNING if (trail.final_confidence or 0) < 0.5
                else Severity.INFO
            ),
            payload={
                "trail_type": "decision_trail",
                "trail": trail.to_dict(),
            },
        )


class DecisionTrailContext:
    """Context manager for decision trail capture."""
    
    def __init__(self, capture: DecisionTrailCapture, trail: DecisionTrail):
        self._capture = capture
        self._trail = trail
    
    def __enter__(self) -> DecisionTrail:
        self._capture._register_trail(self._trail)
        return self._trail
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            # Record error in trail
            self._trail.add_step(
                step_type=ReasoningStepType.CONSTRAINT_CHECK,
                input_state={"error_type": str(exc_type)},
                output_state={"error": str(exc_val)},
                reasoning=f"Trail terminated due to error: {exc_val}",
            )
            self._trail.complete(
                decision="error",
                confidence=0.0,
                outcome=f"Failed: {exc_val}",
            )
        elif self._trail.final_decision is None:
            # Trail not explicitly completed
            self._trail.complete(
                decision="incomplete",
                confidence=0.0,
                outcome="Trail context exited without explicit completion",
            )
        
        self._capture._finalize_trail(self._trail)

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

"""
integrity_verification.py - Verify tamper-evident audit log chains

This module provides tools for verifying the integrity of audit log
chains, detecting any tampering or corruption.
"""


import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


class VerificationResult(Enum):
    """Result of integrity verification."""
    VALID = "valid"
    INVALID_HASH = "invalid_hash"
    BROKEN_CHAIN = "broken_chain"
    MISSING_EVENTS = "missing_events"
    SEQUENCE_GAP = "sequence_gap"
    TIMESTAMP_ANOMALY = "timestamp_anomaly"


@dataclass
class VerificationReport:
    """Report from integrity verification."""
    result: VerificationResult
    events_checked: int
    first_invalid_event: int | None
    details: str
    anomalies: list[dict[str, Any]]
    
    @property
    def is_valid(self) -> bool:
        return self.result == VerificationResult.VALID


class IntegrityVerifier:
    """
    Verifies the integrity of audit log chains.
    
    The verifier checks:
    1. Each event's hash matches its contents
    2. The chain of previous_hash references is unbroken
    3. Sequence numbers are monotonic without gaps
    4. Timestamps are non-decreasing within tolerance (allowing for clock
       granularity and bounded skew across writers)
    
    Example usage:
        
        verifier = IntegrityVerifier()
        
        # Verify a log file
        report = verifier.verify_file("/var/log/agent-audit/audit_20260428.jsonl")
        
        if not report.is_valid:
            print(f"Integrity violation: {report.details}")
            for anomaly in report.anomalies:
                print(f"  Event {anomaly['sequence_num']}: {anomaly['issue']}")
    """
    
    def verify_file(self, file_path: str | Path) -> VerificationReport:
        """Verify integrity of events in a log file."""
        path = Path(file_path)
        if not path.exists():
            return VerificationReport(
                result=VerificationResult.MISSING_EVENTS,
                events_checked=0,
                first_invalid_event=None,
                details=f"File not found: {file_path}",
                anomalies=[],
            )
        
        events = list(self._read_events(path))
        return self.verify_events(events)
    
    def verify_events(self, events: list[dict[str, Any]]) -> VerificationReport:
        """Verify integrity of a list of events."""
        if not events:
            return VerificationReport(
                result=VerificationResult.VALID,
                events_checked=0,
                first_invalid_event=None,
                details="No events to verify",
                anomalies=[],
            )
        
        anomalies: list[dict[str, Any]] = []
        expected_previous_hash = "genesis"
        expected_sequence = 1
        last_timestamp: datetime | None = None
        
        for i, event in enumerate(events):
            integrity = event.get("integrity", {})
            sequence_num = integrity.get("sequence_num")
            previous_hash = integrity.get("previous_hash")
            stored_hash = integrity.get("event_hash")
            
            # Check sequence continuity
            if sequence_num != expected_sequence:
                anomalies.append({
                    "event_index": i,
                    "sequence_num": sequence_num,
                    "issue": f"Sequence gap: expected {expected_sequence}, got {sequence_num}",
                    "severity": "error",
                })
            
            # Check chain continuity
            if previous_hash != expected_previous_hash:
                anomalies.append({
                    "event_index": i,
                    "sequence_num": sequence_num,
                    "issue": f"Chain broken: expected previous_hash {expected_previous_hash[:16]}..., got {previous_hash[:16] if previous_hash else 'None'}...",
                    "severity": "critical",
                })
            
            # Verify event hash
            calculated_hash = self._calculate_event_hash(event)
            if calculated_hash != stored_hash:
                anomalies.append({
                    "event_index": i,
                    "sequence_num": sequence_num,
                    "issue": f"Hash mismatch: stored {stored_hash[:16]}..., calculated {calculated_hash[:16]}...",
                    "severity": "critical",
                })
            
            # Check timestamp ordering
            event_timestamp = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            )
            if last_timestamp and event_timestamp < last_timestamp:
                anomalies.append({
                    "event_index": i,
                    "sequence_num": sequence_num,
                    "issue": f"Timestamp anomaly: {event_timestamp} is before previous {last_timestamp}",
                    "severity": "warning",
                })
            
            # Update expectations for next event
            expected_previous_hash = stored_hash
            expected_sequence = sequence_num + 1
            last_timestamp = event_timestamp
        
        # Determine overall result
        if not anomalies:
            return VerificationReport(
                result=VerificationResult.VALID,
                events_checked=len(events),
                first_invalid_event=None,
                details="All events verified successfully",
                anomalies=[],
            )
        
        critical_anomalies = [a for a in anomalies if a["severity"] == "critical"]
        if critical_anomalies:
            first_critical = critical_anomalies[0]
            if "Hash mismatch" in first_critical["issue"]:
                result = VerificationResult.INVALID_HASH
            else:
                result = VerificationResult.BROKEN_CHAIN
        elif any(a["severity"] == "error" for a in anomalies):
            result = VerificationResult.SEQUENCE_GAP
        else:
            result = VerificationResult.TIMESTAMP_ANOMALY
        
        return VerificationReport(
            result=result,
            events_checked=len(events),
            first_invalid_event=anomalies[0]["event_index"],
            details=f"Found {len(anomalies)} anomalies in audit log",
            anomalies=anomalies,
        )
    
    def _read_events(self, path: Path) -> Iterator[dict[str, Any]]:
        """Read events from a JSONL file."""
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)
    
    def _calculate_event_hash(self, event: dict[str, Any]) -> str:
        """Calculate hash for an event."""
        # Match the writer's canonical serialization exactly: sorted keys and
        # the same compact separators used by AuditLogger._create_event.
        # Any drift here makes verification produce false-positive mismatches.
        event_copy = json.loads(json.dumps(event))
        event_copy["integrity"]["event_hash"] = ""
        event_json = json.dumps(
            event_copy, sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(event_json.encode()).hexdigest()


class PeriodicCheckpointer:
    """
    Creates periodic integrity checkpoints.
    
    Checkpoints capture the state of the audit chain at specific
    points, enabling detection of tampering even if an attacker
    tries to rewrite history consistently.
    
    Checkpoints can be:
    - Stored in a separate, append-only system
    - Published to a blockchain or timestamping service
    - Distributed to multiple independent parties
    """
    
    def __init__(
        self,
        checkpoint_interval: int = 1000,
        checkpoint_sink: callable | None = None,
    ):
        self._interval = checkpoint_interval
        self._sink = checkpoint_sink
        self._events_since_checkpoint = 0
        self._last_checkpoint_hash: str | None = None
    
    def record_event(self, event_hash: str, sequence_num: int) -> dict | None:
        """
        Record an event and create checkpoint if needed.
        
        Returns checkpoint data if a checkpoint was created.
        """
        self._events_since_checkpoint += 1
        
        if self._events_since_checkpoint >= self._interval:
            checkpoint = self._create_checkpoint(event_hash, sequence_num)
            self._events_since_checkpoint = 0
            
            if self._sink:
                self._sink(checkpoint)
            
            return checkpoint
        
        return None
    
    def _create_checkpoint(
        self,
        event_hash: str,
        sequence_num: int,
    ) -> dict[str, Any]:
        """Create an integrity checkpoint."""
        checkpoint = {
            "checkpoint_type": "audit_integrity",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence_num": sequence_num,
            "event_hash": event_hash,
            "previous_checkpoint_hash": self._last_checkpoint_hash,
            "events_in_interval": self._events_since_checkpoint,
        }
        
        # Calculate checkpoint hash
        checkpoint_json = json.dumps(checkpoint, sort_keys=True)
        checkpoint_hash = hashlib.sha256(checkpoint_json.encode()).hexdigest()
        checkpoint["checkpoint_hash"] = checkpoint_hash
        
        self._last_checkpoint_hash = checkpoint_hash
        
        return checkpoint

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

"""
audit_query.py - Query interface for compliance investigations

This module provides a query interface for searching and analyzing
audit logs during compliance investigations, incident response,
and routine audits.
"""


from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Iterator
import json
from pathlib import Path


class QueryOperator(Enum):
    """Operators for query conditions."""
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    CONTAINS = "contains"
    IN = "in"
    REGEX = "regex"


@dataclass
class QueryCondition:
    """A single condition in an audit query."""
    field: str
    operator: QueryOperator
    value: Any
    
    def matches(self, event: dict[str, Any]) -> bool:
        """Check if an event matches this condition."""
        actual = self._get_nested_value(event, self.field)
        
        if actual is None and self.operator != QueryOperator.EQUALS:
            return False
        
        if self.operator == QueryOperator.EQUALS:
            return actual == self.value
        elif self.operator == QueryOperator.NOT_EQUALS:
            return actual != self.value
        elif self.operator == QueryOperator.GREATER_THAN:
            return actual > self.value
        elif self.operator == QueryOperator.LESS_THAN:
            return actual < self.value
        elif self.operator == QueryOperator.CONTAINS:
            return self.value in str(actual)
        elif self.operator == QueryOperator.IN:
            return actual in self.value
        elif self.operator == QueryOperator.REGEX:
            import re
            return bool(re.search(self.value, str(actual)))
        
        return False
    
    def _get_nested_value(self, obj: dict, path: str) -> Any:
        """Get a value from a nested dictionary using dot notation."""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current


@dataclass
class TimeRange:
    """A time range for filtering events."""
    start: datetime
    end: datetime
    
    @classmethod
    def last_hours(cls, hours: int) -> TimeRange:
        """Create a time range for the last N hours (UTC)."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        return cls(start=start, end=end)

    @classmethod
    def last_days(cls, days: int) -> TimeRange:
        """Create a time range for the last N days (UTC)."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        return cls(start=start, end=end)


class AuditQuery:
    """
    Build and execute queries against audit logs.
    
    This class provides a fluent interface for building complex
    queries against audit log data.
    
    Example usage:
        
        query = (
            AuditQuery()
            .time_range(TimeRange.last_days(7))
            .where("event_type", QueryOperator.EQUALS, "decision")
            .where("payload.confidence", QueryOperator.LESS_THAN, 0.5)
            .where("context.agent_id", QueryOperator.EQUALS, "trading-agent-v1")
            .order_by("timestamp", descending=True)
            .limit(100)
        )
        
        results = query_engine.execute(query)
    """
    
    def __init__(self):
        self._time_range: TimeRange | None = None
        self._conditions: list[QueryCondition] = []
        self._order_by_field: str | None = None
        self._order_descending: bool = False
        self._limit_value: int | None = None
        self._offset_value: int = 0
    
    def time_range(self, range: TimeRange) -> AuditQuery:
        """Filter events to a specific time range."""
        self._time_range = range
        return self
    
    def where(
        self,
        field: str,
        operator: QueryOperator,
        value: Any,
    ) -> AuditQuery:
        """Add a filter condition."""
        self._conditions.append(QueryCondition(field, operator, value))
        return self
    
    def order_by(self, field: str, descending: bool = False) -> AuditQuery:
        """Set the ordering for results."""
        self._order_by_field = field
        self._order_descending = descending
        return self
    
    def limit(self, count: int) -> AuditQuery:
        """Limit the number of results."""
        self._limit_value = count
        return self
    
    def offset(self, count: int) -> AuditQuery:
        """Skip the first N results."""
        self._offset_value = count
        return self


@dataclass
class QueryResult:
    """Results from an audit query."""
    events: list[dict[str, Any]]
    total_count: int
    query_time_ms: float
    
    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.events)
    
    def __len__(self) -> int:
        return len(self.events)


class FileQueryEngine:
    """
    Query engine for file-based audit logs.
    
    This engine executes queries against JSONL audit log files.
    For production systems with large log volumes, consider using
    Elasticsearch or a similar search system.
    """
    
    def __init__(self, log_directory: str | Path):
        self._log_dir = Path(log_directory)
    
    def execute(self, query: AuditQuery) -> QueryResult:
        """Execute a query and return results."""
        import time
        start_time = time.time()
        
        matching_events: list[dict[str, Any]] = []
        
        # Find relevant log files based on time range
        log_files = self._find_log_files(query._time_range)
        
        for log_file in log_files:
            for event in self._read_events(log_file):
                if self._matches_query(event, query):
                    matching_events.append(event)
        
        # Apply ordering
        if query._order_by_field:
            matching_events.sort(
                key=lambda e: self._get_nested_value(e, query._order_by_field) or "",
                reverse=query._order_descending,
            )
        
        total_count = len(matching_events)
        
        # Apply offset and limit
        if query._offset_value:
            matching_events = matching_events[query._offset_value:]
        if query._limit_value:
            matching_events = matching_events[:query._limit_value]
        
        query_time_ms = (time.time() - start_time) * 1000
        
        return QueryResult(
            events=matching_events,
            total_count=total_count,
            query_time_ms=query_time_ms,
        )
    
    def _find_log_files(self, time_range: TimeRange | None) -> list[Path]:
        """Find log files that may contain events in the time range."""
        if not self._log_dir.exists():
            return []
        
        # For simplicity, return all log files
        # A production implementation would filter by file timestamps
        return sorted(self._log_dir.glob("audit_*.jsonl"))
    
    def _read_events(self, path: Path) -> Iterator[dict[str, Any]]:
        """Read events from a log file."""
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)
    
    def _matches_query(self, event: dict[str, Any], query: AuditQuery) -> bool:
        """Check if an event matches a query."""
        # Check time range
        if query._time_range:
            event_time = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            )
            if event_time < query._time_range.start or event_time > query._time_range.end:
                return False
        
        # Check all conditions
        for condition in query._conditions:
            if not condition.matches(event):
                return False
        
        return True
    
    def _get_nested_value(self, obj: dict, path: str) -> Any:
        """Get a value from a nested dictionary using dot notation."""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current


class ComplianceReporter:
    """
    Generate compliance reports from audit data.
    
    This class provides pre-built queries and reports for common
    compliance scenarios.
    """
    
    def __init__(self, query_engine: FileQueryEngine):
        self._engine = query_engine
    
    def data_access_report(
        self,
        data_subject_id: str,
        time_range: TimeRange,
    ) -> dict[str, Any]:
        """
        Generate GDPR data access report for a data subject.
        
        This report answers: "What data did we access about this
        individual, when, and why?"
        """
        query = (
            AuditQuery()
            .time_range(time_range)
            .where("event_type", QueryOperator.EQUALS, "data_access")
            .where("payload.data_subjects", QueryOperator.CONTAINS, data_subject_id)
            .order_by("timestamp")
        )
        
        results = self._engine.execute(query)
        
        return {
            "report_type": "data_access",
            "data_subject_id": data_subject_id,
            "time_range": {
                "start": time_range.start.isoformat(),
                "end": time_range.end.isoformat(),
            },
            "access_count": len(results),
            "accesses": [
                {
                    "timestamp": event["timestamp"],
                    "source": event["payload"].get("source"),
                    "purpose": event["payload"].get("purpose"),
                    "agent_id": event["context"].get("agent_id"),
                }
                for event in results
            ],
        }
    
    def decision_audit_report(
        self,
        session_id: str,
    ) -> dict[str, Any]:
        """
        Generate decision audit report for a session.
        
        This report provides complete traceability for all decisions
        made in a session.
        """
        query = (
            AuditQuery()
            .where("context.session_id", QueryOperator.EQUALS, session_id)
            .order_by("timestamp")
        )
        
        results = self._engine.execute(query)
        
        decisions = [
            event for event in results
            if event["event_type"] == "decision"
        ]
        
        return {
            "report_type": "decision_audit",
            "session_id": session_id,
            "total_events": len(results),
            "decision_count": len(decisions),
            "decisions": [
                {
                    "timestamp": event["timestamp"],
                    "goal": event["payload"].get("goal"),
                    "selection": event["payload"].get("selection"),
                    "confidence": event["payload"].get("confidence"),
                    "rationale": event["payload"].get("rationale"),
                }
                for event in decisions
            ],
        }
    
    def low_confidence_decisions(
        self,
        time_range: TimeRange,
        threshold: float = 0.5,
    ) -> dict[str, Any]:
        """
        Report on low-confidence decisions for review.
        
        This helps identify decisions that may need human review
        or indicate model issues.
        """
        query = (
            AuditQuery()
            .time_range(time_range)
            .where("event_type", QueryOperator.EQUALS, "decision")
            .where("payload.confidence", QueryOperator.LESS_THAN, threshold)
            .order_by("payload.confidence")
        )
        
        results = self._engine.execute(query)
        
        return {
            "report_type": "low_confidence_decisions",
            "threshold": threshold,
            "time_range": {
                "start": time_range.start.isoformat(),
                "end": time_range.end.isoformat(),
            },
            "count": len(results),
            "decisions": [
                {
                    "timestamp": event["timestamp"],
                    "session_id": event["context"].get("session_id"),
                    "agent_id": event["context"].get("agent_id"),
                    "goal": event["payload"].get("goal"),
                    "confidence": event["payload"].get("confidence"),
                }
                for event in results
            ],
        }

# ============================================================================
# Block 9, 10, 11 (chapter listings, illustrative usage)
# ============================================================================
#
# The three usage examples below appear in the chapter to show how an
# AuditQuery API might be invoked. They reference a hypothetical richer
# surface (.add_condition / .set_time_range with an external `storage`
# binding) than the runnable AuditQuery class above (which exposes .where).
# They are preserved here as a module-level docstring so this file stays
# importable; readers should treat them as pseudocode and adapt them to
# the actual AuditQuery surface in their own integration.

_ILLUSTRATIVE_AUDITQUERY_USAGE = r"""
# Block 9, find all audit events involving a specific customer
query = AuditQuery()
query.add_condition(QueryCondition(
    field="actor.id",
    operator=QueryOperator.EQUALS,
    value="customer_12345"
))
query.set_time_range(
    start=datetime(2024, 1, 1, tzinfo=timezone.utc),
    end=datetime.now(timezone.utc),
)
customer_events = list(query.execute(storage))

# Block 10, find all access events to PII-tagged resources in Q1
query = AuditQuery()
query.add_condition(QueryCondition(
    field="event_type",
    operator=QueryOperator.EQUALS,
    value="data_access"
))
query.add_condition(QueryCondition(
    field="payload.data_classification",
    operator=QueryOperator.EQUALS,
    value="PII"
))
query.set_time_range(
    start=datetime(2024, 1, 1),
    end=datetime(2024, 3, 31)
)
pii_access_events = list(query.execute(storage))

# Block 11, verify deletion was logged for compliance evidence
query = AuditQuery()
query.add_condition(QueryCondition(
    field="event_type",
    operator=QueryOperator.EQUALS,
    value="data_deletion"
))
query.add_condition(QueryCondition(
    field="payload.data_subject_id",
    operator=QueryOperator.EQUALS,
    value="customer_12345"
))
deletion_proof = list(query.execute(storage))
# This provides auditable evidence that erasure was performed
"""
