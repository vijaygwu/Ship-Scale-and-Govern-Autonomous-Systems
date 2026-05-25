"""
Monitoring and Observability

Code listings from Chapter 06, Book 2:
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

import logging
import json
from datetime import datetime, timezone
from typing import Any
from dataclasses import dataclass, asdict


REDACTED = "[REDACTED]"
MAX_LOG_VALUE_CHARS = 200
MAX_LOG_KEYS = 20
SENSITIVE_FIELD_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "ssn",
    "prompt",
    "completion",
    "raw",
    "content",
    "document",
    "retrieved",
)

@dataclass
class AgentLogEntry:
    """Structured log entry for agent operations."""
    timestamp: str
    agent_id: str
    task_id: str
    event_type: str
    step_index: int
    reasoning_summary: str
    context: dict[str, Any]
    token_count: int | None = None
    tool_name: str | None = None
    model_name: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


class AgentLogger:
    """Structured logging for agent systems with correlation support."""

    def __init__(self, agent_id: str, service_name: str = "agent-service"):
        self.agent_id = agent_id
        self.service_name = service_name
        self.logger = logging.getLogger(f"agent.{agent_id}")
        self._configure_handler()

    def _configure_handler(self) -> None:
        # logging.getLogger(name) returns the same logger instance across
        # calls. Without this guard, constructing N AgentLogger instances
        # with the same agent_id attaches N handlers and emits each line
        # N times.
        if self.logger.handlers:
            return
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        # Avoid double-emission through the root logger.
        self.logger.propagate = False

    def log_decision_rationale(
        self,
        task_id: str,
        step: int,
        reasoning_summary: str,
        action: str | None = None,
        decision_rationale: str | None = None,
        observation_summary: str | None = None,
        token_count: int | None = None
    ) -> None:
        """Log a safe operational summary, not hidden chain-of-thought.

        Store concise decision summaries and tool choices. Do not pass raw
        hidden chain-of-thought, full prompts, retrieved documents, secrets,
        or private user data to this logger.
        """
        context = self._allowlisted_context(
            {
                "action": action,
                "decision_rationale": decision_rationale,
                "observation_summary": observation_summary,
            },
            allowed_keys={
                "action",
                "decision_rationale",
                "observation_summary",
            }
        )
        entry = AgentLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            task_id=task_id,
            event_type="decision_rationale",
            step_index=step,
            reasoning_summary=self._safe_value(
                "reasoning_summary",
                reasoning_summary
            ),
            context=context,
            token_count=token_count
        )
        self.logger.info(entry.to_json())

    def log_tool_invocation(
        self,
        task_id: str,
        step: int,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
        duration_ms: float,
        allowed_argument_keys: set[str] | None = None
    ) -> None:
        """Log tool usage without raw arguments or result payloads."""
        entry = AgentLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.agent_id,
            task_id=task_id,
            event_type="tool_invocation",
            step_index=step,
            reasoning_summary="Invoked tool with redacted inputs and summarized output",
            tool_name=tool_name,
            context={
                "arguments": self._safe_arguments(
                    arguments,
                    allowed_argument_keys or set()
                ),
                "result": self._result_summary(result),
                "duration_ms": duration_ms
            }
        )
        self.logger.info(entry.to_json())

    def _allowlisted_context(
        self,
        context: dict[str, Any],
        allowed_keys: set[str]
    ) -> dict[str, Any]:
        """Keep only explicitly approved context fields."""
        safe_context: dict[str, Any] = {}
        for key in allowed_keys:
            value = context.get(key)
            if value is not None:
                safe_context[key] = self._safe_value(key, value)
        return safe_context

    def _safe_arguments(
        self,
        arguments: dict[str, Any],
        allowed_keys: set[str]
    ) -> dict[str, Any]:
        """Summarize all argument keys and include only allow-listed values."""
        safe_values = {
            key: self._safe_value(key, arguments[key])
            for key in sorted(allowed_keys)
            if key in arguments
        }
        omitted_keys = [
            str(key) for key in arguments
            if key not in allowed_keys
        ][:MAX_LOG_KEYS]
        return {
            "allowed_values": safe_values,
            "omitted_keys": omitted_keys,
            "omitted_count": max(0, len(arguments) - len(safe_values))
        }

    def _safe_value(self, key: str, value: Any) -> Any:
        """Redact sensitive fields and summarize complex values."""
        if self._is_sensitive_key(key):
            return REDACTED
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            if len(value) > MAX_LOG_VALUE_CHARS:
                return value[:MAX_LOG_VALUE_CHARS] + "...[truncated]"
            return value
        if isinstance(value, dict):
            return {
                "type": "dict",
                "keys": [str(k) for k in list(value.keys())[:MAX_LOG_KEYS]],
                "item_count": len(value)
            }
        if isinstance(value, (list, tuple, set)):
            return {
                "type": type(value).__name__,
                "item_count": len(value)
            }
        return {"type": type(value).__name__}

    def _result_summary(self, result: Any) -> dict[str, Any]:
        """Describe a tool result without copying payload content."""
        if isinstance(result, dict):
            return {
                "type": "dict",
                "keys": [str(k) for k in list(result.keys())[:MAX_LOG_KEYS]],
                "item_count": len(result)
            }
        if isinstance(result, (list, tuple, set)):
            return {
                "type": type(result).__name__,
                "item_count": len(result)
            }
        if isinstance(result, str):
            return {"type": "str", "char_count": len(result)}
        if isinstance(result, bytes):
            return {"type": "bytes", "byte_count": len(result)}
        return {"type": type(result).__name__}

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = key.lower().replace("-", "_")
        return any(marker in normalized for marker in SENSITIVE_FIELD_MARKERS)

# ============================================================================
# Block 2 (chapter listing #2)
# ============================================================================

from enum import Enum
from dataclasses import dataclass, field
from typing import Callable
from collections import defaultdict, deque
import time


class TaskOutcome(Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SAFETY_ABORT = "safety_abort"
    USER_ABORT = "user_abort"


@dataclass
class TaskResult:
    task_id: str
    outcome: TaskOutcome
    duration_seconds: float
    reasoning_steps: int
    total_tokens: int
    tools_used: list[str]
    error_message: str | None = None
    user_feedback_score: float | None = None


class TaskSuccessMetrics:
    """Track and analyze task success rates with multiple dimensions."""

    _DEFAULT_TASK_TYPE = "default"
    _OTHER_TASK_TYPE = "other"
    _MAX_TRACKED_TASK_TYPES = 128

    def __init__(self):
        # Bounded ring buffer keeps recent results for analysis without
        # growing without bound in a long-running monitoring service. For
        # full retention, stream results to an external metrics backend
        # (Prometheus, CloudWatch) and keep only aggregate counters here.
        self._results: deque[TaskResult] = deque(maxlen=10_000)
        self._outcome_counts: dict[TaskOutcome, int] = defaultdict(int)
        self._outcome_by_task_type: dict[str, dict[TaskOutcome, int]] = {}

    def _normalise_task_type(self, task_type: str) -> str:
        """Bound caller-provided task labels to a fixed number of buckets."""
        task_type = task_type or self._DEFAULT_TASK_TYPE
        if task_type in self._outcome_by_task_type:
            return task_type

        custom_type_limit = self._MAX_TRACKED_TASK_TYPES - 1
        if len(self._outcome_by_task_type) < custom_type_limit:
            return task_type
        return self._OTHER_TASK_TYPE

    def record_result(self, result: TaskResult, task_type: str = "default") -> None:
        """Record a task result for metric calculation."""
        self._results.append(result)
        self._outcome_counts[result.outcome] += 1
        task_type = self._normalise_task_type(task_type)
        type_counts = self._outcome_by_task_type.setdefault(
            task_type,
            defaultdict(int),
        )
        type_counts[result.outcome] += 1

    def success_rate(self, include_partial: bool = True) -> float:
        """Calculate overall success rate.

        Args:
            include_partial: Whether to count partial successes as successes.

        Returns:
            Success rate as a decimal between 0 and 1.
        """
        if not self._results:
            return 0.0

        success_outcomes = {TaskOutcome.SUCCESS}
        if include_partial:
            success_outcomes.add(TaskOutcome.PARTIAL_SUCCESS)

        successes = sum(
            1 for r in self._results if r.outcome in success_outcomes
        )
        return successes / len(self._results)

    def success_rate_by_type(self, task_type: str) -> float:
        """Calculate success rate for a specific task type."""
        task_type = self._normalise_task_type(task_type)
        type_counts = self._outcome_by_task_type.get(task_type, {})
        if not type_counts:
            return 0.0

        total = sum(type_counts.values())
        successes = type_counts.get(TaskOutcome.SUCCESS, 0)
        successes += type_counts.get(TaskOutcome.PARTIAL_SUCCESS, 0)
        return successes / total

    def mean_time_to_completion(self, successful_only: bool = True) -> float:
        """Calculate average task completion time in seconds."""
        results = self._results
        if successful_only:
            results = [
                r for r in results
                if r.outcome in {TaskOutcome.SUCCESS, TaskOutcome.PARTIAL_SUCCESS}
            ]

        if not results:
            return 0.0

        return sum(r.duration_seconds for r in results) / len(results)

    def percentile_duration(self, percentile: int = 95) -> float:
        """Calculate the Nth percentile task duration.

        Uses linear interpolation between adjacent ranks, equivalent to
        NumPy's percentile(method='linear') and Excel's PERCENTILE.INC.
        """
        if not self._results:
            return 0.0

        durations = sorted(r.duration_seconds for r in self._results)
        n = len(durations)
        rank = (percentile / 100) * (n - 1)
        lower_idx = int(rank)
        upper_idx = min(lower_idx + 1, n - 1)
        weight = rank - lower_idx
        return durations[lower_idx] * (1 - weight) + durations[upper_idx] * weight

# ============================================================================
# Block 3 (chapter listing #3)
# ============================================================================

from dataclasses import dataclass
from typing import Any, Optional
import time
from contextlib import contextmanager


@dataclass
class LatencyBreakdown:
    """Detailed breakdown of agent operation latency."""
    total_ms: float
    model_inference_ms: float
    tool_execution_ms: float
    context_retrieval_ms: float
    response_generation_ms: float
    network_overhead_ms: float

    @property
    def model_percentage(self) -> float:
        return (self.model_inference_ms / self.total_ms) * 100 if self.total_ms > 0 else 0

    @property
    def tool_percentage(self) -> float:
        return (self.tool_execution_ms / self.total_ms) * 100 if self.total_ms > 0 else 0

    def bottleneck(self) -> str:
        """Identify the primary latency contributor."""
        components = {
            "model_inference": self.model_inference_ms,
            "tool_execution": self.tool_execution_ms,
            "context_retrieval": self.context_retrieval_ms,
            "response_generation": self.response_generation_ms,
            "network_overhead": self.network_overhead_ms
        }
        return max(components, key=components.get)


class LatencyTracker:
    """Track latency across different operation phases."""

    def __init__(self):
        self._phase_times: dict[str, float] = {}
        self._phase_starts: dict[str, float] = {}
        self._total_start: Optional[float] = None

    def start_operation(self) -> None:
        """Mark the start of the overall operation."""
        self._total_start = time.perf_counter()
        self._phase_times.clear()
        self._phase_starts.clear()

    @contextmanager
    def track_phase(self, phase_name: str):
        """Context manager to track a specific phase."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = (time.perf_counter() - start) * 1000
            self._phase_times[phase_name] = self._phase_times.get(phase_name, 0) + elapsed

    def get_breakdown(self) -> LatencyBreakdown:
        """Generate a latency breakdown report."""
        total = (time.perf_counter() - self._total_start) * 1000 if self._total_start else 0

        tracked_total = sum(self._phase_times.values())
        untracked = max(0, total - tracked_total)

        return LatencyBreakdown(
            total_ms=total,
            model_inference_ms=self._phase_times.get("model_inference", 0),
            tool_execution_ms=self._phase_times.get("tool_execution", 0),
            context_retrieval_ms=self._phase_times.get("context_retrieval", 0),
            response_generation_ms=self._phase_times.get("response_generation", 0),
            network_overhead_ms=untracked
        )

# ============================================================================
# Block 4 (chapter listing #4)
# ============================================================================

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import threading


@dataclass
class TokenUsage:
    """Token usage for a single operation."""
    prompt_tokens: int
    completion_tokens: int
    cached_tokens: int = 0
    reasoning_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def billable_tokens(self) -> int:
        """Tokens that count toward billing (excludes cached)."""
        return self.prompt_tokens - self.cached_tokens + self.completion_tokens

    def cost_estimate(
        self,
        input_price_per_million: float,
        output_price_per_million: float,
        cached_price_per_million: float
    ) -> float:
        """Estimate cost in USD from explicitly supplied per-million-token rates."""
        billable_input = self.prompt_tokens - self.cached_tokens
        return (
            (billable_input / 1_000_000) * input_price_per_million +
            (self.cached_tokens / 1_000_000) * cached_price_per_million +
            (self.completion_tokens / 1_000_000) * output_price_per_million
        )


@dataclass
class TokenBudget:
    """Token budget management for cost control."""
    daily_limit: int
    hourly_limit: int
    per_task_limit: int

    _daily_used: int = field(default=0, repr=False)
    _hourly_used: int = field(default=0, repr=False)
    # Track full (date, hour) and full date tuples so that the reset
    # logic does not collide across months/days. A bare day-of-month
    # would equal itself one month later and skip the reset entirely.
    _last_reset_hour: tuple = field(default=(), repr=False)
    _last_reset_day: object = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def check_and_consume(self, tokens: int) -> bool:
        """Check if tokens can be consumed and consume them if so.

        Returns:
            True if tokens were consumed, False if budget exceeded.
        """
        with self._lock:
            self._reset_if_needed()

            if tokens > self.per_task_limit:
                return False
            if self._daily_used + tokens > self.daily_limit:
                return False
            if self._hourly_used + tokens > self.hourly_limit:
                return False

            self._daily_used += tokens
            self._hourly_used += tokens
            return True

    def _reset_if_needed(self) -> None:
        """Reset counters if time period has passed."""
        now = datetime.now(timezone.utc)

        # Compare full dates and (date, hour) tuples so that a missed
        # day or hour never aliases to the same scalar value.
        current_day = now.date()
        if current_day != self._last_reset_day:
            self._daily_used = 0
            self._last_reset_day = current_day

        current_hour_key = (current_day, now.hour)
        if current_hour_key != self._last_reset_hour:
            self._hourly_used = 0
            self._last_reset_hour = current_hour_key

    @property
    def remaining_daily(self) -> int:
        with self._lock:
            self._reset_if_needed()
            return max(0, self.daily_limit - self._daily_used)

    @property
    def remaining_hourly(self) -> int:
        with self._lock:
            self._reset_if_needed()
            return max(0, self.hourly_limit - self._hourly_used)

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Any
from contextvars import ContextVar
from collections import OrderedDict
import threading
import uuid
import time


@dataclass
class SpanContext:
    """Trace context that propagates across agent boundaries."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: dict[str, str] = field(default_factory=dict)

    def child_context(self) -> "SpanContext":
        """Create a child span context."""
        return SpanContext(
            trace_id=self.trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=self.span_id,
            baggage=self.baggage.copy()
        )

    def to_headers(self) -> dict[str, str]:
        """Convert to HTTP headers for propagation."""
        headers = {
            "X-Trace-ID": self.trace_id,
            "X-Span-ID": self.span_id,
        }
        if self.parent_span_id:
            headers["X-Parent-Span-ID"] = self.parent_span_id

        # W3C Trace Context format for interoperability
        headers["traceparent"] = f"00-{self.trace_id}-{self.span_id}-01"

        return headers

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> Optional["SpanContext"]:
        """Extract context from HTTP headers."""
        # Try W3C format first
        traceparent = headers.get("traceparent")
        if traceparent:
            parts = traceparent.split("-")
            if len(parts) >= 3:
                return cls(
                    trace_id=parts[1],
                    span_id=uuid.uuid4().hex[:16],
                    parent_span_id=parts[2]
                )

        # Fall back to custom headers
        trace_id = headers.get("X-Trace-ID")
        if trace_id:
            return cls(
                trace_id=trace_id,
                span_id=uuid.uuid4().hex[:16],
                parent_span_id=headers.get("X-Span-ID")
            )

        return None

    @classmethod
    def new_trace(cls) -> "SpanContext":
        """Create a new root trace context."""
        return cls(
            trace_id=uuid.uuid4().hex,
            span_id=uuid.uuid4().hex[:16]
        )


_current_span: ContextVar[Optional[SpanContext]] = ContextVar(
    'current_span', default=None
)


MAX_SPAN_EVENTS = 1_000


@dataclass
class Span:
    """A single span in a distributed trace."""
    name: str
    context: SpanContext
    start_time: float
    end_time: Optional[float] = None
    status: str = "OK"
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set_attribute(self, key: str, value: Any) -> None:
        """Add an attribute to the span."""
        with self._lock:
            self.attributes[key] = value

    def add_event(self, name: str, attributes: Optional[dict] = None) -> None:
        """Add a timestamped event to the span."""
        event = {
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {}
        }
        with self._lock:
            self.events.append(event)
            overflow = len(self.events) - MAX_SPAN_EVENTS
            if overflow > 0:
                del self.events[:overflow]

    def set_error(self, error: Exception) -> None:
        """Mark the span as errored."""
        with self._lock:
            self.status = "ERROR"
        self.set_attribute("error.type", type(error).__name__)
        self.set_attribute("error.message", str(error))

    def end(self) -> None:
        """End the span."""
        with self._lock:
            self.end_time = time.time()

    @property
    def duration_ms(self) -> float:
        with self._lock:
            end_time = self.end_time
            start_time = self.start_time
        if end_time is None:
            return (time.time() - start_time) * 1000
        return (end_time - start_time) * 1000

# ============================================================================
# Block 6 (chapter listing #6)
# ============================================================================

from typing import Callable, TypeVar, ParamSpec
from functools import wraps
import asyncio


P = ParamSpec('P')
R = TypeVar('R')


class AgentTracer:
    """Tracer implementation for multi-agent systems."""

    def __init__(
        self,
        service_name: str,
        exporter: Optional[Callable[[Span], None]] = None,
        config: Optional[dict[str, Any]] = None,
    ):
        self.service_name = service_name
        self.exporter = exporter or self._default_exporter
        # Bound active spans to prevent orphaned spans from growing forever
        # if callers forget to close them.
        config = config or {}
        self._max_active_spans: int = config.get("max_active_spans", 10_000)
        self._active_spans: "OrderedDict[str, Span]" = OrderedDict()
        self._lock = threading.RLock()

    def _default_exporter(self, span: Span) -> None:
        """Default exporter that prints spans (replace with real exporter)."""
        print(f"SPAN: {span.name} duration={span.duration_ms:.2f}ms status={span.status}")

    def start_span(
        self,
        name: str,
        parent: Optional[SpanContext] = None,
        attributes: Optional[dict[str, Any]] = None
    ) -> Span:
        """Start a new span."""
        if parent is None:
            parent = _current_span.get()

        if parent:
            context = parent.child_context()
        else:
            context = SpanContext.new_trace()

        span = Span(
            name=name,
            context=context,
            start_time=time.time(),
            attributes=attributes or {}
        )
        span.set_attribute("service.name", self.service_name)

        # Simple LRU-style eviction: drop the oldest active span when the
        # bound is reached. Protects long-running tracers from unbounded
        # growth if callers forget to end_span.
        with self._lock:
            if len(self._active_spans) >= self._max_active_spans:
                self._active_spans.popitem(last=False)
            self._active_spans[context.span_id] = span
        _current_span.set(context)

        return span

    def end_span(self, span: Span) -> None:
        """End a span and export it."""
        span.end()

        with self._lock:
            self._active_spans.pop(span.context.span_id, None)

            # Restore parent context
            if span.context.parent_span_id:
                parent_span = self._active_spans.get(span.context.parent_span_id)
                if parent_span:
                    _current_span.set(parent_span.context)
                else:
                    _current_span.set(None)
            else:
                _current_span.set(None)

        try:
            self.exporter(span)
        except Exception as exc:  # noqa: BLE001 -- exporter isolation
            logging.getLogger(__name__).warning(
                "Span exporter failed for %s: %s",
                span.name,
                exc,
                exc_info=True,
            )

    def trace(
        self,
        name: Optional[str] = None,
        attributes: Optional[dict[str, Any]] = None
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorator to trace a function."""
        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            span_name = name or func.__name__

            @wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                span = self.start_span(span_name, attributes=attributes)
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.set_error(e)
                    raise
                finally:
                    self.end_span(span)

            @wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                span = self.start_span(span_name, attributes=attributes)
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception as e:
                    span.set_error(e)
                    raise
                finally:
                    self.end_span(span)

            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            return sync_wrapper

        return decorator

    def inject_context(self, headers: dict[str, str]) -> dict[str, str]:
        """Inject current trace context into headers for outbound calls."""
        context = _current_span.get()
        if context:
            headers.update(context.to_headers())
        return headers

    def extract_context(self, headers: dict[str, str]) -> Optional[SpanContext]:
        """Extract trace context from incoming request headers."""
        return SpanContext.from_headers(headers)

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

# OpenTelemetry is an optional observability backend; guard the imports
# so the rest of this chapter module remains importable in a vanilla
# environment. Real deployments install opentelemetry-api / -sdk /
# -exporter-otlp from requirements.txt and the real names take over.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _optional import _RequiredDependency  # noqa: E402

try:
    from opentelemetry import trace, metrics  # type: ignore[import-not-found]
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-not-found]
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore[import-not-found]
    from opentelemetry.sdk.metrics import MeterProvider  # type: ignore[import-not-found]
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader  # type: ignore[import-not-found]
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore[import-not-found]
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter  # type: ignore[import-not-found]
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME  # type: ignore[import-not-found]
    from opentelemetry.trace import Status, StatusCode  # type: ignore[import-not-found]
    from opentelemetry.metrics import Counter, Histogram, UpDownCounter  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - dependency not required for examples
    _otel_hint = "Install opentelemetry-api, -sdk, and -exporter-otlp to enable tracing."
    trace = _RequiredDependency("opentelemetry.trace", _otel_hint)
    metrics = _RequiredDependency("opentelemetry.metrics", _otel_hint)
    TracerProvider = _RequiredDependency("TracerProvider", _otel_hint)
    BatchSpanProcessor = _RequiredDependency("BatchSpanProcessor", _otel_hint)
    MeterProvider = _RequiredDependency("MeterProvider", _otel_hint)
    PeriodicExportingMetricReader = _RequiredDependency(
        "PeriodicExportingMetricReader", _otel_hint
    )
    OTLPSpanExporter = _RequiredDependency("OTLPSpanExporter", _otel_hint)
    OTLPMetricExporter = _RequiredDependency("OTLPMetricExporter", _otel_hint)
    Resource = _RequiredDependency("Resource", _otel_hint)
    SERVICE_NAME = "service.name"  # OTel semantic-convention constant
    Status = _RequiredDependency("Status", _otel_hint)
    StatusCode = _RequiredDependency("StatusCode", _otel_hint)
    Counter = _RequiredDependency("Counter", _otel_hint)
    Histogram = _RequiredDependency("Histogram", _otel_hint)
    UpDownCounter = _RequiredDependency("UpDownCounter", _otel_hint)
from typing import Any, Callable, Optional
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
import atexit
import threading
import time


# Shared, bounded executor for timeout-guarded collaborator calls.
# Allocating a fresh ThreadPoolExecutor per call leaked worker threads when
# a wedged call survived shutdown(wait=False); a small shared pool caps the
# blast radius and is cleaned up at interpreter exit.
_EXTERNAL_CALL_MAX_WORKERS = 4
_EXTERNAL_CALL_MAX_PENDING = 8
_EXTERNAL_CALL_EXECUTOR = ThreadPoolExecutor(
    max_workers=_EXTERNAL_CALL_MAX_WORKERS,
    thread_name_prefix="agent-external-call",
)
_EXTERNAL_CALL_SLOTS = threading.BoundedSemaphore(
    _EXTERNAL_CALL_MAX_WORKERS + _EXTERNAL_CALL_MAX_PENDING
)
atexit.register(_EXTERNAL_CALL_EXECUTOR.shutdown, wait=False, cancel_futures=True)


def get_timeout_executor() -> ThreadPoolExecutor:
    """Return the module-level executor used for timeout-guarded calls."""
    return _EXTERNAL_CALL_EXECUTOR


def set_timeout_executor(executor: ThreadPoolExecutor) -> None:
    """Replace the module-level executor (intended for tests)."""
    global _EXTERNAL_CALL_EXECUTOR
    _EXTERNAL_CALL_EXECUTOR = executor


def get_external_call_executor() -> ThreadPoolExecutor:
    """Return the shared executor for external (collaborator) calls.

    This is the same underlying pool as ``get_timeout_executor``; the
    two names exist because callers reason about the pool at different
    levels (timeout-guarded vs. external-call quota).
    """
    return _EXTERNAL_CALL_EXECUTOR


def set_external_call_executor(executor: ThreadPoolExecutor) -> None:
    """Replace the shared external-call executor (intended for tests)."""
    global _EXTERNAL_CALL_EXECUTOR
    _EXTERNAL_CALL_EXECUTOR = executor


class ExternalCallSaturationError(TimeoutError):
    """Raised when the shared sync-call executor cannot accept more work."""


def _remaining_seconds(deadline: float) -> float:
    """Return remaining deadline budget or raise when it has expired."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("agent request deadline exceeded")
    return remaining


def _call_with_timeout(
    operation_name: str,
    call: Callable[..., Any],
    *args: Any,
    timeout_seconds: float,
    deadline: float,
    span: Any | None = None,
    orphan_counter: Any | None = None,
    saturation_counter: Any | None = None,
    metric_attributes: dict[str, Any] | None = None,
) -> Any:
    """Run one synchronous collaborator call with bounded wait and capacity."""
    attributes = metric_attributes or {"operation": operation_name}
    slot_timeout = min(timeout_seconds, _remaining_seconds(deadline))
    slot_limiter = _EXTERNAL_CALL_SLOTS
    acquired = slot_limiter.acquire(timeout=slot_timeout)
    if not acquired:
        if span is not None:
            span.set_attribute(f"{operation_name}.saturated", True)
        _record_counter(
            saturation_counter,
            {**attributes, "error.type": "ExternalCallSaturationError"},
        )
        raise ExternalCallSaturationError(
            f"{operation_name} shared executor saturated after "
            f"{slot_timeout:.2f}s"
        )

    try:
        result_timeout = min(timeout_seconds, _remaining_seconds(deadline))
        future = get_timeout_executor().submit(
            call,
            *args,
            timeout=result_timeout,
            deadline=deadline,
        )
    except Exception:
        slot_limiter.release()
        raise

    future.add_done_callback(lambda _future: slot_limiter.release())

    try:
        return future.result(timeout=result_timeout)
    except FutureTimeoutError as exc:
        cancelled = future.cancel()
        if span is not None:
            span.set_attribute(
                f"{operation_name}.cancelled_after_timeout",
                cancelled,
            )
        if not cancelled:
            if span is not None:
                span.set_attribute(
                    f"{operation_name}.orphaned_after_timeout",
                    True,
                )
            _record_counter(
                orphan_counter,
                {**attributes, "error.type": "TimeoutError"},
            )
        raise TimeoutError(
            f"{operation_name} timed out after {timeout_seconds:.2f}s"
        ) from exc


def _record_counter(counter: Any, attributes: dict[str, Any]) -> None:
    """Best-effort metrics recording should not mask the request result."""
    if counter is None:
        return
    try:
        counter.add(1, attributes)
    except Exception:
        pass


def _mark_span_error(span: Any, exc: BaseException) -> None:
    span.set_status(Status(StatusCode.ERROR, str(exc)))
    span.record_exception(exc)
    span.set_attribute("error.type", type(exc).__name__)


def _call_with_retries(
    operation_name: str,
    call: Callable[..., Any],
    *args: Any,
    timeout_seconds: float,
    deadline: float,
    max_attempts: int,
    retry_backoff_seconds: float,
    span: Any,
    retry_counter: Any,
    timeout_counter: Any,
    orphan_counter: Any,
    saturation_counter: Any,
) -> Any:
    """Call a model or tool with deadline-aware transient retries."""
    for attempt in range(1, max_attempts + 1):
        attributes = {
            "operation": operation_name,
            "attempt": attempt,
        }
        try:
            attempt_timeout = min(timeout_seconds, _remaining_seconds(deadline))
        except TimeoutError as exc:
            _record_counter(
                timeout_counter,
                {**attributes, "error.type": type(exc).__name__},
            )
            raise

        span.set_attribute(f"{operation_name}.timeout_seconds", attempt_timeout)
        span.set_attribute(f"{operation_name}.attempt", attempt)

        try:
            return _call_with_timeout(
                operation_name,
                call,
                *args,
                timeout_seconds=attempt_timeout,
                deadline=deadline,
                span=span,
                orphan_counter=orphan_counter,
                saturation_counter=saturation_counter,
                metric_attributes=attributes,
            )
        except TimeoutError as exc:
            _record_counter(
                timeout_counter,
                {**attributes, "error.type": type(exc).__name__},
            )
            raise
        except ConnectionError as exc:
            retry_attributes = {**attributes, "error.type": type(exc).__name__}
            if attempt >= max_attempts:
                raise

            _record_counter(retry_counter, retry_attributes)
            try:
                remaining = _remaining_seconds(deadline)
            except TimeoutError as timeout_exc:
                _record_counter(
                    timeout_counter,
                    {**attributes, "error.type": type(timeout_exc).__name__},
                )
                raise timeout_exc from exc
            backoff = min(
                retry_backoff_seconds * (2 ** (attempt - 1)),
                remaining,
            )
            if backoff > 0:
                time.sleep(backoff)

    raise TimeoutError(f"{operation_name} exhausted retry attempts")


def trace_agent_request_example(
    request_id: str,
    prompt: str,
    model_client: Any,
    tool_registry: Any,
    request_timeout_seconds: float = 30.0,
    model_timeout_seconds: float = 10.0,
    tool_timeout_seconds: float = 5.0,
    max_attempts: int = 2,
    retry_backoff_seconds: float = 0.25,
) -> str:
    """Minimal end-to-end trace: request -> model call -> tool call.

    The model client and tool registry are expected to honor ``timeout``
    and ``deadline`` keyword arguments so cancellation propagates past the
    example wrapper.
    """
    if request_timeout_seconds <= 0:
        raise ValueError("request_timeout_seconds must be positive")
    if model_timeout_seconds <= 0:
        raise ValueError("model_timeout_seconds must be positive")
    if tool_timeout_seconds <= 0:
        raise ValueError("tool_timeout_seconds must be positive")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    if retry_backoff_seconds < 0:
        raise ValueError("retry_backoff_seconds must be non-negative")

    tracer = trace.get_tracer(__name__)
    meter = metrics.get_meter(__name__)
    request_counter = meter.create_counter(
        "agent.request.outcomes",
        description="Agent request outcomes",
        unit="1",
    )
    retry_counter = meter.create_counter(
        "agent.external_call.retries",
        description="Transient model/tool retries",
        unit="1",
    )
    timeout_counter = meter.create_counter(
        "agent.external_call.timeouts",
        description="Model/tool timeouts",
        unit="1",
    )
    orphan_counter = meter.create_counter(
        "agent.external_call.orphaned",
        description="Timed-out sync calls that could not be cancelled",
        unit="1",
    )
    saturation_counter = meter.create_counter(
        "agent.external_call.saturation",
        description="Sync calls rejected by shared executor backpressure",
        unit="1",
    )
    deadline = time.monotonic() + request_timeout_seconds

    with tracer.start_as_current_span(
        "agent.request",
        attributes={
            "request.id": request_id,
            "agent.task_type": "question_answering",
            "agent.deadline_unix_ns": time.time_ns()
            + int(request_timeout_seconds * 1_000_000_000),
        },
    ) as request_span:
        try:
            with tracer.start_as_current_span(
                "model.call",
                attributes={
                    "model.name": "frontier-model",
                    "model.operation": "chat_completion",
                    "llm.prompt_chars": len(prompt),
                },
            ) as model_span:
                try:
                    model_response = _call_with_retries(
                        "model.call",
                        model_client.complete,
                        prompt,
                        timeout_seconds=model_timeout_seconds,
                        deadline=deadline,
                        max_attempts=max_attempts,
                        retry_backoff_seconds=retry_backoff_seconds,
                        span=model_span,
                        retry_counter=retry_counter,
                        timeout_counter=timeout_counter,
                        orphan_counter=orphan_counter,
                        saturation_counter=saturation_counter,
                    )
                    prompt_tokens = model_response.get("prompt_tokens", 0)
                    completion_tokens = model_response.get("completion_tokens", 0)
                    model_span.set_attribute("llm.prompt_tokens", prompt_tokens)
                    model_span.set_attribute(
                        "llm.completion_tokens",
                        completion_tokens,
                    )
                    model_span.set_status(Status(StatusCode.OK))
                except Exception as exc:
                    _mark_span_error(model_span, exc)
                    raise

            tool_name = model_response.get("tool_name", "search")
            tool_args = model_response.get("tool_args", {"query": prompt})
            with tracer.start_as_current_span(
                "tool.call",
                attributes={
                    "tool.name": tool_name,
                    "tool.argument_count": len(tool_args),
                },
            ) as tool_span:
                try:
                    tool_result = _call_with_retries(
                        "tool.call",
                        tool_registry.invoke,
                        tool_name,
                        tool_args,
                        timeout_seconds=tool_timeout_seconds,
                        deadline=deadline,
                        max_attempts=max_attempts,
                        retry_backoff_seconds=retry_backoff_seconds,
                        span=tool_span,
                        retry_counter=retry_counter,
                        timeout_counter=timeout_counter,
                        orphan_counter=orphan_counter,
                        saturation_counter=saturation_counter,
                    )
                    tool_span.set_attribute(
                        "tool.result_type",
                        type(tool_result).__name__,
                    )
                    tool_span.set_status(Status(StatusCode.OK))
                except Exception as exc:
                    _mark_span_error(tool_span, exc)
                    raise

            request_span.set_attribute("agent.response.kind", "tool_augmented")
            request_span.set_status(Status(StatusCode.OK))
            _record_counter(
                request_counter,
                {"status": "success", "request.kind": "tool_augmented"},
            )
            return str(tool_result)
        except Exception as exc:
            request_span.set_attribute("agent.response.kind", "error")
            _mark_span_error(request_span, exc)
            _record_counter(
                request_counter,
                {"status": "error", "error.type": type(exc).__name__},
            )
            raise


class OpenTelemetryAgentInstrumentation:
    """Reference OpenTelemetry instrumentation pattern for agent systems."""

    def __init__(
        self,
        service_name: str,
        otlp_endpoint: str = "localhost:4317",
        environment: str = "production"
    ):
        self.service_name = service_name
        self.environment = environment

        # Create resource with service metadata
        resource = Resource.create({
            SERVICE_NAME: service_name,
            "deployment.environment": environment,
            "service.version": "1.0.0",
        })

        # Set up tracing
        trace_provider = TracerProvider(resource=resource)
        trace_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        trace_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
        trace.set_tracer_provider(trace_provider)
        self.tracer = trace.get_tracer(__name__)

        # Set up metrics
        metric_exporter = OTLPMetricExporter(endpoint=otlp_endpoint, insecure=True)
        metric_reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=60000
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        self.meter = metrics.get_meter(__name__)

        # Create agent-specific metrics
        self._setup_metrics()

    def _setup_metrics(self) -> None:
        """Initialize all agent metrics."""
        # Task metrics
        self.task_counter = self.meter.create_counter(
            "agent.tasks.total",
            description="Total number of tasks processed",
            unit="1"
        )

        self.task_duration = self.meter.create_histogram(
            "agent.task.duration",
            description="Task execution duration",
            unit="ms"
        )

        self.active_tasks = self.meter.create_up_down_counter(
            "agent.tasks.active",
            description="Number of currently active tasks",
            unit="1"
        )

        # Token metrics
        self.token_counter = self.meter.create_counter(
            "agent.tokens.total",
            description="Total tokens consumed",
            unit="1"
        )

        self.token_histogram = self.meter.create_histogram(
            "agent.tokens.per_task",
            description="Tokens consumed per task",
            unit="1"
        )

        # Tool metrics
        self.tool_invocations = self.meter.create_counter(
            "agent.tools.invocations",
            description="Tool invocation count",
            unit="1"
        )

        self.tool_duration = self.meter.create_histogram(
            "agent.tools.duration",
            description="Tool execution duration",
            unit="ms"
        )

        self.tool_errors = self.meter.create_counter(
            "agent.tools.errors",
            description="Tool execution errors",
            unit="1"
        )

        # Reasoning metrics
        self.reasoning_steps = self.meter.create_histogram(
            "agent.reasoning.steps",
            description="Number of reasoning steps per task",
            unit="1"
        )

        # Model metrics
        self.model_latency = self.meter.create_histogram(
            "agent.model.latency",
            description="Model inference latency",
            unit="ms"
        )

        self.model_errors = self.meter.create_counter(
            "agent.model.errors",
            description="Model call errors",
            unit="1"
        )

    @contextmanager
    def trace_task(
        self,
        task_id: str,
        task_type: str,
        attributes: Optional[dict[str, Any]] = None
    ):
        """Context manager to trace an entire task execution."""
        self.active_tasks.add(1, {"task.type": task_type})
        start_time = time.time()

        with self.tracer.start_as_current_span(
            "agent.task",
            attributes={
                "task.id": task_id,
                "task.type": task_type,
                **(attributes or {})
            }
        ) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
                self.task_counter.add(1, {"task.type": task_type, "status": "success"})
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                self.task_counter.add(1, {"task.type": task_type, "status": "error"})
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                self.task_duration.record(duration_ms, {"task.type": task_type})
                self.active_tasks.add(-1, {"task.type": task_type})

    @contextmanager
    def trace_tool(self, tool_name: str, arguments: dict[str, Any]):
        """Context manager to trace tool execution without raw arguments."""
        start_time = time.time()

        with self.tracer.start_as_current_span(
            f"tool.{tool_name}",
            attributes={
                "tool.name": tool_name,
                **self._safe_tool_argument_attributes(arguments)
            }
        ) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
                self.tool_invocations.add(1, {"tool.name": tool_name, "status": "success"})
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                self.tool_invocations.add(1, {"tool.name": tool_name, "status": "error"})
                self.tool_errors.add(1, {"tool.name": tool_name, "error.type": type(e).__name__})
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                self.tool_duration.record(duration_ms, {"tool.name": tool_name})

    def _safe_tool_argument_attributes(
        self,
        arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Summarize tool arguments for spans without copying values."""
        argument_keys = list(arguments)
        sampled_keys = argument_keys[:MAX_LOG_KEYS]
        sensitive_count = sum(
            1 for key in argument_keys
            if self._is_sensitive_key(str(key))
        )

        return {
            "tool.argument_count": len(arguments),
            "tool.argument_names": [
                REDACTED if self._is_sensitive_key(str(key)) else str(key)
                for key in sampled_keys
            ],
            "tool.argument_types": [
                type(arguments[key]).__name__
                for key in sampled_keys
            ],
            "tool.argument_names_truncated": len(argument_keys) > MAX_LOG_KEYS,
            "tool.sensitive_argument_count": sensitive_count,
        }

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        normalized = key.lower().replace("-", "_")
        return any(marker in normalized for marker in SENSITIVE_FIELD_MARKERS)

    @contextmanager
    def trace_model_call(
        self,
        model_name: str,
        operation: str = "inference"
    ):
        """Context manager to trace model API calls."""
        start_time = time.time()

        with self.tracer.start_as_current_span(
            f"model.{operation}",
            attributes={
                "model.name": model_name,
                "model.operation": operation
            }
        ) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                self.model_errors.add(1, {
                    "model.name": model_name,
                    "error.type": type(e).__name__
                })
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                self.model_latency.record(duration_ms, {"model.name": model_name})

    def record_tokens(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        model_name: str,
        task_type: str
    ) -> None:
        """Record token usage metrics."""
        total = prompt_tokens + completion_tokens

        self.token_counter.add(prompt_tokens, {
            "token.type": "prompt",
            "model.name": model_name,
            "task.type": task_type
        })
        self.token_counter.add(completion_tokens, {
            "token.type": "completion",
            "model.name": model_name,
            "task.type": task_type
        })
        self.token_histogram.record(total, {
            "model.name": model_name,
            "task.type": task_type
        })

    def record_reasoning_steps(self, steps: int, task_type: str) -> None:
        """Record the number of reasoning steps for a task."""
        self.reasoning_steps.record(steps, {"task.type": task_type})

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

from prometheus_client import (
    Counter, Histogram, Gauge, Info,
    CollectorRegistry, generate_latest,
    CONTENT_TYPE_LATEST
)
from typing import Any, Optional
from dataclasses import dataclass
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
import threading


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded metrics server with bounded backlog and socket timeouts."""
    daemon_threads = True
    request_queue_size = 32

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        connection_timeout: float = 5.0,
        request_queue_size: int = 32,
    ):
        self.connection_timeout = connection_timeout
        self.request_queue_size = request_queue_size
        super().__init__(server_address, RequestHandlerClass)

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(self.connection_timeout)
        return sock, addr


class PrometheusAgentMetrics:
    """Prometheus metrics exporter for agent systems.

    Prometheus labels are intentionally bounded. Raw agent IDs, exact
    tool names, and model version strings belong in structured logs,
    traces, or exemplars, not metric labels.
    """

    def __init__(
        self,
        namespace: str = "agent",
        registry: Optional[CollectorRegistry] = None
    ):
        self.registry = registry or CollectorRegistry()
        self.namespace = namespace

        # Task metrics. task_type is assumed to be a configured enum; agent_id
        # is collapsed to agent_pool so deployments do not create one series
        # per replica, tenant, or request-scoped agent.
        self.tasks_total = Counter(
            f"{namespace}_tasks_total",
            "Total number of tasks by outcome",
            ["task_type", "outcome", "agent_pool"],
            registry=self.registry
        )

        self.task_duration_seconds = Histogram(
            f"{namespace}_task_duration_seconds",
            "Task duration in seconds",
            ["task_type", "outcome"],
            buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
            registry=self.registry
        )

        self.tasks_by_pool_total = Counter(
            f"{namespace}_tasks_by_pool_total",
            "Tasks completed per bounded agent pool",
            ["agent_pool", "outcome"],
            registry=self.registry
        )

        self.tasks_in_progress = Gauge(
            f"{namespace}_tasks_in_progress",
            "Number of tasks currently in progress",
            ["task_type", "agent_pool"],
            registry=self.registry
        )

        # Token metrics
        self.tokens_total = Counter(
            f"{namespace}_tokens_total",
            "Total tokens consumed",
            ["token_type", "model_tier", "agent_pool"],
            registry=self.registry
        )

        self.tokens_per_task = Histogram(
            f"{namespace}_tokens_per_task",
            "Tokens consumed per task",
            ["task_type", "model_tier"],
            buckets=[100, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000],
            registry=self.registry
        )

        # Tool metrics
        self.tool_calls_total = Counter(
            f"{namespace}_tool_calls_total",
            "Total tool invocations",
            ["tool_category", "status", "agent_pool"],
            registry=self.registry
        )

        self.tool_duration_seconds = Histogram(
            f"{namespace}_tool_duration_seconds",
            "Tool execution duration in seconds",
            ["tool_category"],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=self.registry
        )

        # Model metrics
        self.model_calls_total = Counter(
            f"{namespace}_model_calls_total",
            "Total model API calls",
            ["model_tier", "status", "agent_pool"],
            registry=self.registry
        )

        self.model_latency_seconds = Histogram(
            f"{namespace}_model_latency_seconds",
            "Model inference latency in seconds",
            ["model_tier"],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
            registry=self.registry
        )

        # Reasoning metrics
        self.reasoning_steps_per_task = Histogram(
            f"{namespace}_reasoning_steps_per_task",
            "Number of reasoning steps per task",
            ["task_type", "agent_pool"],
            buckets=[1, 2, 3, 5, 7, 10, 15, 20, 30, 50],
            registry=self.registry
        )

        # Cost metrics
        self.estimated_cost_usd = Counter(
            f"{namespace}_estimated_cost_usd_total",
            "Estimated cost in USD",
            ["model_tier", "task_type"],
            registry=self.registry
        )

        # Health metrics
        self.agent_info = Info(
            f"{namespace}_agent",
            "Agent metadata",
            registry=self.registry
        )

        self.last_successful_task_timestamp = Gauge(
            f"{namespace}_last_successful_task_timestamp_seconds",
            "Unix timestamp of last successful task",
            ["agent_pool"],
            registry=self.registry
        )

        # Suppress repeated warnings about the same unrecognized agent_id.
        # A legacy ID shape would otherwise flood logs on every request.
        self._warned_agent_ids: set[str] = set()
        self._warned_agent_ids_max: int = 10000
        self._agent_pool_fallthrough_count: int = 0

    def record_task_start(self, task_type: str, agent_id: str) -> None:
        """Record that a task has started."""
        agent_pool = self._agent_pool(agent_id)
        self.tasks_in_progress.labels(
            task_type=task_type,
            agent_pool=agent_pool
        ).inc()

    def record_task_complete(
        self,
        task_type: str,
        agent_id: str,
        outcome: str,
        duration_seconds: float,
        tokens_used: int,
        model: str,
        reasoning_steps: int
    ) -> None:
        """Record task completion with all metrics."""
        agent_pool = self._agent_pool(agent_id)
        model_tier = self._model_tier(model)

        self.tasks_in_progress.labels(
            task_type=task_type,
            agent_pool=agent_pool
        ).dec()

        self.tasks_total.labels(
            task_type=task_type,
            outcome=outcome,
            agent_pool=agent_pool
        ).inc()

        self.task_duration_seconds.labels(
            task_type=task_type,
            outcome=outcome
        ).observe(duration_seconds)

        self.tasks_by_pool_total.labels(
            agent_pool=agent_pool,
            outcome=outcome
        ).inc()

        self.tokens_per_task.labels(
            task_type=task_type,
            model_tier=model_tier
        ).observe(tokens_used)

        self.reasoning_steps_per_task.labels(
            task_type=task_type,
            agent_pool=agent_pool
        ).observe(reasoning_steps)

        if outcome == "success":
            import time
            self.last_successful_task_timestamp.labels(
                agent_pool=agent_pool
            ).set(time.time())

    def record_tokens(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        model: str,
        agent_id: str
    ) -> None:
        """Record token usage."""
        agent_pool = self._agent_pool(agent_id)
        model_tier = self._model_tier(model)

        self.tokens_total.labels(
            token_type="prompt",
            model_tier=model_tier,
            agent_pool=agent_pool
        ).inc(prompt_tokens)

        self.tokens_total.labels(
            token_type="completion",
            model_tier=model_tier,
            agent_pool=agent_pool
        ).inc(completion_tokens)

    def record_tool_call(
        self,
        tool_name: str,
        agent_id: str,
        duration_seconds: float,
        success: bool
    ) -> None:
        """Record a tool invocation."""
        status = "success" if success else "error"
        agent_pool = self._agent_pool(agent_id)
        tool_category = self._tool_category(tool_name)

        self.tool_calls_total.labels(
            tool_category=tool_category,
            status=status,
            agent_pool=agent_pool
        ).inc()

        self.tool_duration_seconds.labels(
            tool_category=tool_category
        ).observe(duration_seconds)

    def record_model_call(
        self,
        model: str,
        agent_id: str,
        latency_seconds: float,
        success: bool
    ) -> None:
        """Record a model API call."""
        status = "success" if success else "error"
        agent_pool = self._agent_pool(agent_id)
        model_tier = self._model_tier(model)

        self.model_calls_total.labels(
            model_tier=model_tier,
            status=status,
            agent_pool=agent_pool
        ).inc()

        self.model_latency_seconds.labels(
            model_tier=model_tier
        ).observe(latency_seconds)

    def record_cost(
        self,
        cost_usd: float,
        model: str,
        task_type: str,
        agent_id: str
    ) -> None:
        """Record estimated cost."""
        model_tier = self._model_tier(model)
        self.estimated_cost_usd.labels(
            model_tier=model_tier,
            task_type=task_type
        ).inc(cost_usd)

    def set_agent_info(self, agent_id: str, version: str, model: str) -> None:
        """Set agent metadata."""
        self.agent_info.info({
            "agent_pool": self._agent_pool(agent_id),
            "version": version,
            "default_model_tier": self._model_tier(model)
        })

    def get_metrics(self) -> bytes:
        """Generate Prometheus metrics output."""
        return generate_latest(self.registry)

    def _agent_pool(self, agent_id: str) -> str:
        """Map arbitrary agent IDs to a bounded deployment pool."""
        value = (agent_id or "").lower()
        if "canary" in value:
            return "canary"
        if "shadow" in value:
            return "shadow"
        if "batch" in value:
            return "batch"
        if "eval" in value or "test" in value:
            return "nonprod"
        # Falling through to "primary" silently collapses cardinality; warn so
        # operators can audit unexpected agent_id shapes that route to default.
        # We warn at most once per ID (bounded set) so a fleet with legacy IDs
        # does not flood logs on every request.
        self._agent_pool_fallthrough_count += 1
        key = agent_id or ""
        if key not in self._warned_agent_ids:
            if len(self._warned_agent_ids) < self._warned_agent_ids_max:
                self._warned_agent_ids.add(key)
            logging.getLogger(__name__).warning(
                "Unrecognized agent_id shape %r; falling through to primary "
                "pool. Subsequent occurrences will be suppressed.",
                agent_id,
            )
        return "primary"

    @property
    def agent_pool_fallthrough_count(self) -> int:
        """Count of agent_ids that fell through to the default 'primary' pool.
        Sustained growth indicates misconfigured canary/shadow traffic or a
        new agent_id naming scheme not yet mapped. Operators should monitor
        this counter."""
        return self._agent_pool_fallthrough_count

    @staticmethod
    def _tool_category(tool_name: str) -> str:
        """Map exact tool names to bounded operational categories."""
        value = (tool_name or "").lower()
        if any(marker in value for marker in ("search", "retrieval", "rag", "vector")):
            return "retrieval"
        if any(marker in value for marker in ("sql", "db", "postgres", "mysql")):
            return "database"
        if any(marker in value for marker in ("http", "browser", "web", "fetch")):
            return "web"
        if any(marker in value for marker in ("file", "fs", "s3", "gcs", "blob")):
            return "file_io"
        if any(marker in value for marker in ("python", "bash", "shell", "code")):
            return "code_execution"
        if any(marker in value for marker in ("slack", "email", "calendar", "ticket")):
            return "workflow"
        if any(marker in value for marker in ("payment", "billing", "order")):
            return "business_action"
        return "other"

    @staticmethod
    def _model_tier(model: str) -> str:
        """Map raw model identifiers to bounded cost/latency tiers."""
        value = (model or "").lower()
        if "embed" in value:
            return "embedding"
        if "rerank" in value:
            return "reranker"
        if any(marker in value for marker in ("mini", "small", "lite", "haiku")):
            return "small"
        if any(marker in value for marker in ("frontier", "large", "opus", "pro")):
            return "frontier"
        if any(marker in value for marker in ("standard", "turbo", "sonnet")):
            return "standard"
        return "other"


class MetricsHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for Prometheus scraping."""

    metrics: PrometheusAgentMetrics

    def do_GET(self):
        if self.path == "/metrics":
            output = self.metrics.get_metrics()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging


@dataclass
class MetricsServerHandle:
    """Owns the background metrics server and its serving thread."""
    server: BoundedThreadingHTTPServer
    thread: threading.Thread
    shutdown_timeout: float = 5.0

    def shutdown(self, timeout: float | None = None) -> None:
        """Stop serving, close the socket, and wait briefly for the thread."""
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        self.thread.join(
            self.shutdown_timeout if timeout is None else timeout
        )

    def close(self, timeout: float | None = None) -> None:
        """Alias for shutdown(), useful in cleanup blocks."""
        self.shutdown(timeout=timeout)

    def __enter__(self) -> "MetricsServerHandle":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.server, name)


def start_metrics_server(
    metrics: PrometheusAgentMetrics,
    port: int = 9090,
    host: str = "127.0.0.1",
    request_queue_size: int = 32,
    connection_timeout: float = 5.0,
) -> MetricsServerHandle:
    """Start a Prometheus metrics server in a background thread.

    Uses ``ThreadingHTTPServer`` so concurrent Prometheus scrapes do
    not serialize on a single request handler (the default HTTPServer
    is single-threaded and becomes a bottleneck under multi-replica
    scrape configurations).
    """
    handler = type(
        'MetricsHandler',
        (MetricsHTTPHandler,),
        {'metrics': metrics}
    )

    server = BoundedThreadingHTTPServer(
        (host, port),
        handler,
        connection_timeout=connection_timeout,
        request_queue_size=request_queue_size,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    return MetricsServerHandle(server=server, thread=thread)

# ============================================================================
# Block 9 (chapter listing #9)
# ============================================================================

from dataclasses import dataclass, field
from typing import Any, Optional, Callable
from datetime import datetime, timezone
from contextlib import contextmanager
from collections import deque
import logging
import queue
import sys
import threading
import time
import statistics

logger = logging.getLogger(__name__)


@dataclass
class MetricSnapshot:
    """Point-in-time snapshot of agent metrics."""
    timestamp: datetime
    tasks_completed: int
    tasks_failed: int
    success_rate: float
    avg_duration_ms: float
    p95_duration_ms: float
    total_tokens: int
    avg_tokens_per_task: float
    active_tasks: int
    tool_calls: int
    tool_error_rate: float
    model_calls: int
    model_error_rate: float
    estimated_cost_usd: float
    callback_notifications_dropped: int = 0
    callback_errors: int = 0


class AgentMetrics:
    """Unified metrics collection for production agent systems.

    This class provides a comprehensive interface for collecting, aggregating,
    and exporting agent metrics. It supports multiple export formats and
    provides both real-time and historical metrics access.
    """

    def __init__(
        self,
        agent_id: str,
        window_size: int = 1000,
        prometheus_metrics: Optional[PrometheusAgentMetrics] = None,
        otel_instrumentation: Optional[OpenTelemetryAgentInstrumentation] = None,
        max_metric_callbacks: int = 64,
        callback_queue_size: int = 1024,
    ):
        if max_metric_callbacks < 0:
            raise ValueError("max_metric_callbacks must be non-negative")
        if callback_queue_size <= 0:
            raise ValueError("callback_queue_size must be positive")

        self.agent_id = agent_id
        self.window_size = window_size
        self.prometheus = prometheus_metrics
        self.otel = otel_instrumentation

        # Thread-safe counters
        self._lock = threading.RLock()

        # Rolling windows for statistics
        self._task_durations: deque[float] = deque(maxlen=window_size)
        self._task_tokens: deque[int] = deque(maxlen=window_size)
        self._tool_results: deque[bool] = deque(maxlen=window_size)
        self._model_results: deque[bool] = deque(maxlen=window_size)

        # Counters
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._total_tokens = 0
        self._total_cost = 0.0
        self._tool_calls = 0
        self._model_calls = 0
        # Wall-clock of the most recent completion/failure. Used by alert
        # rules that need windowed "no tasks processed in last N minutes"
        # semantics (the raw counters above are cumulative since startup
        # and so cannot answer that question directly).
        self._last_task_at: Optional[datetime] = None
        self._active_tasks = 0

        # Callbacks for custom metric handling. Callback execution is bounded
        # and asynchronous so instrumentation cannot block request completion.
        self._max_metric_callbacks = max_metric_callbacks
        self._metric_callbacks: dict[str, Callable[[str, Any], None]] = {}
        self._next_callback_id = 0
        self._callback_queue: queue.Queue[tuple[str, Any] | None] = queue.Queue(
            maxsize=callback_queue_size
        )
        self._callback_notifications_dropped = 0
        self._callback_errors = 0
        self._callback_worker = threading.Thread(
            target=self._run_callback_worker,
            name=f"agent-metrics-callbacks-{agent_id}",
            daemon=True,
        )
        self._callback_worker.start()

    def add_callback(self, callback: Callable[[str, Any], None]) -> str:
        """Register a callback for metric updates."""
        with self._lock:
            if len(self._metric_callbacks) >= self._max_metric_callbacks:
                raise RuntimeError("metric callback registry is full")
            callback_id = f"callback-{self._next_callback_id}"
            self._next_callback_id += 1
            self._metric_callbacks[callback_id] = callback
            return callback_id

    def remove_callback(self, callback_id: str) -> bool:
        """Remove a registered metric callback by id."""
        with self._lock:
            return self._metric_callbacks.pop(callback_id, None) is not None

    def _notify_callbacks(self, metric_name: str, value: Any) -> None:
        """Queue a metric update for registered callbacks."""
        with self._lock:
            has_callbacks = bool(self._metric_callbacks)
        if not has_callbacks:
            return

        try:
            self._callback_queue.put_nowait((metric_name, value))
        except queue.Full:
            with self._lock:
                self._callback_notifications_dropped += 1

    def _run_callback_worker(self) -> None:
        """Run metric callbacks away from the business request path."""
        while True:
            item = self._callback_queue.get()
            if item is None:
                self._callback_queue.task_done()
                return

            metric_name, value = item
            with self._lock:
                callbacks = list(self._metric_callbacks.values())

            for callback in callbacks:
                try:
                    callback(metric_name, value)
                except Exception as e:
                    with self._lock:
                        self._callback_errors += 1
                    logger.debug(
                        "Metric callback error suppressed: %s",
                        e,
                        exc_info=True,
                    )
            self._callback_queue.task_done()

    def wait_for_callbacks(self, timeout: float | None = None) -> bool:
        """Wait for queued callbacks to drain; intended for shutdown/tests."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while self._callback_queue.unfinished_tasks:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.001)
        return True

    def close(self, timeout: float | None = 1.0) -> None:
        """Stop the callback worker after draining queued notifications."""
        self.wait_for_callbacks(timeout=timeout)
        try:
            self._callback_queue.put_nowait(None)
        except queue.Full:
            # Queue is at capacity; drop the sentinel and increment the
            # existing dropped-notifications counter so operators see the
            # slow-shutdown case. We still attempt to join so the caller
            # can observe whether the worker exits on its own.
            with self._lock:
                self._callback_notifications_dropped += 1
            logger.warning(
                "AgentMetrics.close: callback queue full; sentinel "
                "dropped, worker may exit on next tick or be force-joined."
            )
        self._callback_worker.join(timeout=timeout)
        if self._callback_worker.is_alive():
            logger.warning(
                "AgentMetrics.close: callback worker did not exit within "
                "%ss; abandoning.",
                timeout,
            )

    def _call_metric_backend(
        self,
        operation: str,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Call a metrics backend without letting it affect business code."""
        try:
            func(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- exporter isolation
            logger.debug(
                "Metric backend error suppressed during %s: %s",
                operation,
                e,
                exc_info=True,
            )

    def _enter_task_trace(self, task_id: str, task_type: str) -> Any:
        """Enter the optional tracing context without failing the task."""
        if not self.otel:
            return None
        try:
            trace_context = self.otel.trace_task(task_id, task_type)
            trace_context.__enter__()
            return trace_context
        except Exception as e:  # noqa: BLE001 -- exporter isolation
            logger.debug(
                "Metric trace backend error suppressed during task start: %s",
                e,
                exc_info=True,
            )
            return None

    def _exit_task_trace(self, trace_context: Any, exc_info: tuple) -> None:
        """Exit the optional tracing context without masking task outcome."""
        if trace_context is None:
            return
        try:
            trace_context.__exit__(*exc_info)
        except Exception as e:  # noqa: BLE001 -- exporter isolation
            logger.debug(
                "Metric trace backend error suppressed during task end: %s",
                e,
                exc_info=True,
            )

    @contextmanager
    def track_task(
        self,
        task_id: str,
        task_type: str = "default",
        model: str = "unknown"
    ):
        """Context manager for tracking a complete task execution.

        Usage:
            with metrics.track_task("task-123", "query", "claude-3"):
                # Execute task
                pass
        """
        start_time = time.perf_counter()
        task_tokens = 0
        reasoning_steps = 0

        with self._lock:
            self._active_tasks += 1

        if self.prometheus:
            self._call_metric_backend(
                "task start",
                self.prometheus.record_task_start,
                task_type,
                self.agent_id,
            )

        # Create a context object for the task to update
        class TaskContext:
            def __init__(ctx):
                ctx.tokens = 0
                ctx.steps = 0

            def add_tokens(ctx, count: int):
                nonlocal task_tokens
                task_tokens += count
                ctx.tokens = task_tokens

            def increment_steps(ctx):
                nonlocal reasoning_steps
                reasoning_steps += 1
                ctx.steps = reasoning_steps

        context = TaskContext()
        success = False
        business_error: BaseException | None = None
        exc_info: tuple = (None, None, None)
        trace_context = self._enter_task_trace(task_id, task_type)

        try:
            yield context
            success = True
        except BaseException as e:
            business_error = e
            exc_info = sys.exc_info()
            raise
        finally:
            self._exit_task_trace(trace_context, exc_info)
            duration_ms = (time.perf_counter() - start_time) * 1000
            finished_at = datetime.now(timezone.utc)

            with self._lock:
                if success:
                    self._tasks_completed += 1
                    self._task_durations.append(duration_ms)
                    self._task_tokens.append(task_tokens)
                    self._total_tokens += task_tokens
                else:
                    self._tasks_failed += 1
                self._active_tasks = max(0, self._active_tasks - 1)
                self._last_task_at = finished_at

            if self.prometheus:
                self._call_metric_backend(
                    "task complete",
                    self.prometheus.record_task_complete,
                    task_type=task_type,
                    agent_id=self.agent_id,
                    outcome="success" if success else "failure",
                    duration_seconds=duration_ms / 1000,
                    tokens_used=task_tokens,
                    model=model,
                    reasoning_steps=reasoning_steps,
                )

            callback_payload = {
                "task_id": task_id,
                "success": success,
                "duration_ms": duration_ms,
            }
            if business_error is not None:
                callback_payload["error"] = str(business_error)
            self._notify_callbacks("task_complete", callback_payload)

    @contextmanager
    def track_tool(self, tool_name: str):
        """Context manager for tracking tool execution."""
        start_time = time.perf_counter()

        try:
            if self.otel:
                with self.otel.trace_tool(tool_name, {}):
                    yield
            else:
                yield

            duration_seconds = time.perf_counter() - start_time

            with self._lock:
                self._tool_calls += 1
                self._tool_results.append(True)

            if self.prometheus:
                self._call_metric_backend(
                    "tool call success",
                    self.prometheus.record_tool_call,
                    tool_name, self.agent_id, duration_seconds, True
                )

        except Exception:
            duration_seconds = time.perf_counter() - start_time

            with self._lock:
                self._tool_calls += 1
                self._tool_results.append(False)

            if self.prometheus:
                self._call_metric_backend(
                    "tool call failure",
                    self.prometheus.record_tool_call,
                    tool_name, self.agent_id, duration_seconds, False
                )

            raise

    @contextmanager
    def track_model_call(self, model: str):
        """Context manager for tracking model API calls."""
        start_time = time.perf_counter()

        try:
            if self.otel:
                with self.otel.trace_model_call(model):
                    yield
            else:
                yield

            latency_seconds = time.perf_counter() - start_time

            with self._lock:
                self._model_calls += 1
                self._model_results.append(True)

            if self.prometheus:
                self._call_metric_backend(
                    "model call success",
                    self.prometheus.record_model_call,
                    model, self.agent_id, latency_seconds, True
                )

        except Exception:
            latency_seconds = time.perf_counter() - start_time

            with self._lock:
                self._model_calls += 1
                self._model_results.append(False)

            if self.prometheus:
                self._call_metric_backend(
                    "model call failure",
                    self.prometheus.record_model_call,
                    model, self.agent_id, latency_seconds, False
                )

            raise

    def record_cost(self, cost_usd: float, model: str, task_type: str) -> None:
        """Record estimated cost for a task."""
        with self._lock:
            self._total_cost += cost_usd

        if self.prometheus:
            self._call_metric_backend(
                "cost record",
                self.prometheus.record_cost,
                cost_usd,
                model,
                task_type,
                self.agent_id,
            )

    def get_snapshot(self) -> MetricSnapshot:
        """Get a point-in-time snapshot of all metrics."""
        with self._lock:
            total_tasks = self._tasks_completed + self._tasks_failed
            success_rate = (
                self._tasks_completed / total_tasks if total_tasks > 0 else 0.0
            )

            avg_duration = (
                statistics.mean(self._task_durations)
                if self._task_durations else 0.0
            )

            # p95 with linear interpolation between adjacent ranks, matching
            # NumPy's percentile(method='linear') / Excel PERCENTILE.INC.
            if self._task_durations:
                sorted_durations = sorted(self._task_durations)
                n = len(sorted_durations)
                rank = 0.95 * (n - 1)
                lower_idx = int(rank)
                upper_idx = min(lower_idx + 1, n - 1)
                weight = rank - lower_idx
                p95_duration = (
                    sorted_durations[lower_idx] * (1 - weight)
                    + sorted_durations[upper_idx] * weight
                )
            else:
                p95_duration = 0.0

            avg_tokens = (
                statistics.mean(self._task_tokens)
                if self._task_tokens else 0.0
            )

            tool_successes = sum(self._tool_results)
            tool_error_rate = (
                1 - (tool_successes / len(self._tool_results))
                if self._tool_results else 0.0
            )

            model_successes = sum(self._model_results)
            model_error_rate = (
                1 - (model_successes / len(self._model_results))
                if self._model_results else 0.0
            )

            return MetricSnapshot(
                timestamp=datetime.now(timezone.utc),
                tasks_completed=self._tasks_completed,
                tasks_failed=self._tasks_failed,
                success_rate=success_rate,
                avg_duration_ms=avg_duration,
                p95_duration_ms=p95_duration,
                total_tokens=self._total_tokens,
                avg_tokens_per_task=avg_tokens,
                active_tasks=self._active_tasks,
                tool_calls=self._tool_calls,
                tool_error_rate=tool_error_rate,
                model_calls=self._model_calls,
                model_error_rate=model_error_rate,
                estimated_cost_usd=self._total_cost,
                callback_notifications_dropped=(
                    self._callback_notifications_dropped
                ),
                callback_errors=self._callback_errors,
            )

# ============================================================================
# Block 10 (chapter listing #10)
# ============================================================================

from dataclasses import dataclass
from typing import Optional
from collections import deque, OrderedDict
import math
import statistics


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    is_anomaly: bool
    score: float  # Standard deviations from mean
    metric_name: str
    current_value: float
    expected_value: float
    threshold: float
    description: str


class AgentAnomalyDetector:
    """Statistical anomaly detection for agent behavior patterns.

    Uses z-score analysis with optional hour-of-day seasonal baselines
    to identify unusual agent behavior.

    Production features:
    - Bounded metric tracking (max_metrics) to prevent unbounded memory growth
    - LRU eviction when at capacity
    """

    MAX_METRICS: int = 1000  # Limit unique metrics tracked

    def __init__(
        self,
        baseline_window: int = 1000,
        sensitivity: float = 3.0,  # Standard deviations
        min_samples: int = 100,
        max_metrics: int = MAX_METRICS
    ):
        if baseline_window <= 0:
            raise ValueError("baseline_window must be positive")
        if sensitivity <= 0:
            raise ValueError("sensitivity must be positive")
        if min_samples <= 0:
            raise ValueError("min_samples must be positive")
        if max_metrics <= 0:
            raise ValueError("max_metrics must be positive")
        self.baseline_window = baseline_window
        self.sensitivity = sensitivity
        self.min_samples = min_samples
        self._max_metrics = max_metrics

        # Metric baselines with LRU tracking. Access order is recorded in an
        # OrderedDict so updates and evictions are O(1) instead of the O(n)
        # list.remove() / pop(0) pair the earlier draft used.
        self._baselines: dict[str, deque[float]] = {}
        self._hourly_baselines: dict[str, dict[int, deque[float]]] = {}
        self._access_order: "OrderedDict[str, None]" = OrderedDict()

    def _get_baseline(self, metric_name: str) -> deque[float]:
        """Get or create baseline for a metric with LRU eviction."""
        if metric_name in self._baselines:
            # O(1) move to most-recently-used end.
            self._access_order.move_to_end(metric_name)
            return self._baselines[metric_name]

        # Check capacity before adding new metric
        if len(self._baselines) >= self._max_metrics:
            oldest, _ = self._access_order.popitem(last=False)
            del self._baselines[oldest]
            self._hourly_baselines.pop(oldest, None)

        self._baselines[metric_name] = deque(maxlen=self.baseline_window)
        self._access_order[metric_name] = None
        return self._baselines[metric_name]

    def _get_hourly_baseline(
        self,
        metric_name: str,
        hour: int
    ) -> deque[float]:
        """Get or create hourly baseline for seasonal patterns."""
        if metric_name not in self._hourly_baselines:
            self._hourly_baselines[metric_name] = {}

        if hour not in self._hourly_baselines[metric_name]:
            self._hourly_baselines[metric_name][hour] = deque(
                maxlen=max(self.min_samples, self.baseline_window // 24, 1)
            )

        return self._hourly_baselines[metric_name][hour]

    def record_and_check(
        self,
        metric_name: str,
        value: float,
        hour: Optional[int] = None
    ) -> Optional[AnomalyResult]:
        """Record a metric value and check for anomalies.

        Args:
            metric_name: Name of the metric being recorded.
            value: Current value of the metric.
            hour: Optional hour of day (0-23) for seasonal adjustment.

        Returns:
            AnomalyResult if anomaly detected, None otherwise.
        """
        if hour is not None and not 0 <= hour <= 23:
            raise ValueError("hour must be between 0 and 23")

        baseline = self._get_baseline(metric_name)

        prior_values = list(baseline)
        hourly_baseline = None
        scoring_values = prior_values

        if hour is not None:
            hourly_baseline = self._get_hourly_baseline(metric_name, hour)
            hourly_prior_values = list(hourly_baseline)
            if len(hourly_prior_values) >= self.min_samples:
                scoring_values = hourly_prior_values

        # Need minimum samples for detection
        if len(scoring_values) < self.min_samples:
            baseline.append(value)
            if hourly_baseline is not None:
                hourly_baseline.append(value)
            return None

        # Calculate z-score against the prior baseline. Adding the candidate
        # first would dilute the score and invalidate the usual z-threshold.
        mean = statistics.mean(scoring_values)
        stdev = statistics.stdev(scoring_values) if len(scoring_values) > 1 else 0

        if stdev == 0:
            baseline.append(value)
            if hourly_baseline is not None:
                hourly_baseline.append(value)
            return None

        z_score = (value - mean) / stdev

        # Check if anomalous
        result = None
        if abs(z_score) > self.sensitivity:
            direction = "above" if z_score > 0 else "below"
            result = AnomalyResult(
                is_anomaly=True,
                score=z_score,
                metric_name=metric_name,
                current_value=value,
                expected_value=mean,
                threshold=self.sensitivity,
                description=(
                    f"{metric_name} is {abs(z_score):.1f} standard deviations "
                    f"{direction} normal ({value:.2f} vs expected {mean:.2f})"
                )
            )

        baseline.append(value)
        if hourly_baseline is not None:
            hourly_baseline.append(value)

        return result

    def check_task_duration_anomaly(
        self,
        duration_ms: float,
        task_type: str
    ) -> Optional[AnomalyResult]:
        """Check if task duration is anomalous."""
        return self.record_and_check(f"task_duration_{task_type}", duration_ms)

    def check_token_usage_anomaly(
        self,
        tokens: int,
        task_type: str
    ) -> Optional[AnomalyResult]:
        """Check if token usage is anomalous."""
        return self.record_and_check(f"token_usage_{task_type}", float(tokens))

    def check_reasoning_steps_anomaly(
        self,
        steps: int,
        task_type: str
    ) -> Optional[AnomalyResult]:
        """Check if reasoning step count is anomalous."""
        return self.record_and_check(f"reasoning_steps_{task_type}", float(steps))

    def check_error_rate_anomaly(
        self,
        error_rate: float,
        component: str
    ) -> Optional[AnomalyResult]:
        """Check if error rate is anomalous."""
        # Use one-sided detection for error rates (only alert on increases)
        baseline = self._get_baseline(f"error_rate_{component}")
        prior_values = list(baseline)

        if len(prior_values) < self.min_samples:
            baseline.append(error_rate)
            return None

        mean = statistics.mean(prior_values)
        stdev = statistics.stdev(prior_values) if len(prior_values) > 1 else 0

        if stdev == 0:
            baseline.append(error_rate)
            return None

        z_score = (error_rate - mean) / stdev

        # Only alert on increases
        result = None
        if z_score > self.sensitivity:
            result = AnomalyResult(
                is_anomaly=True,
                score=z_score,
                metric_name=f"error_rate_{component}",
                current_value=error_rate,
                expected_value=mean,
                threshold=self.sensitivity,
                description=(
                    f"{component} error rate spike: {error_rate:.1%} "
                    f"(normally {mean:.1%})"
                )
            )

        baseline.append(error_rate)
        return result


class BehaviorDriftDetector:
    """Detect gradual drift in agent behavior patterns.

    Per-metric history is held in two OrderedDicts capped at
    ``max_metrics`` entries with LRU eviction, so a long-running
    process cannot grow unbounded if metric names include
    high-cardinality labels (e.g., per-tenant or per-request IDs).
    """

    def __init__(
        self,
        window_size: int = 500,
        drift_threshold: float = 0.1,
        max_metrics: int = 10_000,
    ):
        if window_size <= 0:
            raise ValueError("window_size must be positive")
        if drift_threshold <= 0:
            raise ValueError("drift_threshold must be positive")
        if max_metrics <= 0:
            raise ValueError("max_metrics must be positive")
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.max_metrics = max_metrics
        self._recent: "OrderedDict[str, deque[float]]" = OrderedDict()
        self._historical: "OrderedDict[str, deque[float]]" = OrderedDict()

    def warmup_complete(self, metric_name: str) -> bool:
        """True once the metric's historical buffer holds more than
        ``2 * window_size`` samples. Drift comparisons before this point
        should be treated as low-confidence: the older slice has not yet
        accumulated enough samples to be a stable baseline."""
        historical = self._historical.get(metric_name)
        if historical is None:
            return False
        return len(historical) >= 2 * self.window_size

    def record(self, metric_name: str, value: float) -> Optional[str]:
        """Record a value and check for drift.

        Returns a drift warning message if drift detected.
        """
        if metric_name not in self._recent:
            # LRU eviction: drop the oldest metric series when at capacity.
            while len(self._recent) >= self.max_metrics:
                self._recent.popitem(last=False)
                self._historical.popitem(last=False)
            self._recent[metric_name] = deque(maxlen=self.window_size)
            self._historical[metric_name] = deque(maxlen=self.window_size * 4)
        else:
            # Mark this metric as most-recently used.
            self._recent.move_to_end(metric_name)
            self._historical.move_to_end(metric_name)

        self._recent[metric_name].append(value)
        self._historical[metric_name].append(value)

        recent = self._recent[metric_name]
        historical = self._historical[metric_name]

        if len(recent) < self.window_size or len(historical) < self.window_size * 2:
            return None

        # Compare recent window to older historical data
        recent_mean = statistics.mean(recent)
        older_data = list(historical)[:-self.window_size]
        historical_mean = statistics.mean(older_data)

        if historical_mean == 0:
            return None

        drift_ratio = abs(recent_mean - historical_mean) / historical_mean

        if drift_ratio > self.drift_threshold:
            direction = "increased" if recent_mean > historical_mean else "decreased"
            return (
                f"Behavior drift detected in {metric_name}: "
                f"{direction} by {drift_ratio:.1%} "
                f"(from {historical_mean:.2f} to {recent_mean:.2f})"
            )

        return None

# ============================================================================
# Block 11 (chapter listing #11)
# ============================================================================

from dataclasses import dataclass
from typing import Callable
from datetime import datetime, timedelta, timezone
from enum import Enum


class SLOStatus(Enum):
    HEALTHY = "healthy"
    AT_RISK = "at_risk"
    BREACHED = "breached"


@dataclass
class SLI:
    """Service Level Indicator definition."""
    name: str
    description: str
    unit: str
    good_event_query: Callable[[], int]
    total_event_query: Callable[[], int]


@dataclass
class SLO:
    """Service Level Objective definition."""
    name: str
    description: str
    sli: SLI
    target_percentage: float  # e.g., 99.5 for 99.5%
    window_days: int = 30
    # A 10x burn rate consumes a 30-day error budget in ~3 days (30 / 10).
    # Production alerting often uses separate fast and slow windows; this
    # in-process example reports a single one-hour approximation.
    burn_rate_alert_threshold: float = 10.0


@dataclass
class SLOState:
    """Current state of an SLO."""
    slo: SLO
    current_percentage: float
    error_budget_remaining: float
    burn_rate: float
    status: SLOStatus
    window_start: datetime
    window_end: datetime
    good_events: int
    total_events: int


class AgentSLOManager:
    """Manage SLOs and SLIs for agent systems.

    Implements error budget management with a bounded, in-process
    one-hour burn-rate approximation.
    """

    def __init__(self):
        self._slos: dict[str, SLO] = {}
        self._event_buckets: dict[str, dict[int, list[int]]] = {}

    def register_slo(self, slo: SLO) -> None:
        """Register an SLO for tracking."""
        self._slos[slo.name] = slo
        self._event_buckets[slo.name] = {}

    def record_event(self, slo_name: str, is_good: bool) -> None:
        """Record an event (good or bad) for an SLO."""
        if slo_name not in self._event_buckets:
            raise ValueError(f"Unknown SLO: {slo_name}")

        now = datetime.now(timezone.utc)
        bucket_key = self._bucket_key(now)
        bucket = self._event_buckets[slo_name].setdefault(bucket_key, [0, 0])
        if is_good:
            bucket[0] += 1
        bucket[1] += 1

        slo = self._slos[slo_name]
        self._prune_old_buckets(slo_name, now, slo.window_days)

    def get_state(self, slo_name: str) -> SLOState:
        """Get current state of an SLO."""
        if slo_name not in self._slos:
            raise ValueError(f"Unknown SLO: {slo_name}")

        slo = self._slos[slo_name]
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=slo.window_days)
        self._prune_old_buckets(slo_name, now, slo.window_days)

        buckets = self._event_buckets[slo_name]
        window_start_key = self._bucket_key(window_start)
        bucket_values = [
            counts for key, counts in buckets.items()
            if key >= window_start_key
        ]

        bucket_good_events = sum(counts[0] for counts in bucket_values)
        bucket_total_events = sum(counts[1] for counts in bucket_values)

        sampled_for_state = False
        if bucket_total_events > 0:
            good_events = bucket_good_events
            total_events = bucket_total_events
        else:
            good_events, total_events = self._sample_sli(slo)
            sampled_for_state = total_events > 0

        if total_events == 0:
            current_percentage = 100.0
        else:
            current_percentage = (good_events / total_events) * 100

        # Calculate error budget
        error_budget_total = 100.0 - slo.target_percentage
        errors_actual = 100.0 - current_percentage

        if error_budget_total > 0:
            error_budget_remaining = max(
                0,
                (error_budget_total - errors_actual) / error_budget_total * 100
            )
        else:
            error_budget_remaining = 0 if errors_actual > 0 else 100

        # Calculate burn rate (how fast we're consuming error budget)
        # Using 1-hour bucket window for burn rate calculation
        one_hour_ago = now - timedelta(hours=1)
        one_hour_key = self._bucket_key(one_hour_ago)
        recent_values = [
            counts for key, counts in buckets.items()
            if key >= one_hour_key
        ]

        recent_total = sum(counts[1] for counts in recent_values)
        if recent_total:
            recent_good = sum(counts[0] for counts in recent_values)
            recent_error_rate = 1 - (recent_good / recent_total)
            expected_error_rate = (100 - slo.target_percentage) / 100

            if expected_error_rate > 0:
                burn_rate = recent_error_rate / expected_error_rate
            else:
                burn_rate = float('inf') if recent_error_rate > 0 else 0
        elif sampled_for_state:
            query_error_rate = 1 - (good_events / total_events)
            expected_error_rate = (100 - slo.target_percentage) / 100
            if expected_error_rate > 0:
                burn_rate = query_error_rate / expected_error_rate
            else:
                burn_rate = float('inf') if query_error_rate > 0 else 0
        else:
            burn_rate = 0

        # Determine status
        if current_percentage < slo.target_percentage:
            status = SLOStatus.BREACHED
        elif burn_rate > slo.burn_rate_alert_threshold:
            status = SLOStatus.AT_RISK
        elif error_budget_remaining < 20:
            status = SLOStatus.AT_RISK
        else:
            status = SLOStatus.HEALTHY

        return SLOState(
            slo=slo,
            current_percentage=current_percentage,
            error_budget_remaining=error_budget_remaining,
            burn_rate=burn_rate,
            status=status,
            window_start=window_start,
            window_end=now,
            good_events=good_events,
            total_events=total_events
        )

    def get_all_states(self) -> list[SLOState]:
        """Get state of all registered SLOs."""
        return [self.get_state(name) for name in self._slos]

    def _sample_sli(self, slo: SLO) -> tuple[int, int]:
        """Sample the SLI query callables and normalize event counts."""
        good_events = max(0, int(slo.sli.good_event_query()))
        total_events = max(0, int(slo.sli.total_event_query()))
        return min(good_events, total_events), total_events

    @staticmethod
    def _bucket_key(timestamp: datetime) -> int:
        """Return a UTC minute bucket key for bounded in-process state."""
        return int(timestamp.timestamp() // 60)

    def _prune_old_buckets(
        self,
        slo_name: str,
        now: datetime,
        window_days: int
    ) -> None:
        """Drop buckets older than the SLO window.

        State grows with configured window size, not event volume:
        a 30-day SLO stores at most about 43,200 minute buckets per SLO.
        """
        cutoff_key = self._bucket_key(now - timedelta(days=window_days))
        buckets = self._event_buckets[slo_name]
        for key in list(buckets):
            if key < cutoff_key:
                del buckets[key]


def create_standard_agent_slos(metrics: AgentMetrics) -> list[SLO]:
    """Create standard SLO definitions for an agent system."""

    def task_success_good() -> int:
        with metrics._lock:
            return metrics._tasks_completed

    def task_success_total() -> int:
        with metrics._lock:
            return metrics._tasks_completed + metrics._tasks_failed

    def task_latency_good() -> int:
        with metrics._lock:
            return sum(1 for d in metrics._task_durations if d < 30000)

    def task_latency_total() -> int:
        with metrics._lock:
            return len(metrics._task_durations)

    task_success_sli = SLI(
        name="task_success_rate",
        description="Percentage of tasks completing successfully",
        unit="percent",
        good_event_query=task_success_good,
        total_event_query=task_success_total
    )

    task_latency_sli = SLI(
        name="task_latency_p95",
        description="95th percentile task latency under 30 seconds",
        unit="seconds",
        good_event_query=task_latency_good,
        total_event_query=task_latency_total
    )

    return [
        SLO(
            name="task_success",
            description="Tasks should succeed at least 99.5% of the time",
            sli=task_success_sli,
            target_percentage=99.5,
            window_days=30
        ),
        SLO(
            name="task_latency",
            description="95% of tasks should complete within 30 seconds",
            sli=task_latency_sli,
            target_percentage=95.0,
            window_days=7
        )
    ]

# ============================================================================
# Block 12 (chapter listing #12)
# ============================================================================

from dataclasses import dataclass, field
from typing import Callable, Any, Optional
from datetime import datetime, timedelta, timezone
from enum import Enum
from collections import defaultdict
import hashlib


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertState(Enum):
    FIRING = "firing"
    PENDING = "pending"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """An alert instance."""
    name: str
    severity: AlertSeverity
    message: str
    labels: dict[str, str]
    annotations: dict[str, str]
    state: AlertState
    started_at: datetime
    resolved_at: Optional[datetime] = None
    fingerprint: str = field(default="")

    def __post_init__(self):
        if not self.fingerprint:
            # Create unique fingerprint from name and labels
            label_str = str(sorted(self.labels.items()))
            self.fingerprint = hashlib.sha256(
                f"{self.name}{label_str}".encode()
            ).hexdigest()[:16]


@dataclass
class AlertRule:
    """Definition of an alerting rule."""
    name: str
    description: str
    severity: AlertSeverity
    condition: Callable[[], bool]
    for_duration: timedelta  # Alert must fire for this long before triggering
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    cooldown: timedelta = field(default_factory=lambda: timedelta(minutes=30))


class AgentAlertManager:
    """Alert management with fatigue prevention.

    Implements:
    - Alert deduplication
    - Cooldown periods
    - Severity-based routing
    - Alert grouping
    - Silencing
    """

    def __init__(self):
        self._rules: list[AlertRule] = []
        self._active_alerts: dict[str, Alert] = {}
        self._pending_alerts: dict[str, datetime] = {}
        self._cooldowns: dict[str, datetime] = {}
        self._silences: dict[str, datetime] = {}  # fingerprint -> until
        self._alert_handlers: dict[AlertSeverity, list[Callable[[Alert], None]]] = (
            defaultdict(list)
        )

    def add_rule(self, rule: AlertRule) -> None:
        """Add an alerting rule."""
        self._rules.append(rule)

    def register_handler(
        self,
        severity: AlertSeverity,
        handler: Callable[[Alert], None]
    ) -> None:
        """Register a handler for alerts of a given severity."""
        self._alert_handlers[severity].append(handler)

    def silence(self, fingerprint: str, duration: timedelta) -> None:
        """Silence an alert for a specified duration."""
        self._silences[fingerprint] = datetime.now(timezone.utc) + duration

    def evaluate_rules(self) -> list[Alert]:
        """Evaluate all rules and return new/changed alerts."""
        now = datetime.now(timezone.utc)
        new_alerts: list[Alert] = []

        # Clean expired silences
        self._silences = {
            fp: until for fp, until in self._silences.items()
            if until > now
        }

        # Clean expired cooldowns so the dict cannot grow without bound;
        # entries are only meaningful while now < cooldown_end.
        self._cooldowns = {
            fp: until for fp, until in self._cooldowns.items()
            if until > now
        }

        for rule in self._rules:
            # Generate fingerprint for this rule
            label_str = str(sorted(rule.labels.items()))
            fingerprint = hashlib.sha256(
                f"{rule.name}{label_str}".encode()
            ).hexdigest()[:16]

            # Check if silenced
            if fingerprint in self._silences:
                continue

            # Check cooldown
            if fingerprint in self._cooldowns:
                if now < self._cooldowns[fingerprint]:
                    continue

            # Evaluate condition
            try:
                condition_met = rule.condition()
            except Exception as e:
                logger.warning(f"Alert rule {rule.name} evaluation failed: {e}")
                continue

            if condition_met:
                # Check if already pending
                if fingerprint in self._pending_alerts:
                    pending_since = self._pending_alerts[fingerprint]
                    if now - pending_since >= rule.for_duration:
                        # Promote to firing
                        if fingerprint not in self._active_alerts:
                            alert = Alert(
                                name=rule.name,
                                severity=rule.severity,
                                message=rule.description,
                                labels=rule.labels,
                                annotations=rule.annotations,
                                state=AlertState.FIRING,
                                started_at=pending_since,
                                fingerprint=fingerprint
                            )
                            self._active_alerts[fingerprint] = alert
                            new_alerts.append(alert)
                            self._fire_alert(alert)
                else:
                    # Start pending period
                    self._pending_alerts[fingerprint] = now
            else:
                # Condition not met
                if fingerprint in self._pending_alerts:
                    del self._pending_alerts[fingerprint]

                if fingerprint in self._active_alerts:
                    # Resolve the alert
                    alert = self._active_alerts[fingerprint]
                    alert.state = AlertState.RESOLVED
                    alert.resolved_at = now
                    new_alerts.append(alert)
                    del self._active_alerts[fingerprint]

                    # Set cooldown
                    self._cooldowns[fingerprint] = now + rule.cooldown

        return new_alerts

    def _fire_alert(self, alert: Alert) -> None:
        """Fire handlers for a new alert."""
        for handler in self._alert_handlers[alert.severity]:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Alert handler failed for {alert.name}: {e}", exc_info=True)

    def get_active_alerts(self) -> list[Alert]:
        """Get all currently firing alerts."""
        return list(self._active_alerts.values())


def create_standard_agent_alerts(
    metrics: AgentMetrics,
    anomaly_detector: AgentAnomalyDetector,
    slo_manager: AgentSLOManager
) -> list[AlertRule]:
    """Create standard alerting rules for agent systems."""

    return [
        AlertRule(
            name="high_task_failure_rate",
            description="Task failure rate exceeds 10%",
            severity=AlertSeverity.ERROR,
            condition=lambda: (
                metrics._tasks_failed /
                max(1, metrics._tasks_completed + metrics._tasks_failed)
            ) > 0.10,
            for_duration=timedelta(minutes=5),
            labels={"component": "agent", "type": "reliability"}
        ),
        AlertRule(
            name="slo_breach",
            description="SLO target breached",
            severity=AlertSeverity.CRITICAL,
            condition=lambda: any(
                state.status == SLOStatus.BREACHED
                for state in slo_manager.get_all_states()
            ),
            for_duration=timedelta(minutes=1),
            labels={"component": "agent", "type": "slo"}
        ),
        AlertRule(
            name="high_burn_rate",
            description="Error budget burning too fast",
            severity=AlertSeverity.WARNING,
            condition=lambda: any(
                state.burn_rate > 5.0
                for state in slo_manager.get_all_states()
            ),
            for_duration=timedelta(minutes=10),
            labels={"component": "agent", "type": "slo"}
        ),
        AlertRule(
            name="no_tasks_processed",
            description="No tasks processed in 15 minutes",
            severity=AlertSeverity.WARNING,
            # Windowed: fires when no completion/failure has been
            # recorded in the last 15 minutes AND nothing is currently
            # active. Cumulative counters cannot answer "in the last
            # window" so we check _last_task_at directly.
            condition=lambda: metrics._active_tasks == 0 and (
                metrics._last_task_at is None
                or (datetime.now(timezone.utc) - metrics._last_task_at)
                >= timedelta(minutes=15)
            ),
            for_duration=timedelta(minutes=15),
            labels={"component": "agent", "type": "availability"}
        ),
        AlertRule(
            name="high_token_usage",
            description="Token usage anomalously high",
            severity=AlertSeverity.WARNING,
            condition=lambda: (
                len(metrics._task_tokens) > 100 and
                sum(list(metrics._task_tokens)[-10:]) / 10 >
                sum(metrics._task_tokens) / len(metrics._task_tokens) * 2
            ),
            for_duration=timedelta(minutes=5),
            labels={"component": "agent", "type": "cost"},
            cooldown=timedelta(hours=1)
        )
    ]

# ============================================================================
# Block 13 (chapter block #13) — non-python listing (log output)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_13_listing = r"""
2026-03-15 14:23:00 ANOMALY DETECTED
Metric: reasoning_steps_per_task_support_ticket
Current: 2.3 (mean: 5.8, stddev: 1.2)
Z-score: -2.9
Description: Tasks completing with unusually few reasoning steps

2026-03-15 14:45:00 DRIFT DETECTED
Metric: token_usage_support_ticket
Trend: Decreased by 42% over past 2 weeks
Historical mean: 3,400 tokens
Current mean: 1,980 tokens
"""

# ============================================================================
# Block 14 (chapter block #14) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_14_listing = r"""
Before Update:
Task: resolve_billing_dispute
  Step 1: Understand customer complaint (450 tokens)
  Step 2: Query billing history (tool call)
  Step 3: Analyze discrepancies (890 tokens)
  Step 4: Check policy guidelines (tool call)
  Step 5: Formulate resolution (720 tokens)
  Step 6: Draft response (640 tokens)
  Total: 6 steps, 3,400 tokens

After Update:
Task: resolve_billing_dispute
  Step 1: Understand customer complaint (380 tokens)
  Step 2: Query billing history (tool call)
  Step 3: Draft response (520 tokens)
  Total: 3 steps, 1,200 tokens
"""

# ============================================================================
# Block 15 (chapter listing #15)
# ============================================================================

class QualityMetrics:
    """Metrics for agent output quality monitoring."""

    def __init__(self, prometheus: PrometheusAgentMetrics):
        self.prometheus = prometheus

        self.output_length = Histogram(
            "agent_output_length_chars",
            "Length of agent outputs in characters",
            ["task_type"],
            buckets=[100, 250, 500, 1000, 2000, 5000, 10000],
            registry=self.prometheus.registry
        )

        self.reasoning_depth = Histogram(
            "agent_reasoning_depth",
            "Depth of reasoning (nested tool calls)",
            ["task_type"],
            buckets=[1, 2, 3, 4, 5, 7, 10, 15],
            registry=self.prometheus.registry
        )

        self.tool_diversity = Histogram(
            "agent_tool_diversity",
            "Number of unique tools used per task",
            ["task_type"],
            buckets=[1, 2, 3, 4, 5, 7, 10],
            registry=self.prometheus.registry
        )

    def record_task_quality(
        self,
        task_type: str,
        output_length: int,
        reasoning_depth: int,
        tools_used: set[str]
    ) -> None:
        """Record quality metrics for a completed task."""
        self.output_length.labels(task_type=task_type).observe(output_length)
        self.reasoning_depth.labels(task_type=task_type).observe(reasoning_depth)
        self.tool_diversity.labels(task_type=task_type).observe(len(tools_used))
