"""
Error Handling and Resilience

Code listings from Chapter 07, Book 2:
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

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Type
from datetime import datetime, timedelta, timezone
import traceback


# ---------------------------------------------------------------------------
# Placeholder request/response models and collaborators used by the multi-agent
# walkthrough in Block 15. Real deployments will replace these with concrete
# implementations, but the stubs let this module import cleanly so every
# chapter listing remains executable in isolation.
# ---------------------------------------------------------------------------
@dataclass
class UserRequest:
    query: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"query": self.query}


@dataclass
class Response:
    content: str = ""
    degraded: bool = False


# Pedagogical placeholders for the multi-agent walkthrough in Block 15.
# Replaced with fail-loud RequiredDependency so a copy-paste deployment
# raises a clear error rather than silently no-oping. See the
# Production Setup Checklist below.
#
# Production Setup Checklist
# --------------------------
# 1. Replace ``recommendation_agent`` with the real downstream agent
#    client (HTTP, gRPC, or in-process callable).
# 2. Replace ``classifier`` with the real error classifier (typically
#    an instance of ErrorClassifier defined later in this chapter).
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _optional import _RequiredDependency  # noqa: E402

recommendation_agent = _RequiredDependency(  # TODO[1]: see checklist
    "recommendation_agent",
    "Replace with the real downstream agent client.",
)
classifier = _RequiredDependency(  # TODO[2]: see checklist
    "classifier",
    "Replace with an ErrorClassifier instance (defined later in this chapter).",
)


class ErrorCategory(Enum):
    """Primary classification of agent system errors."""
    LLM_ERROR = auto()           # Upstream model API failures (timeouts, 5xx)
    TOOL_FAILURE = auto()        # A tool/integration returned an error
    TIMEOUT = auto()             # Wall-clock deadline exceeded
    VALIDATION = auto()          # Input failed schema validation
    # OUTPUT_VALIDATION: model output failed schema/safety validation;
    # recover by reprompting with the validator error as feedback
    # (retry-with-feedback).
    OUTPUT_VALIDATION = auto()
    STATE_ERROR = auto()
    RESOURCE_ERROR = auto()
    UNKNOWN = auto()


class ErrorSeverity(Enum):
    """Severity levels determining escalation and alerting."""
    LOW = auto()      # Log and continue
    MEDIUM = auto()   # Retry with backoff
    HIGH = auto()     # Circuit breaker consideration
    CRITICAL = auto() # Immediate escalation, potential service halt


class RecoveryStrategy(Enum):
    """Recommended recovery approach for each error type."""
    RETRY_IMMEDIATE = auto()
    RETRY_BACKOFF = auto()
    FALLBACK = auto()
    CIRCUIT_BREAK = auto()
    PROPAGATE = auto()
    DEAD_LETTER = auto()


@dataclass
class AgentError:
    """
    Comprehensive error representation for agent systems.
    
    This class captures not just the error itself, but the context
    needed for rule-based recovery decisions (mapping error categories
    and severities to specific recovery strategies).
    """
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    original_exception: Optional[Exception] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retry_count: int = 0
    context: Dict[str, Any] = field(default_factory=dict)
    trace_id: Optional[str] = None
    component: Optional[str] = None
    recovery_strategy: Optional[RecoveryStrategy] = None
    
    def __post_init__(self):
        if self.recovery_strategy is None:
            self.recovery_strategy = self._determine_recovery_strategy()
    
    def _determine_recovery_strategy(self) -> RecoveryStrategy:
        """
        Determine recovery strategy based on category and severity.

        This mapping encodes common patterns observed across production
        deployments. These are starting defaults, not universal truths -
        tune based on your system's failure modes. Consider A/B testing
        recovery strategies to validate effectiveness for your workload.

        Asymmetry worth noting between the two CRITICAL branches:
        LLM_ERROR-CRITICAL routes to CIRCUIT_BREAK because the LLM API is
        a recoverable upstream: opening a breaker diverts traffic to a
        fallback model or surfaces a clean degradation. TOOL_FAILURE-CRITICAL
        routes to DEAD_LETTER because a hard tool failure usually means a
        side-effecting call we cannot safely retry without inspecting why
        it failed; the operator gets a record to investigate rather than
        an automated retry storm.
        """
        strategy_map = {
            (ErrorCategory.LLM_ERROR, ErrorSeverity.LOW): RecoveryStrategy.RETRY_IMMEDIATE,
            (ErrorCategory.LLM_ERROR, ErrorSeverity.MEDIUM): RecoveryStrategy.RETRY_BACKOFF,
            (ErrorCategory.LLM_ERROR, ErrorSeverity.HIGH): RecoveryStrategy.FALLBACK,
            (ErrorCategory.LLM_ERROR, ErrorSeverity.CRITICAL): RecoveryStrategy.CIRCUIT_BREAK,
            (ErrorCategory.TOOL_FAILURE, ErrorSeverity.LOW): RecoveryStrategy.RETRY_IMMEDIATE,
            (ErrorCategory.TOOL_FAILURE, ErrorSeverity.MEDIUM): RecoveryStrategy.RETRY_BACKOFF,
            (ErrorCategory.TOOL_FAILURE, ErrorSeverity.HIGH): RecoveryStrategy.FALLBACK,
            (ErrorCategory.TOOL_FAILURE, ErrorSeverity.CRITICAL): RecoveryStrategy.DEAD_LETTER,
            (ErrorCategory.TIMEOUT, ErrorSeverity.LOW): RecoveryStrategy.RETRY_IMMEDIATE,
            (ErrorCategory.TIMEOUT, ErrorSeverity.MEDIUM): RecoveryStrategy.RETRY_BACKOFF,
            (ErrorCategory.TIMEOUT, ErrorSeverity.HIGH): RecoveryStrategy.FALLBACK,
            (ErrorCategory.TIMEOUT, ErrorSeverity.CRITICAL): RecoveryStrategy.PROPAGATE,
            (ErrorCategory.VALIDATION, ErrorSeverity.LOW): RecoveryStrategy.RETRY_IMMEDIATE,
            (ErrorCategory.VALIDATION, ErrorSeverity.MEDIUM): RecoveryStrategy.PROPAGATE,
            (ErrorCategory.VALIDATION, ErrorSeverity.HIGH): RecoveryStrategy.DEAD_LETTER,
            (ErrorCategory.VALIDATION, ErrorSeverity.CRITICAL): RecoveryStrategy.DEAD_LETTER,
        }
        return strategy_map.get(
            (self.category, self.severity),
            RecoveryStrategy.PROPAGATE
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for logging and monitoring systems."""
        return {
            "category": self.category.name,
            "severity": self.severity.name,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "retry_count": self.retry_count,
            "context": self.context,
            "trace_id": self.trace_id,
            "component": self.component,
            "recovery_strategy": self.recovery_strategy.name if self.recovery_strategy else None,
            # Use the single-argument form available since Python 3.10;
            # the 3-arg form is deprecated.
            "stack_trace": traceback.format_exception(self.original_exception)
            if self.original_exception
            else None,
        }


class ErrorClassifier:
    """
    Classifies raw exceptions into structured AgentError instances.
    
    This classifier uses pattern matching on exception types and messages
    to determine the appropriate category and severity. Production systems
    should extend this with domain-specific patterns.
    """
    
    def __init__(self):
        self._patterns: Dict[Type[Exception], tuple[ErrorCategory, ErrorSeverity]] = {
            TimeoutError: (ErrorCategory.TIMEOUT, ErrorSeverity.MEDIUM),
            ConnectionError: (ErrorCategory.TOOL_FAILURE, ErrorSeverity.MEDIUM),
            MemoryError: (ErrorCategory.RESOURCE_ERROR, ErrorSeverity.CRITICAL),
            ValueError: (ErrorCategory.VALIDATION, ErrorSeverity.LOW),
            TypeError: (ErrorCategory.VALIDATION, ErrorSeverity.LOW),
        }
        
        # Message patterns for finer-grained classification
        self._message_patterns = [
            ("rate limit", ErrorCategory.LLM_ERROR, ErrorSeverity.MEDIUM),
            ("context length", ErrorCategory.LLM_ERROR, ErrorSeverity.HIGH),
            ("content filter", ErrorCategory.LLM_ERROR, ErrorSeverity.HIGH),
            ("invalid api key", ErrorCategory.TOOL_FAILURE, ErrorSeverity.CRITICAL),
            ("connection refused", ErrorCategory.TOOL_FAILURE, ErrorSeverity.HIGH),
            ("out of memory", ErrorCategory.RESOURCE_ERROR, ErrorSeverity.CRITICAL),
        ]
    
    def classify(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        trace_id: Optional[str] = None
    ) -> AgentError:
        """
        Classify an exception into an AgentError with full context.
        
        Args:
            exception: The raw exception to classify
            context: Additional context about the operation
            component: The component that raised the error
            trace_id: Distributed tracing identifier
            
        Returns:
            Structured AgentError with classification and recovery strategy
        """
        category = ErrorCategory.UNKNOWN
        severity = ErrorSeverity.MEDIUM
        
        # Check exception type first
        for exc_type, (cat, sev) in self._patterns.items():
            if isinstance(exception, exc_type):
                category = cat
                severity = sev
                break
        
        # Refine based on message patterns
        message_lower = str(exception).lower()
        for pattern, cat, sev in self._message_patterns:
            if pattern in message_lower:
                category = cat
                severity = sev
                break
        
        return AgentError(
            category=category,
            severity=severity,
            message=str(exception),
            original_exception=exception,
            context=context or {},
            component=component,
            trace_id=trace_id
        )

# ============================================================================
# Block 2 (chapter listing #2)
# ============================================================================

import asyncio
import atexit
import contextvars
import random
import time
import threading
from concurrent.futures import (
    Executor,
    ThreadPoolExecutor,
    TimeoutError as FutureTimeoutError,
)
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, ClassVar, Optional, Set, TypeVar, Generic, Awaitable
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# Placeholder for the LLM client used by the @with_retry-decorated example
# functions (generate_response, get_product_recommendation). Replace with
# your actual client instance (e.g., an anthropic.AsyncAnthropic() or
# openai.AsyncOpenAI() handle) in your application before calling them.
from _optional import _RequiredDependency
llm_client = _RequiredDependency(
    "llm_client",
    "Provide an Anthropic/OpenAI client before running these examples."
)

T = TypeVar('T')


class BackoffStrategy(ABC):
    """Abstract base for backoff calculation strategies."""
    
    @abstractmethod
    def calculate_delay(self, attempt: int, base_delay: float) -> float:
        """Calculate delay for the given attempt number."""
        pass


class ExponentialBackoff(BackoffStrategy):
    """
    Exponential backoff with optional jitter.
    
    Jitter prevents thundering herd problems when many clients
    retry simultaneously after a shared failure.
    """
    
    def __init__(
        self,
        multiplier: float = 2.0,
        max_delay: float = 60.0,
        jitter: bool = True,
        jitter_factor: float = 0.1,
        min_delay: float = 0.05,
    ):
        if multiplier <= 0:
            raise ValueError("multiplier must be positive")
        if max_delay <= 0:
            raise ValueError("max_delay must be positive")
        if not 0 <= jitter_factor < 1:
            raise ValueError("jitter_factor must be in [0, 1)")
        if min_delay < 0:
            raise ValueError("min_delay must be non-negative")
        self.multiplier = multiplier
        self.max_delay = max_delay
        self.jitter = jitter
        self.jitter_factor = jitter_factor
        self.min_delay = min_delay
    
    def calculate_delay(self, attempt: int, base_delay: float) -> float:
        if attempt < 0:
            raise ValueError("attempt must be non-negative")
        if base_delay <= 0:
            raise ValueError("base_delay must be positive")

        # Bounded full jitter: preserve random spreading while keeping a small
        # non-zero floor so a retry loop cannot spin immediately on delay=0.
        cap = min(base_delay * (self.multiplier ** attempt), self.max_delay)
        if self.jitter:
            floor = min(cap, max(self.min_delay, cap * self.jitter_factor))
            return random.uniform(floor, cap)
        return cap


class LinearBackoff(BackoffStrategy):
    """Linear backoff for predictable delay increases."""
    
    def __init__(self, increment: float = 1.0, max_delay: float = 30.0):
        self.increment = increment
        self.max_delay = max_delay
    
    def calculate_delay(self, attempt: int, base_delay: float) -> float:
        return min(base_delay + (self.increment * attempt), self.max_delay)


class DecorrelatedJitter(BackoffStrategy):
    """
    AWS-recommended decorrelated jitter algorithm.

    This strategy provides better distribution of retry attempts
    compared to standard jittered exponential backoff, reducing
    the likelihood of synchronized retries across multiple clients.

    Previous-delay state is held in a ContextVar for thread/task isolation
    and reset when a new retry sequence starts at attempt 0.
    """

    def __init__(self, max_delay: float = 60.0):
        self.max_delay = max_delay
        # ContextVar gives per-coroutine and per-thread isolation, so a
        # single DecorrelatedJitter instance can be shared across a
        # RetryPolicy used by many concurrent sequences.
        self._previous_delay: contextvars.ContextVar[Optional[float]] = (
            contextvars.ContextVar(
                f"_decorrelated_jitter_prev_{id(self)}",
                default=None,
            )
        )

    def calculate_delay(self, attempt: int, base_delay: float) -> float:
        prev = None if attempt <= 0 else self._previous_delay.get()
        if prev is None:
            prev = base_delay

        delay = random.uniform(base_delay, prev * 3)
        delay = min(delay, self.max_delay)
        self._previous_delay.set(delay)
        return delay


class SyncAttemptStillRunningError(TimeoutError):
    """Raised when a timed-out sync attempt cannot be confirmed stopped."""


@dataclass
class RetryPolicy:
    """
    Configurable retry policy for agent operations.
    
    This class encapsulates all retry behavior configuration and
    provides both sync and async execution wrappers.
    """
    max_retries: int = 3
    base_delay: float = 1.0
    backoff_strategy: BackoffStrategy = field(
        default_factory=lambda: ExponentialBackoff()
    )
    retryable_categories: Set[ErrorCategory] = field(
        default_factory=lambda: {
            ErrorCategory.LLM_ERROR,
            ErrorCategory.TOOL_FAILURE,
            ErrorCategory.TIMEOUT
        }
    )
    retryable_severities: Set[ErrorSeverity] = field(
        default_factory=lambda: {
            ErrorSeverity.LOW,
            ErrorSeverity.MEDIUM
        }
    )
    on_retry: Optional[Callable[[AgentError, int], None]] = None
    error_classifier: ErrorClassifier = field(
        default_factory=ErrorClassifier
    )
    retry_budget: Optional["RetryBudget"] = None
    attempt_timeout: Optional[float] = None
    sync_timeout_executor: Optional[Executor] = None

    # Shared lazy default executor used when ``attempt_timeout`` is set
    # but no ``sync_timeout_executor`` is supplied. ClassVar keeps the
    # dataclass from treating these as fields.
    _default_executor: ClassVar[Optional[ThreadPoolExecutor]] = None
    _default_executor_warned: ClassVar[bool] = False

    def _get_default_executor(self) -> ThreadPoolExecutor:
        """Return a small process-wide default executor, lazy-built.

        We warn once so the operator notices that a production deployment is
        running on an implicit pool whose size we did not size for them.
        """
        cls = type(self)
        if cls._default_executor is None:
            cls._default_executor = ThreadPoolExecutor(
                max_workers=4,
                thread_name_prefix="retry-policy-default",
            )
            atexit.register(
                cls._default_executor.shutdown,
                wait=False,
                cancel_futures=True,
            )
        if not cls._default_executor_warned:
            logger.warning(
                "RetryPolicy.execute_sync called with attempt_timeout set "
                "but no sync_timeout_executor; lazy-allocated a default "
                "pool. Pass an explicit executor for production deployments."
            )
            cls._default_executor_warned = True
        return cls._default_executor

    def should_retry(self, error: AgentError, attempt: int) -> bool:
        """
        Determine if an error should trigger a retry.
        
        This method encodes the core retry logic: we retry if we
        haven't exceeded max retries, the error category is retryable,
        and the severity permits retry attempts.
        """
        if attempt >= self.max_retries:
            return False
        if error.category not in self.retryable_categories:
            return False
        if error.severity not in self.retryable_severities:
            return False
        return True
    
    def get_delay(self, attempt: int) -> float:
        """Calculate the delay before the next retry attempt."""
        return self.backoff_strategy.calculate_delay(attempt, self.base_delay)
    
    async def execute_async(
        self,
        operation: Callable[[], Awaitable[T]],
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None
    ) -> T:
        """
        Execute an async operation with retry logic.
        
        Args:
            operation: Async callable to execute
            context: Context for error classification
            component: Component name for error tracking
            
        Returns:
            Result of the operation
            
        Raises:
            AgentError: If all retries exhausted or non-retryable error
        """
        last_error: Optional[AgentError] = None
        if self.retry_budget:
            self.retry_budget.record_call()
        
        for attempt in range(self.max_retries + 1):
            try:
                if self.attempt_timeout is None:
                    return await operation()
                return await asyncio.wait_for(
                    operation(),
                    timeout=self.attempt_timeout
                )
            except Exception as e:
                agent_error = self.error_classifier.classify(
                    e, context=context, component=component
                )
                agent_error.retry_count = attempt
                last_error = agent_error
                
                if not self.should_retry(agent_error, attempt):
                    logger.warning(
                        f"Non-retryable error in {component}: {agent_error.message}",
                        extra={"error": agent_error.to_dict()}
                    )
                    # Re-raise the in-flight exception so the original
                    # traceback is preserved. Re-raising `original_exception
                    # from e` would self-reference (e IS that exception) and
                    # build a malformed __cause__ chain.
                    raise

                if self.retry_budget and not self.retry_budget.can_retry():
                    logger.warning(
                        f"Retry budget exhausted for {component}; "
                        "surfacing original failure.",
                        extra={"error": agent_error.to_dict()}
                    )
                    raise
                
                delay = self.get_delay(attempt)
                logger.info(
                    f"Retry {attempt + 1}/{self.max_retries} for {component} "
                    f"after {delay:.2f}s: {agent_error.message}"
                )
                
                if self.on_retry:
                    self.on_retry(agent_error, attempt)

                if self.retry_budget:
                    self.retry_budget.record_retry()
                
                await asyncio.sleep(delay)
        
        # All retries exhausted
        if last_error:
            if last_error.original_exception is not None:
                raise last_error.original_exception
            raise RuntimeError(f"Retries exhausted: {last_error.message}")
        raise RuntimeError("Unexpected retry loop termination")
    
    def execute_sync(
        self,
        operation: Callable[[], T],
        context: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None
    ) -> T:
        """Synchronous version of execute_async."""
        last_error: Optional[AgentError] = None
        if self.retry_budget:
            self.retry_budget.record_call()
        
        for attempt in range(self.max_retries + 1):
            try:
                return self._run_sync_attempt(operation)
            except SyncAttemptStillRunningError:
                raise
            except Exception as e:
                agent_error = self.error_classifier.classify(
                    e, context=context, component=component
                )
                agent_error.retry_count = attempt
                last_error = agent_error

                if not self.should_retry(agent_error, attempt):
                    raise

                if self.retry_budget and not self.retry_budget.can_retry():
                    logger.warning(
                        f"Retry budget exhausted for {component}; "
                        "surfacing original failure.",
                        extra={"error": agent_error.to_dict()}
                    )
                    raise
                
                delay = self.get_delay(attempt)
                logger.info(
                    f"Retry {attempt + 1}/{self.max_retries} after {delay:.2f}s"
                )

                if self.on_retry:
                    self.on_retry(agent_error, attempt)

                if self.retry_budget:
                    self.retry_budget.record_retry()
                
                time.sleep(delay)
        
        if last_error:
            if last_error.original_exception is not None:
                raise last_error.original_exception
            raise RuntimeError(f"Retries exhausted: {last_error.message}")
        raise RuntimeError("Unexpected retry loop termination")

    def _run_sync_attempt(self, operation: Callable[[], T]) -> T:
        """Run one sync attempt, optionally bounding caller wait time.

        Python cannot safely interrupt arbitrary blocking synchronous code.
        When ``attempt_timeout`` is set, callers must supply an executor. The
        timeout bounds how long this retry loop waits for the result; if the
        callable is already running in a worker thread, cancellation may not
        stop that underlying work.
        """
        if self.attempt_timeout is None:
            return operation()

        executor = self.sync_timeout_executor or self._get_default_executor()
        future = executor.submit(operation)
        try:
            return future.result(timeout=self.attempt_timeout)
        except FutureTimeoutError as e:
            cancelled = future.cancel()
            message = (
                f"Sync operation exceeded per-attempt timeout "
                f"of {self.attempt_timeout:.3f}s"
            )
            if not cancelled:
                # Log the orphaned future's identity so operators can
                # correlate this wedge with later cleanup or thread dumps;
                # id() is sufficient for in-process correlation.
                logger.warning(
                    "Sync retry attempt timed out with uncancelable future "
                    "future_id=%d timeout=%.3fs",
                    id(future),
                    self.attempt_timeout,
                )
                raise SyncAttemptStillRunningError(
                    f"{message}; underlying work is still running, so retrying "
                    "could duplicate non-idempotent side effects"
                ) from e
            raise TimeoutError(message) from e


def with_retry(
    policy: Optional[RetryPolicy] = None,
    **policy_kwargs
) -> Callable:
    """
    Decorator for applying retry policy to functions.
    
    Can be used with a pre-configured policy or with kwargs
    to create a new policy.
    
    Example:
        @with_retry(max_retries=5, base_delay=2.0)
        async def call_llm(prompt: str) -> str:
            ...
    """
    if policy is None:
        policy = RetryPolicy(**policy_kwargs)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await policy.execute_async(
                lambda: func(*args, **kwargs),
                component=func.__name__
            )
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return policy.execute_sync(
                lambda: func(*args, **kwargs),
                component=func.__name__
            )
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator

# ============================================================================
# Block 3 (chapter listing #3)
# ============================================================================

# Wrapped in an ``if __name__ == "__main__":`` guard (same pattern Block 15
# uses) because ``generate_response`` calls ``llm_client.complete`` on the
# module-top placeholder ``llm_client = None``; real applications must
# supply a client. Keeping the policy + decorated example inside the guard
# lets ``import error_handling`` succeed in test/import contexts that don't
# provide a real client.
if __name__ == "__main__":
    # Example: Configuring different policies for different error types

    llm_retry_policy = RetryPolicy(
        max_retries=5,
        base_delay=1.0,
        backoff_strategy=DecorrelatedJitter(max_delay=30.0),
        retryable_categories={ErrorCategory.LLM_ERROR, ErrorCategory.TIMEOUT}
    )

    tool_retry_policy = RetryPolicy(
        max_retries=3,
        base_delay=0.5,
        backoff_strategy=ExponentialBackoff(multiplier=2.0, max_delay=10.0),
        retryable_categories={ErrorCategory.TOOL_FAILURE}
    )

    @with_retry(policy=llm_retry_policy)
    async def generate_response(prompt: str) -> str:
        return await llm_client.complete(prompt)


# Block 3b: RetryBudget primitive (gRPC-style retry-storm guard).
# Shared across all RetryPolicy instances targeting the same downstream
# dependency. See chapter section "Bounding Retries Globally: The Retry
# Budget" for the motivation.
from collections import deque
import time as _time
import threading as _threading


@dataclass
class RetryBudget:
    """Rolling-window guard that caps the fraction of recent calls that
    may be retries. When the budget is exhausted, retries are suppressed
    and the caller surfaces the original failure instead of piling more
    load on a struggling downstream.
    """
    retry_ratio: float = 0.10
    window_seconds: float = 10.0
    min_calls_per_window: int = 10

    # Belt-and-suspenders: cap deque length to bound memory even if the
    # time-window eviction logic ever fails to keep up under bursty load.
    _calls: deque = field(default_factory=lambda: deque(maxlen=10_000))
    _retries: deque = field(default_factory=lambda: deque(maxlen=10_000))
    _lock: _threading.Lock = field(default_factory=_threading.Lock)

    def record_call(self) -> None:
        with self._lock:
            now = _time.monotonic()
            self._calls.append(now)
            self._evict(now)

    def can_retry(self) -> bool:
        with self._lock:
            now = _time.monotonic()
            self._evict(now)
            n_calls = len(self._calls)
            if n_calls < self.min_calls_per_window:
                return True
            return len(self._retries) < self.retry_ratio * n_calls

    def record_retry(self) -> None:
        with self._lock:
            now = _time.monotonic()
            self._retries.append(now)
            self._evict(now)

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._calls and self._calls[0] < cutoff:
            self._calls.popleft()
        while self._retries and self._retries[0] < cutoff:
            self._retries.popleft()

    def get_metrics(self) -> dict:
        with self._lock:
            n_calls = len(self._calls)
            n_retries = len(self._retries)
            ratio = n_retries / n_calls if n_calls else 0.0
            return {
                "calls_in_window": n_calls,
                "retries_in_window": n_retries,
                "retry_ratio": ratio,
                "budget_remaining": max(
                    0.0, self.retry_ratio * n_calls - n_retries
                ),
            }


# ============================================================================
# Block 4 (chapter listing #4)
# ============================================================================

import threading
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Callable, Optional, TypeVar, Generic, Awaitable, Any, Dict
from datetime import datetime, timedelta, timezone
from collections import deque
import asyncio
import math

T = TypeVar('T')


class CircuitState(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 2  # Successes in half-open to close
    timeout: timedelta = field(default_factory=lambda: timedelta(seconds=30))
    half_open_max_calls: int = 3  # Max concurrent calls in half-open
    failure_rate_threshold: float = 0.5  # Alternative: failure rate trigger
    minimum_calls: int = 10  # Minimum calls before rate calculation
    sliding_window_size: int = 100  # Max calls retained for measurement
    sliding_window_duration: Optional[timedelta] = None  # Optional time window
    latency_threshold: Optional[timedelta] = None  # Optional percentile trigger
    latency_percentile: float = 0.99

    def __post_init__(self) -> None:
        if self.failure_threshold <= 0:
            raise ValueError("failure_threshold must be positive")
        if self.success_threshold <= 0:
            raise ValueError("success_threshold must be positive")
        if self.half_open_max_calls <= 0:
            raise ValueError("half_open_max_calls must be positive")
        if self.minimum_calls <= 0:
            raise ValueError("minimum_calls must be positive")
        if self.sliding_window_size <= 0:
            raise ValueError("sliding_window_size must be positive")
        if not 0 < self.failure_rate_threshold <= 1:
            raise ValueError("failure_rate_threshold must be in (0, 1]")
        if (
            self.sliding_window_duration is not None
            and self.sliding_window_duration <= timedelta(0)
        ):
            raise ValueError("sliding_window_duration must be positive")
        if (
            self.latency_threshold is not None
            and self.latency_threshold <= timedelta(0)
        ):
            raise ValueError("latency_threshold must be positive")
        if not 0 < self.latency_percentile <= 1:
            raise ValueError("latency_percentile must be in (0, 1]")


class CircuitBreakerError(Exception):
    """Raised when circuit is open and request is rejected."""
    
    def __init__(self, circuit_name: str, time_until_retry: timedelta):
        self.circuit_name = circuit_name
        self.time_until_retry = time_until_retry
        super().__init__(
            f"Circuit '{circuit_name}' is open. "
            f"Retry after {time_until_retry.total_seconds():.1f}s"
        )


@dataclass
class CallResult:
    """Record of a single call through the circuit breaker."""
    timestamp: datetime
    success: bool
    duration: timedelta
    error: Optional[Exception] = None


class CircuitBreaker(Generic[T]):
    """
    Production-ready circuit breaker with sliding window metrics.
    
    This implementation supports count-based, rate-based, and
    percentile-latency failure detection over a count window, an optional
    time window, or both. It also provides thread-safe state transitions
    and comprehensive metrics for monitoring.
    """
    
    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
        on_state_change: Optional[Callable[[CircuitState, CircuitState], None]] = None,
        on_rejected: Optional[Callable[[], None]] = None
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.on_state_change = on_state_change
        self.on_rejected = on_rejected
        
        self._state = CircuitState.CLOSED
        self._state_lock = threading.RLock()
        self._last_failure_time: Optional[datetime] = None
        self._last_failure_monotonic: Optional[float] = None
        self._half_open_calls = 0
        self._half_open_successes = 0
        self._half_open_generation = 0
        
        # Sliding window for metrics
        self._call_history: deque[CallResult] = deque(
            maxlen=self.config.sliding_window_size
        )
        
        # Metrics
        self._total_calls = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejections = 0
    
    @property
    def state(self) -> CircuitState:
        """Current circuit state with automatic timeout handling."""
        with self._state_lock:
            if self._state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to(CircuitState.HALF_OPEN)
            return self._state
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self._last_failure_monotonic is None:
            return True
        elapsed = _time.monotonic() - self._last_failure_monotonic
        return elapsed >= self.config.timeout.total_seconds()
    
    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state with callback notification."""
        old_state = self._state
        self._state = new_state
        
        if new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0
            self._half_open_successes = 0
            self._half_open_generation += 1
        
        logger.info(
            f"Circuit '{self.name}' transitioned from {old_state.name} "
            f"to {new_state.name}"
        )
        
        if self.on_state_change:
            self.on_state_change(old_state, new_state)
    
    def _record_success(
        self,
        duration: timedelta,
        half_open_generation: Optional[int] = None
    ) -> None:
        """Record a successful call and potentially close circuit."""
        with self._state_lock:
            self._total_successes += 1
            now = datetime.now(timezone.utc)
            self._call_history.append(CallResult(
                timestamp=now,
                success=True,
                duration=duration
            ))
            
            if (
                half_open_generation is not None
                and self._state == CircuitState.HALF_OPEN
                and self._half_open_generation == half_open_generation
            ):
                # Release the half-open slot we acquired in _can_execute()
                # so other probes can proceed; without this the breaker
                # wedges once half_open_max_calls is reached.
                self._half_open_calls = max(0, self._half_open_calls - 1)
                self._half_open_successes += 1
                if self._half_open_successes >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)
            elif (
                self._state == CircuitState.CLOSED
                and self.config.latency_threshold is not None
                and self._should_open()
            ):
                self._last_failure_time = now
                self._last_failure_monotonic = _time.monotonic()
                self._transition_to(CircuitState.OPEN)
    
    def _record_failure(
        self,
        error: Exception,
        duration: timedelta,
        half_open_generation: Optional[int] = None
    ) -> None:
        """Record a failure and potentially open circuit."""
        with self._state_lock:
            self._total_failures += 1
            now = datetime.now(timezone.utc)
            self._last_failure_time = now
            self._last_failure_monotonic = _time.monotonic()
            self._call_history.append(CallResult(
                timestamp=now,
                success=False,
                duration=duration,
                error=error
            ))
            
            if (
                half_open_generation is not None
                and self._state == CircuitState.HALF_OPEN
                and self._half_open_generation == half_open_generation
            ):
                # Release the half-open slot before transitioning so the
                # counter is consistent if state changes again.
                self._half_open_calls = max(0, self._half_open_calls - 1)
                self._transition_to(CircuitState.OPEN)
            elif (
                half_open_generation is None
                and self._state == CircuitState.HALF_OPEN
            ):
                self._half_open_calls = max(0, self._half_open_calls - 1)
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._should_open():
                    self._transition_to(CircuitState.OPEN)

    def record_failure(
        self,
        error: Exception,
        duration: Optional[timedelta] = None
    ) -> None:
        """Record a failure observed by an outer timeout/deadline wrapper."""
        self._record_failure(error, duration or timedelta(0))

    def _windowed_history(
        self,
        now: Optional[datetime] = None
    ) -> list[CallResult]:
        """Return calls inside the configured count and optional time window."""
        calls = list(self._call_history)
        if self.config.sliding_window_duration is None:
            return calls

        now = now or datetime.now(timezone.utc)
        cutoff = now - self.config.sliding_window_duration
        return [call for call in calls if call.timestamp >= cutoff]

    def _duration_at_percentile(
        self,
        calls: list[CallResult],
        percentile: float
    ) -> Optional[timedelta]:
        """Nearest-rank percentile over recorded call durations."""
        if not calls:
            return None

        durations = sorted(call.duration for call in calls)
        rank = max(1, math.ceil(percentile * len(durations))) - 1
        return durations[min(rank, len(durations) - 1)]
    
    def _should_open(self) -> bool:
        """Determine if circuit should open based on failure metrics."""
        calls = self._windowed_history()
        if not calls:
            return False

        # Count-based threshold
        recent_failures = sum(1 for call in calls if not call.success)
        if recent_failures >= self.config.failure_threshold:
            return True
        
        # Rate- and latency-based thresholds need enough samples.
        if len(calls) >= self.config.minimum_calls:
            failure_rate = recent_failures / len(calls)
            if failure_rate >= self.config.failure_rate_threshold:
                return True

            if self.config.latency_threshold is not None:
                percentile_duration = self._duration_at_percentile(
                    calls,
                    self.config.latency_percentile
                )
                if (
                    percentile_duration is not None
                    and percentile_duration > self.config.latency_threshold
                ):
                    return True
        
        return False
    
    def _acquire_execution_slot(self) -> tuple[bool, Optional[int]]:
        """Return whether a call can run and the half-open generation it used."""
        with self._state_lock:
            current_state = self.state  # This may trigger state transition
            
            if current_state == CircuitState.CLOSED:
                return True, None
            elif current_state == CircuitState.OPEN:
                return False, None
            else:  # HALF_OPEN
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True, self._half_open_generation
                return False, None

    def _can_execute(self) -> bool:
        """Check if a call can be executed given current state."""
        can_execute, _ = self._acquire_execution_slot()
        return can_execute

    def _release_half_open_slot(self, half_open_generation: int) -> None:
        """Release a half-open slot when a probe exits without a result."""
        with self._state_lock:
            if (
                self._state == CircuitState.HALF_OPEN
                and self._half_open_generation == half_open_generation
            ):
                self._half_open_calls = max(0, self._half_open_calls - 1)
    
    async def execute_async(
        self,
        operation: Callable[[], Awaitable[T]],
        fallback: Optional[Callable[[], Awaitable[T]]] = None
    ) -> T:
        """
        Execute an async operation through the circuit breaker.
        
        Args:
            operation: The async operation to execute
            fallback: Optional fallback if circuit is open
            
        Returns:
            Result of operation or fallback
            
        Raises:
            CircuitBreakerError: If circuit is open and no fallback provided
        """
        self._total_calls += 1
        
        can_execute, half_open_generation = self._acquire_execution_slot()
        if not can_execute:
            self._total_rejections += 1
            if self.on_rejected:
                self.on_rejected()
            
            if fallback:
                return await fallback()
            
            elapsed = (
                _time.monotonic() - self._last_failure_monotonic
                if self._last_failure_monotonic is not None else 0.0
            )
            time_until_retry = self.config.timeout - timedelta(seconds=elapsed)
            raise CircuitBreakerError(self.name, time_until_retry)
        
        start_time = _time.monotonic()
        try:
            result = await operation()
            self._record_success(
                timedelta(seconds=_time.monotonic() - start_time),
                half_open_generation
            )
            return result
        except asyncio.CancelledError:
            if half_open_generation is not None:
                self._release_half_open_slot(half_open_generation)
            raise
        except Exception as e:
            self._record_failure(
                e,
                timedelta(seconds=_time.monotonic() - start_time),
                half_open_generation
            )
            raise
        except BaseException:
            if half_open_generation is not None:
                self._release_half_open_slot(half_open_generation)
            raise
    
    def execute_sync(
        self,
        operation: Callable[[], T],
        fallback: Optional[Callable[[], T]] = None
    ) -> T:
        """Synchronous version of execute_async."""
        self._total_calls += 1
        
        can_execute, half_open_generation = self._acquire_execution_slot()
        if not can_execute:
            self._total_rejections += 1
            if self.on_rejected:
                self.on_rejected()
            
            if fallback:
                return fallback()
            
            elapsed = (
                _time.monotonic() - self._last_failure_monotonic
                if self._last_failure_monotonic is not None else 0.0
            )
            time_until_retry = self.config.timeout - timedelta(seconds=elapsed)
            raise CircuitBreakerError(self.name, time_until_retry)
        
        start_time = _time.monotonic()
        try:
            result = operation()
            self._record_success(
                timedelta(seconds=_time.monotonic() - start_time),
                half_open_generation
            )
            return result
        except Exception as e:
            self._record_failure(
                e,
                timedelta(seconds=_time.monotonic() - start_time),
                half_open_generation
            )
            raise
        except BaseException:
            if half_open_generation is not None:
                self._release_half_open_slot(half_open_generation)
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current circuit breaker metrics for monitoring."""
        with self._state_lock:
            recent_calls = self._windowed_history(datetime.now(timezone.utc))
            recent_failures = sum(1 for c in recent_calls if not c.success)
            latency_percentile = self._duration_at_percentile(
                recent_calls,
                self.config.latency_percentile
            )
            
            return {
                "name": self.name,
                "state": self._state.name,
                "total_calls": self._total_calls,
                "total_successes": self._total_successes,
                "total_failures": self._total_failures,
                "total_rejections": self._total_rejections,
                "window_calls": len(recent_calls),
                "recent_failure_rate": (
                    recent_failures / len(recent_calls)
                    if recent_calls else 0
                ),
                "latency_percentile": self.config.latency_percentile,
                "latency_percentile_seconds": (
                    latency_percentile.total_seconds()
                    if latency_percentile is not None else None
                ),
                "last_failure_time": (
                    self._last_failure_time.isoformat()
                    if self._last_failure_time else None
                )
            }

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

class CircuitBreakerRegistry:
    """
    Centralized registry for managing multiple circuit breakers.

    Provides aggregated metrics and health status for monitoring dashboards.

    The registry caps the number of tracked breakers at ``max_breakers`` and
    evicts the least-recently-used entry when the cap is reached. This keeps
    long-running processes that mint breakers per request key (e.g., per
    tenant or per upstream endpoint) from leaking memory unbounded. The
    first eviction logs a warning so operators notice the cardinality cap.
    """

    _instance: Optional['CircuitBreakerRegistry'] = None
    _lock = threading.Lock()

    def __new__(cls, max_breakers: int = 1024):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    from collections import OrderedDict
                    cls._instance._breakers: "OrderedDict[str, CircuitBreaker]" = OrderedDict()
                    cls._instance._max_breakers = max_breakers
                    cls._instance._eviction_warned = False
        return cls._instance

    def register(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Register a new circuit breaker or return existing one."""
        with self._lock:
            if name in self._breakers:
                # Touch existing entry to refresh LRU order.
                self._breakers.move_to_end(name)
                return self._breakers[name]

            if len(self._breakers) >= self._max_breakers:
                evicted_name, _ = self._breakers.popitem(last=False)
                if not self._eviction_warned:
                    logger.warning(
                        "CircuitBreakerRegistry hit max_breakers=%d; evicting "
                        "least-recently-used breaker %r. Further evictions "
                        "will be silent. Consider raising max_breakers or "
                        "reducing breaker-name cardinality.",
                        self._max_breakers,
                        evicted_name,
                    )
                    self._eviction_warned = True

            self._breakers[name] = CircuitBreaker(name, config)
            return self._breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get a circuit breaker by name."""
        breaker = self._breakers.get(name)
        if breaker is not None:
            # Reads also count as use for LRU purposes.
            with self._lock:
                if name in self._breakers:
                    self._breakers.move_to_end(name)
        return breaker
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all registered circuit breakers."""
        return {
            name: breaker.get_metrics()
            for name, breaker in self._breakers.items()
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status of all circuits."""
        total = len(self._breakers)
        open_circuits = sum(
            1 for b in self._breakers.values()
            if b.state == CircuitState.OPEN
        )
        half_open = sum(
            1 for b in self._breakers.values()
            if b.state == CircuitState.HALF_OPEN
        )
        
        return {
            "total_circuits": total,
            "closed": total - open_circuits - half_open,
            "open": open_circuits,
            "half_open": half_open,
            "healthy": open_circuits == 0,
            "circuits": {
                name: breaker.state.name
                for name, breaker in self._breakers.items()
            }
        }

# ============================================================================
# Block 6 (chapter listing #6)
# ============================================================================

class FallbackError(Exception):
    """Raised by a fallback to signal that the next one should be tried."""
    pass


class NoFallbackSucceeded(FallbackError):
    """Raised when every configured fallback raised FallbackError."""
    pass


def call_primary_llm(req): ...
def call_secondary_llm(req): ...
def return_cached_answer(req): ...

def with_fallbacks(req, fallbacks):
    for fn in fallbacks:
        try:
            return fn(req)
        except FallbackError:
            continue
    raise NoFallbackSucceeded()

fallbacks = [call_primary_llm, call_secondary_llm, return_cached_answer]
if __name__ == "__main__":
    # Placeholder request object; replace with a real request instance when
    # adapting this example for your own application.
    request = None
    result = with_fallbacks(request, fallbacks)

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, TypeVar, Generic, Callable, Awaitable, Any, Dict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import asyncio

T = TypeVar('T')


class FallbackProvider(ABC, Generic[T]):
    """Base class for fallback providers in the chain."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging and metrics."""
        pass
    
    @property
    @abstractmethod
    def priority(self) -> int:
        """Lower numbers = higher priority."""
        pass
    
    @abstractmethod
    async def execute(self, request: Any) -> T:
        """Execute the request and return result."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is currently available."""
        pass


@dataclass
class LLMProvider(FallbackProvider[str]):
    """LLM-based fallback provider."""
    
    provider_name: str
    model: str
    client: Any  # Would be actual LLM client
    _priority: int = 0
    circuit_breaker: Optional[CircuitBreaker] = None
    
    @property
    def name(self) -> str:
        return f"{self.provider_name}/{self.model}"
    
    @property
    def priority(self) -> int:
        return self._priority
    
    async def execute(self, request: Dict[str, Any]) -> str:
        async def _call():
            # Actual LLM call would go here
            return await self.client.complete(
                model=self.model,
                messages=request.get("messages", []),
                **request.get("parameters", {})
            )
        
        if self.circuit_breaker:
            return await self.circuit_breaker.execute_async(_call)
        return await _call()
    
    def is_available(self) -> bool:
        if self.circuit_breaker:
            return self.circuit_breaker.state != CircuitState.OPEN
        return True


@dataclass
class CachedResponseProvider(FallbackProvider[str]):
    """Provides responses from a semantic cache."""
    
    cache_client: Any  # Vector store client
    similarity_threshold: float = 0.85
    max_age: timedelta = field(default_factory=lambda: timedelta(hours=24))
    _priority: int = 100
    
    @property
    def name(self) -> str:
        return "semantic_cache"
    
    @property
    def priority(self) -> int:
        return self._priority
    
    async def execute(self, request: Dict[str, Any]) -> str:
        # Extract the user's query from the request
        query = self._extract_query(request)
        
        # Search for similar cached responses
        results = await self.cache_client.search(
            query=query,
            limit=1,
            filter={
                "timestamp": {
                    "$gte": (datetime.now(timezone.utc) - self.max_age).isoformat()
                }
            }
        )
        
        if results and results[0].score >= self.similarity_threshold:
            return results[0].response
        
        raise ValueError("No suitable cached response found")
    
    def _extract_query(self, request: Dict[str, Any]) -> str:
        messages = request.get("messages", [])
        user_messages = [m for m in messages if m.get("role") == "user"]
        if user_messages:
            return user_messages[-1].get("content", "")
        return ""
    
    def is_available(self) -> bool:
        return True  # Treated as available at this layer; underlying
                     # process failures are caught by health checks.


@dataclass
class StaticFallbackProvider(FallbackProvider[str]):
    """Provides static pre-written responses as last resort."""
    
    responses: Dict[str, str] = field(default_factory=dict)
    default_response: str = "I'm currently unable to process your request. Please try again later."
    _priority: int = 1000
    
    @property
    def name(self) -> str:
        return "static_fallback"
    
    @property
    def priority(self) -> int:
        return self._priority
    
    async def execute(self, request: Dict[str, Any]) -> str:
        # Try to match request to a category
        category = self._classify_request(request)
        return self.responses.get(category, self.default_response)
    
    def _classify_request(self, request: Dict[str, Any]) -> str:
        # Simple keyword-based classification
        query = self._extract_query(request).lower()
        
        category_keywords = {
            "help": ["help", "assist", "support"],
            "greeting": ["hello", "hi", "hey"],
            "thanks": ["thank", "appreciate"],
            "error": ["error", "problem", "issue"],
        }
        
        for category, keywords in category_keywords.items():
            if any(kw in query for kw in keywords):
                return category
        return "default"
    
    def _extract_query(self, request: Dict[str, Any]) -> str:
        messages = request.get("messages", [])
        user_messages = [m for m in messages if m.get("role") == "user"]
        if user_messages:
            return user_messages[-1].get("content", "")
        return ""
    
    def is_available(self) -> bool:
        return True  # Static fallback is always available


@dataclass
class FallbackResult(Generic[T]):
    """Result of a fallback chain execution."""
    value: T
    provider_used: str
    providers_tried: List[str]
    total_latency: timedelta
    degraded: bool  # True if not from primary provider


DEFAULT_PROVIDER_TIMEOUT_SECONDS = 5.0
_USE_DEFAULT_PROVIDER_TIMEOUT = object()


class FallbackChain(Generic[T]):
    """
    Executes requests through a chain of fallback providers.
    
    Providers are tried in priority order until one succeeds.
    Comprehensive metrics are collected for monitoring and optimization.
    Provider attempts use a bounded default timeout so a hung primary
    cannot stall the whole chain. Use provider_timeouts for known slow
    providers, and pass default_provider_timeout=None only with
    allow_unbounded_provider_waits=True when an unbounded wait is intended.
    """
    
    def __init__(
        self,
        providers: List[FallbackProvider[T]],
        on_fallback: Optional[Callable[[str, str, Exception], None]] = None,
        default_provider_timeout: Any = _USE_DEFAULT_PROVIDER_TIMEOUT,
        provider_timeouts: Optional[Dict[str, Optional[float]]] = None,
        allow_unbounded_provider_waits: bool = False
    ):
        # Sort by priority (lower = higher priority)
        self.providers = sorted(providers, key=lambda p: p.priority)
        self.on_fallback = on_fallback
        self.allow_unbounded_provider_waits = allow_unbounded_provider_waits
        if default_provider_timeout is _USE_DEFAULT_PROVIDER_TIMEOUT:
            default_provider_timeout = DEFAULT_PROVIDER_TIMEOUT_SECONDS
        self.default_provider_timeout = default_provider_timeout
        self.provider_timeouts = provider_timeouts or {}

        if (
            self.default_provider_timeout is None
            and not self.allow_unbounded_provider_waits
        ):
            raise ValueError(
                "default_provider_timeout=None disables provider deadlines; "
                "set allow_unbounded_provider_waits=True to opt in"
            )
        if (
            self.default_provider_timeout is not None
            and self.default_provider_timeout <= 0
        ):
            raise ValueError("default_provider_timeout must be positive")
        for provider_name, timeout in self.provider_timeouts.items():
            if timeout is None:
                if not self.allow_unbounded_provider_waits:
                    raise ValueError(
                        f"Timeout for provider {provider_name!r} disables "
                        "that provider deadline; set "
                        "allow_unbounded_provider_waits=True to opt in"
                    )
                continue
            if timeout <= 0:
                raise ValueError(
                    f"Timeout for provider {provider_name!r} must be positive"
                )
        
        # Metrics
        self._total_requests = 0
        self._provider_usage: Dict[str, int] = {p.name: 0 for p in providers}
        self._fallback_counts: Dict[str, int] = {p.name: 0 for p in providers}
        self._provider_timeout_counts: Dict[str, int] = {
            p.name: 0 for p in providers
        }
    
    async def execute(self, request: Any) -> FallbackResult[T]:
        """
        Execute request through the fallback chain.
        
        Tries each provider in priority order until one succeeds.
        Returns detailed result including which provider was used.
        """
        self._total_requests += 1
        start_time = datetime.now(timezone.utc)
        providers_tried = []
        last_error: Optional[Exception] = None
        
        available_providers = [p for p in self.providers if p.is_available()]
        
        for provider in available_providers:
            providers_tried.append(provider.name)
            
            try:
                result = await self._execute_provider(provider, request)
                self._provider_usage[provider.name] += 1
                
                return FallbackResult(
                    value=result,
                    provider_used=provider.name,
                    providers_tried=providers_tried,
                    total_latency=datetime.now(timezone.utc) - start_time,
                    degraded=provider != self.providers[0]
                )
            except Exception as e:
                last_error = e
                self._fallback_counts[provider.name] += 1
                
                logger.warning(
                    f"Provider {provider.name} failed: {e}",
                    extra={"provider": provider.name, "error": str(e)}
                )
                
                if self.on_fallback and len(providers_tried) > 1:
                    prev_provider = providers_tried[-2] if len(providers_tried) > 1 else "none"
                    self.on_fallback(prev_provider, provider.name, e)
        
        # All providers failed
        raise RuntimeError(
            f"All fallback providers exhausted. "
            f"Tried: {providers_tried}. "
            f"Last error: {last_error}"
        )

    async def _execute_provider(
        self,
        provider: FallbackProvider[T],
        request: Any
    ) -> T:
        """Execute one provider with its configured timeout."""
        timeout = self.provider_timeouts.get(
            provider.name,
            self.default_provider_timeout
        )
        if timeout is None:
            return await provider.execute(request)

        start_time = datetime.now(timezone.utc)
        task = asyncio.create_task(provider.execute(request))
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if task in done:
            return await task

        task.cancel()
        task.add_done_callback(self._consume_provider_task_result)
        duration = datetime.now(timezone.utc) - start_time
        timeout_error = TimeoutError(
            f"Provider {provider.name} exceeded timeout of {timeout:.3f}s"
        )
        self._provider_timeout_counts[provider.name] += 1
        self._record_provider_timeout(provider, timeout_error, duration)
        raise timeout_error

    @staticmethod
    def _consume_provider_task_result(task: asyncio.Task) -> None:
        """Consume cancelled provider task results to avoid unhandled warnings."""
        try:
            task.exception()
        except asyncio.CancelledError:
            pass

    def _record_provider_timeout(
        self,
        provider: FallbackProvider[T],
        error: TimeoutError,
        duration: timedelta
    ) -> None:
        """Feed outer timeout failures into provider-owned circuit breakers."""
        circuit_breaker = getattr(provider, "circuit_breaker", None)
        if circuit_breaker:
            circuit_breaker.record_failure(error, duration)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get fallback chain metrics for monitoring."""
        return {
            "total_requests": self._total_requests,
            "provider_usage": self._provider_usage,
            "fallback_counts": self._fallback_counts,
            "provider_timeout_counts": self._provider_timeout_counts,
            "primary_success_rate": (
                self._provider_usage.get(self.providers[0].name, 0) /
                self._total_requests
                if self._total_requests > 0 else 1.0
            ),
            "available_providers": [
                p.name for p in self.providers if p.is_available()
            ]
        }

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

# Wrapped in an ``if __name__ == "__main__":`` guard (same pattern Block 15
# uses) because the body references ``anthropic_client`` and ``vector_store``,
# collaborators that real applications must supply. Keeping the example
# inside the guard lets ``import error_handling`` succeed without forcing
# module-top placeholders for every demo collaborator.
if __name__ == "__main__":
    # Example: Setting up a production fallback chain for LLM calls

    async def create_production_fallback_chain() -> FallbackChain[str]:
        """Create an example fallback chain for LLM requests. Substitute your
        current model tier (PRIMARY_MODEL / SECONDARY_MODEL) at deployment time
        as Anthropic releases new generations; the structure below is what
        survives a model rename, not the specific identifiers."""

        # Adjust the literal model IDs below as the model family evolves.
        PRIMARY_MODEL = "claude-sonnet-4-6"   # higher quality, primary path
        SECONDARY_MODEL = "claude-haiku-4-5"  # faster, cheaper fallback

        registry = CircuitBreakerRegistry()

        # Primary: higher-quality model
        primary_circuit = registry.register(
            "llm_primary",
            CircuitBreakerConfig(
                failure_threshold=3,
                timeout=timedelta(seconds=30)
            )
        )

        # Secondary: faster, cheaper model
        secondary_circuit = registry.register(
            "llm_secondary",
            CircuitBreakerConfig(
                failure_threshold=5,
                timeout=timedelta(seconds=20)
            )
        )

        providers = [
            LLMProvider(
                provider_name="anthropic",
                model=PRIMARY_MODEL,
                client=anthropic_client,
                _priority=0,
                circuit_breaker=primary_circuit
            ),
            LLMProvider(
                provider_name="anthropic",
                model=SECONDARY_MODEL,
                client=anthropic_client,
                _priority=10,
                circuit_breaker=secondary_circuit
            ),
            CachedResponseProvider(
                cache_client=vector_store,
                similarity_threshold=0.9,
                _priority=100
            ),
            StaticFallbackProvider(
                responses={
                    "help": "I can help you with various tasks. Please describe what you need.",
                    "greeting": "Hello! How can I assist you today?",
                    "error": "I encountered an issue. Please try rephrasing your request.",
                },
                _priority=1000
            )
        ]
        
        return FallbackChain(
            providers=providers,
            default_provider_timeout=5.0,
            provider_timeouts={
                f"anthropic/{PRIMARY_MODEL}": 8.0,
                f"anthropic/{SECONDARY_MODEL}": 4.0,
                "semantic_cache": 1.0,
                "static_fallback": 0.25,
            },
            on_fallback=lambda prev, curr, err: logger.warning(
                f"Fallback from {prev} to {curr}: {err}"
            )
        )

# ============================================================================
# Block 9 (chapter block #9) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_9_listing = r"""
fallbacks = [call_primary_llm, call_secondary_llm, return_cached_answer]
for fn in fallbacks:
    try:
        return fn(request)
    except FallbackError:
        continue
raise NoFallbackSucceeded()
"""

# ============================================================================
# Block 10 (chapter listing #10)
# ============================================================================

from enum import IntEnum
from typing import Set, Callable


class DegradationLevel(IntEnum):
    """
    System degradation levels, from fully operational to minimal service.
    
    Each level represents a set of available capabilities.
    Higher numbers indicate more severe degradation.
    """
    FULL = 0          # All features available
    MINOR = 1         # Non-critical features disabled
    MODERATE = 2      # Some core features limited
    SIGNIFICANT = 3   # Only essential features available
    MINIMAL = 4       # Basic functionality only
    EMERGENCY = 5     # Read-only or status-only mode


@dataclass
class SystemCapability:
    """A capability that can be enabled or disabled based on degradation."""
    name: str
    minimum_level: DegradationLevel
    dependencies: Set[str] = field(default_factory=set)
    fallback_behavior: Optional[Callable] = None


class DegradationManager:
    """
    Manages system degradation state and capability availability.
    
    Provides a central point for determining what features are available
    and handling transitions between degradation levels.
    """
    
    def __init__(self):
        self._current_level = DegradationLevel.FULL
        self._capabilities: Dict[str, SystemCapability] = {}
        self._level_lock = threading.Lock()
        self._listeners: List[Callable[[DegradationLevel, DegradationLevel], None]] = []
    
    def register_capability(self, capability: SystemCapability) -> None:
        """Register a system capability."""
        previous = self._capabilities.get(capability.name)
        self._capabilities[capability.name] = capability
        try:
            cycle = self._find_dependency_cycle(capability.name)
        except Exception:
            if previous is None:
                self._capabilities.pop(capability.name, None)
            else:
                self._capabilities[capability.name] = previous
            raise

        if cycle:
            if previous is None:
                self._capabilities.pop(capability.name, None)
            else:
                self._capabilities[capability.name] = previous
            raise ValueError(
                "Capability dependency cycle detected: "
                + " -> ".join(cycle)
            )

    def _find_dependency_cycle(self, capability_name: str) -> Optional[List[str]]:
        """Return a dependency cycle path if one is reachable."""
        visited: Set[str] = set()
        stack: List[str] = []

        def visit(name: str) -> Optional[List[str]]:
            if name in stack:
                start = stack.index(name)
                return stack[start:] + [name]
            if name in visited:
                return None

            visited.add(name)
            stack.append(name)
            capability = self._capabilities.get(name)
            if capability:
                for dep in capability.dependencies:
                    cycle = visit(dep)
                    if cycle:
                        return cycle
            stack.pop()
            return None

        return visit(capability_name)
    
    def add_listener(
        self,
        listener: Callable[[DegradationLevel, DegradationLevel], None]
    ) -> None:
        """Add a listener for degradation level changes."""
        self._listeners.append(listener)
    
    def set_level(self, level: DegradationLevel) -> None:
        """
        Set the current degradation level.
        
        This triggers capability updates and notifies listeners.
        """
        with self._level_lock:
            if level != self._current_level:
                old_level = self._current_level
                self._current_level = level
                
                logger.warning(
                    f"System degradation level changed: "
                    f"{old_level.name} -> {level.name}"
                )
                
                for listener in self._listeners:
                    try:
                        listener(old_level, level)
                    except Exception as e:
                        logger.error(f"Degradation listener error: {e}")
    
    def is_available(self, capability_name: str) -> bool:
        """Check if a capability is available at current degradation level."""
        return self._is_available(capability_name, [])

    def _is_available(self, capability_name: str, stack: List[str]) -> bool:
        """Check availability while reporting dependency cycles."""
        if capability_name in stack:
            cycle = stack[stack.index(capability_name):] + [capability_name]
            raise ValueError(
                "Capability dependency cycle detected: "
                + " -> ".join(cycle)
            )

        capability = self._capabilities.get(capability_name)
        if not capability:
            return False
        
        # Check degradation level
        if self._current_level > capability.minimum_level:
            return False
        
        # Check dependencies
        stack.append(capability_name)
        for dep in capability.dependencies:
            if not self._is_available(dep, stack):
                stack.pop()
                return False
        stack.pop()
        
        return True
    
    def get_available_capabilities(self) -> Set[str]:
        """Get all currently available capabilities."""
        return {
            name for name in self._capabilities
            if self.is_available(name)
        }
    
    def execute_with_degradation(
        self,
        capability_name: str,
        operation: Callable[[], T],
        fallback: Optional[Callable[[], T]] = None
    ) -> T:
        """
        Execute an operation if capability is available, else use fallback.
        
        Raises:
            RuntimeError: If capability unavailable and no fallback provided
        """
        if self.is_available(capability_name):
            return operation()
        
        capability = self._capabilities.get(capability_name)
        if capability and capability.fallback_behavior:
            return capability.fallback_behavior()
        
        if fallback:
            return fallback()
        
        raise RuntimeError(
            f"Capability '{capability_name}' unavailable at "
            f"degradation level {self._current_level.name}"
        )


# Example: Setting up degradation for an agent system

def setup_agent_degradation() -> DegradationManager:
    """Configure degradation capabilities for an agent system."""
    
    manager = DegradationManager()
    
    # Core capabilities
    manager.register_capability(SystemCapability(
        name="llm_completion",
        minimum_level=DegradationLevel.SIGNIFICANT
    ))
    
    manager.register_capability(SystemCapability(
        name="tool_execution",
        minimum_level=DegradationLevel.MODERATE,
        dependencies={"llm_completion"}
    ))
    
    manager.register_capability(SystemCapability(
        name="multi_step_reasoning",
        minimum_level=DegradationLevel.MINOR,
        dependencies={"llm_completion", "tool_execution"}
    ))
    
    # Non-critical capabilities
    manager.register_capability(SystemCapability(
        name="response_caching",
        minimum_level=DegradationLevel.MODERATE
    ))
    
    manager.register_capability(SystemCapability(
        name="analytics_tracking",
        minimum_level=DegradationLevel.MINOR
    ))
    
    manager.register_capability(SystemCapability(
        name="personalization",
        minimum_level=DegradationLevel.MINOR,
        fallback_behavior=lambda: "generic_response"
    ))
    
    return manager

# ============================================================================
# Block 11 (chapter listing #11)
# ============================================================================

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import uuid
from collections import deque


@dataclass
class AgentErrorContext:
    """
    Error context that propagates through multi-agent systems.
    
    Captures the chain of agents involved and the context at each step,
    enabling context-aware recovery decisions at any level (analyzing
    error chain depth, failure patterns, and affected components).
    """
    error: AgentError
    agent_id: str
    agent_type: str
    parent_context: Optional['AgentErrorContext'] = None
    child_contexts: List['AgentErrorContext'] = field(default_factory=list)
    propagation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def get_error_chain(self) -> List[AgentError]:
        """Get the full chain of errors from root to this context."""
        chain = []
        current = self
        while current:
            chain.append(current.error)
            current = current.parent_context
        return list(reversed(chain))
    
    def get_root_cause(self) -> AgentError:
        """Get the original error that started this propagation."""
        chain = self.get_error_chain()
        return chain[0] if chain else self.error
    
    def add_child_error(self, child: 'AgentErrorContext') -> None:
        """Add a child error context (for parallel agent failures)."""
        child.parent_context = self
        self.child_contexts.append(child)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for logging and debugging."""
        return {
            "propagation_id": self.propagation_id,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "error": self.error.to_dict(),
            "error_chain_length": len(self.get_error_chain()),
            "root_cause": self.get_root_cause().to_dict(),
            "child_count": len(self.child_contexts)
        }


class MultiAgentErrorHandler:
    """
    Centralized error handling for multi-agent systems.
    
    Provides error aggregation, pattern detection, and coordinated
    recovery across multiple agents.
    """
    
    def __init__(
        self,
        max_concurrent_failures: int = 3,
        failure_window: timedelta = timedelta(minutes=5),
        max_contexts: int = 1000
    ):
        if max_contexts <= 0:
            raise ValueError("max_contexts must be positive")
        self.max_concurrent_failures = max_concurrent_failures
        self.failure_window = failure_window
        self.max_contexts = max_contexts
        self._error_contexts: deque[AgentErrorContext] = deque(
            maxlen=max_contexts
        )
        self._context_lock = threading.Lock()
        self._contexts_evicted_by_cap = 0
        self._contexts_expired_by_window = 0
    
    def record_error(self, context: AgentErrorContext) -> None:
        """Record an error context for analysis."""
        with self._context_lock:
            self._cleanup_old_contexts()
            if len(self._error_contexts) == self.max_contexts:
                self._contexts_evicted_by_cap += 1
            self._error_contexts.append(context)
    
    def _cleanup_old_contexts(self) -> None:
        """Remove contexts outside the failure window."""
        cutoff = datetime.now(timezone.utc) - self.failure_window
        before = len(self._error_contexts)
        retained = [
            ctx for ctx in self._error_contexts
            if ctx.error.timestamp > cutoff
        ]
        self._contexts_expired_by_window += before - len(retained)
        self._error_contexts = deque(retained, maxlen=self.max_contexts)
    
    def should_halt_orchestration(self) -> bool:
        """
        Determine if orchestration should halt based on error patterns.
        
        Returns True if too many agents are failing concurrently,
        indicating a systemic issue.
        """
        with self._context_lock:
            self._cleanup_old_contexts()
            
            # Count unique failing agents
            failing_agents = {ctx.agent_id for ctx in self._error_contexts}
            
            if len(failing_agents) >= self.max_concurrent_failures:
                logger.critical(
                    f"Multiple agent failures detected: {failing_agents}"
                )
                return True
            
            return False

    def reset(self) -> None:
        """Operator-invoked recovery: clear halt state and resume processing.

        ``should_halt_orchestration`` returns True as long as enough
        distinct agents have failed inside the rolling window. Reset
        is deliberately manual: once an operator has investigated the
        underlying cause, they call ``reset()`` to drop the recorded
        error contexts so orchestration can resume. Do not call this
        automatically; it exists to require human confirmation.
        """
        with self._context_lock:
            self._error_contexts.clear()
            logger.warning(
                "MultiAgentErrorHandler reset by operator; halt state cleared."
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Expose context-retention metrics for monitoring."""
        with self._context_lock:
            self._cleanup_old_contexts()
            return {
                "contexts_in_window": len(self._error_contexts),
                "max_contexts": self.max_contexts,
                "contexts_evicted_by_cap": self._contexts_evicted_by_cap,
                "contexts_expired_by_window": self._contexts_expired_by_window,
            }
    
    def get_recovery_recommendation(
        self,
        context: AgentErrorContext
    ) -> Dict[str, Any]:
        """
        Provide recovery recommendation based on error context and patterns.
        
        Analyzes the error chain and concurrent failures to suggest
        the best recovery approach.
        """
        root_cause = context.get_root_cause()
        chain_length = len(context.get_error_chain())
        
        # Check for cascade failures
        if chain_length > 3:
            return {
                "action": "halt_and_recover",
                "reason": "Deep error chain indicates cascade failure",
                "suggested_recovery_point": context.get_error_chain()[0].component
            }
        
        # Check for repeated failures of same type
        similar_errors = [
            ctx for ctx in self._error_contexts
            if ctx.error.category == context.error.category
        ]
        
        if len(similar_errors) > 2:
            return {
                "action": "circuit_break",
                "reason": f"Repeated {context.error.category.name} errors",
                "affected_component": root_cause.component
            }
        
        # Default: follow error's recovery strategy
        return {
            "action": root_cause.recovery_strategy.name.lower(),
            "reason": "Following error classification recommendation",
            "retry_count": context.error.retry_count
        }

# ============================================================================
# Block 12 (chapter listing #12)
# ============================================================================

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable, Protocol
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
import json
import uuid
import threading
import inspect
from collections import deque
from concurrent.futures import Executor, ThreadPoolExecutor


class DLQEntryStatus(Enum):
    PENDING = auto()      # Awaiting processing
    PROCESSING = auto()   # Currently being reprocessed
    RESOLVED = auto()     # Successfully reprocessed
    DISCARDED = auto()    # Manually discarded
    EXPIRED = auto()      # TTL exceeded


@dataclass
class DLQEntry:
    """Entry in the dead letter queue."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    original_request: Dict[str, Any] = field(default_factory=dict)
    error_context: Optional[AgentErrorContext] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_attempt_at: Optional[datetime] = None
    processing_deadline: Optional[datetime] = None
    attempt_count: int = 0
    status: DLQEntryStatus = DLQEntryStatus.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)
    resolution_notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "original_request": self.original_request,
            "error": self.error_context.to_dict() if self.error_context else None,
            "created_at": self.created_at.isoformat(),
            "last_attempt_at": self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            "processing_deadline": (
                self.processing_deadline.isoformat()
                if self.processing_deadline
                else None
            ),
            "attempt_count": self.attempt_count,
            "status": self.status.name,
            "metadata": self.metadata
        }


class DLQDurableSink(Protocol):
    """
    Durable storage hook for production DLQ capture.

    Implement with SQS, Kafka, Postgres, Redis Streams, or another durable
    store. The in-memory queue remains the active working set.
    """

    def save(self, entry: DLQEntry) -> None:
        """Persist the current representation of a DLQ entry."""
        ...


class DeadLetterQueue:
    """
    In-memory dead letter queue for failed agent tasks.

    Use durable_sink in production to persist failed work and status changes
    across process restarts.
    """
    
    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: timedelta = timedelta(days=7),
        max_reprocess_attempts: int = 3,
        processing_lease: timedelta = timedelta(minutes=15),
        on_entry_added: Optional[Callable[[DLQEntry], None]] = None,
        on_entry_resolved: Optional[Callable[[DLQEntry], None]] = None,
        durable_sink: Optional[DLQDurableSink] = None
    ):
        if max_size <= 0:
            raise ValueError("max_size must be greater than 0")
        if processing_lease <= timedelta(0):
            raise ValueError("processing_lease must be positive")

        self.max_size = max_size
        self.default_ttl = default_ttl
        self.max_reprocess_attempts = max_reprocess_attempts
        self.processing_lease = processing_lease
        self.on_entry_added = on_entry_added
        self.on_entry_resolved = on_entry_resolved
        self.durable_sink = durable_sink
        
        self._entries: Dict[str, DLQEntry] = {}
        self._entry_order: deque[str] = deque()
        self._lock = threading.Lock()
        
        # Metrics
        self._total_added = 0
        self._total_resolved = 0
        self._total_discarded = 0
        self._total_expired = 0

    def _persist_entry(self, entry: DLQEntry) -> None:
        """Persist an entry when a durable sink is configured."""
        if self.durable_sink:
            self.durable_sink.save(entry)

    def _remove_active_entry(self, entry_id: str) -> None:
        """Remove an entry from the active queue indexes."""
        self._entries.pop(entry_id, None)
        try:
            self._entry_order.remove(entry_id)
        except ValueError:
            pass
    
    def add(
        self,
        request: Dict[str, Any],
        error_context: Optional[AgentErrorContext] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DLQEntry:
        """
        Add a failed task to the dead letter queue.
        
        Returns:
            The created DLQ entry
        """
        entry = DLQEntry(
            original_request=request,
            error_context=error_context,
            metadata=metadata or {}
        )

        expired_entries: List[DLQEntry] = []
        with self._lock:
            # Evict oldest if at capacity
            while len(self._entries) >= self.max_size:
                expired_entry = self._evict_oldest()
                if expired_entry:
                    expired_entries.append(expired_entry)
            
            self._entries[entry.id] = entry
            self._entry_order.append(entry.id)
            self._total_added += 1

        for expired_entry in expired_entries:
            self._persist_entry(expired_entry)
        self._persist_entry(entry)
        
        logger.warning(
            f"Task added to DLQ: {entry.id}",
            extra={"dlq_entry": entry.to_dict()}
        )
        
        if self.on_entry_added:
            self.on_entry_added(entry)
        
        return entry
    
    def _evict_oldest(self) -> Optional[DLQEntry]:
        """Evict the oldest entry to make room."""
        while self._entry_order:
            oldest_id = self._entry_order.popleft()
            entry = self._entries.pop(oldest_id, None)
            if entry is None:
                continue
            entry.status = DLQEntryStatus.EXPIRED
            entry.processing_deadline = None
            self._total_expired += 1
            return entry
        return None
    
    def get(self, entry_id: str) -> Optional[DLQEntry]:
        """Get a specific DLQ entry by ID."""
        return self._entries.get(entry_id)
    
    def get_pending(self, limit: int = 100) -> List[DLQEntry]:
        """Get pending entries for reprocessing."""
        expired_entries: List[DLQEntry] = []
        recovered_entries: List[DLQEntry] = []
        with self._lock:
            now = datetime.now(timezone.utc)
            recovered_entries = self._release_stale_processing(now)
            expired_entries = self._expire_old_entries(now)
            
            pending = [
                entry for entry in self._entries.values()
                if entry.status == DLQEntryStatus.PENDING
                and entry.attempt_count < self.max_reprocess_attempts
            ]
            
            # Sort by creation time (oldest first)
            pending.sort(key=lambda e: e.created_at)
            
            result = pending[:limit]

        for recovered_entry in recovered_entries:
            self._persist_entry(recovered_entry)
        for expired_entry in expired_entries:
            self._persist_entry(expired_entry)

        return result
    
    def _expire_old_entries(self, now: datetime) -> List[DLQEntry]:
        """Mark entries past TTL as expired and remove them from the queue."""
        cutoff = now - self.default_ttl
        expired_ids: list[str] = []
        expired_entries: List[DLQEntry] = []
        for entry_id, entry in self._entries.items():
            if entry.created_at < cutoff and entry.status == DLQEntryStatus.PENDING:
                entry.status = DLQEntryStatus.EXPIRED
                entry.processing_deadline = None
                self._total_expired += 1
                expired_ids.append(entry_id)
                expired_entries.append(entry)
        for entry_id in expired_ids:
            # Drop from the active map and the FIFO order index so
            # expired entries stop counting against max_size.
            self._remove_active_entry(entry_id)
        return expired_entries

    def _release_stale_processing(self, now: datetime) -> List[DLQEntry]:
        """Return expired processing leases to PENDING for another attempt."""
        recovered_entries: List[DLQEntry] = []
        terminal_ids: list[str] = []
        for entry_id, entry in self._entries.items():
            if (
                entry.status == DLQEntryStatus.PROCESSING
                and (
                    entry.processing_deadline is None
                    or entry.processing_deadline <= now
                )
            ):
                if entry.attempt_count >= self.max_reprocess_attempts:
                    entry.status = DLQEntryStatus.DISCARDED
                    self._total_discarded += 1
                    terminal_ids.append(entry_id)
                else:
                    entry.status = DLQEntryStatus.PENDING
                entry.processing_deadline = None
                recovered_entries.append(entry)
        for entry_id in terminal_ids:
            self._remove_active_entry(entry_id)
        return recovered_entries

    def recover_stale_processing(self) -> int:
        """
        Return expired PROCESSING leases to PENDING.

        Call this after rehydrating a durable DLQ on startup. get_pending()
        also runs it before selecting work, so crashed processors do not leave
        entries stuck in PROCESSING forever.
        """
        with self._lock:
            recovered_entries = self._release_stale_processing(
                datetime.now(timezone.utc)
            )

        for entry in recovered_entries:
            self._persist_entry(entry)
        return len(recovered_entries)
    
    def mark_processing(self, entry_id: str) -> bool:
        """Mark an entry as being processed."""
        entry_to_persist: Optional[DLQEntry] = None
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry and entry.status == DLQEntryStatus.PENDING:
                now = datetime.now(timezone.utc)
                entry.status = DLQEntryStatus.PROCESSING
                entry.last_attempt_at = now
                entry.processing_deadline = now + self.processing_lease
                entry.attempt_count += 1
                entry_to_persist = entry

        if entry_to_persist:
            self._persist_entry(entry_to_persist)
            return True
        return False
    
    def mark_resolved(
        self,
        entry_id: str,
        resolution_notes: Optional[str] = None
    ) -> bool:
        """Mark an entry as successfully resolved."""
        entry_to_persist: Optional[DLQEntry] = None
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.status = DLQEntryStatus.RESOLVED
                entry.processing_deadline = None
                entry.resolution_notes = resolution_notes
                self._total_resolved += 1
                entry_to_persist = entry
                self._remove_active_entry(entry_id)

        if entry_to_persist:
            self._persist_entry(entry_to_persist)
            if self.on_entry_resolved:
                self.on_entry_resolved(entry_to_persist)
            return True
        return False
    
    def mark_failed(self, entry_id: str) -> bool:
        """Mark a reprocessing attempt as failed, return to pending."""
        entry_to_persist: Optional[DLQEntry] = None
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                if entry.attempt_count >= self.max_reprocess_attempts:
                    entry.status = DLQEntryStatus.DISCARDED
                    entry.processing_deadline = None
                    self._total_discarded += 1
                    self._remove_active_entry(entry_id)
                else:
                    entry.status = DLQEntryStatus.PENDING
                    entry.processing_deadline = None
                entry_to_persist = entry

        if entry_to_persist:
            self._persist_entry(entry_to_persist)
            return True
        return False
    
    def discard(
        self,
        entry_id: str,
        reason: Optional[str] = None
    ) -> bool:
        """Manually discard an entry."""
        entry_to_persist: Optional[DLQEntry] = None
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.status = DLQEntryStatus.DISCARDED
                entry.processing_deadline = None
                entry.resolution_notes = reason
                self._total_discarded += 1
                entry_to_persist = entry
                self._remove_active_entry(entry_id)

        if entry_to_persist:
            self._persist_entry(entry_to_persist)
            return True
        return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get DLQ metrics for monitoring."""
        with self._lock:
            status_counts = {}
            for status in DLQEntryStatus:
                status_counts[status.name] = sum(
                    1 for e in self._entries.values()
                    if e.status == status
                )
            
            return {
                "total_entries": len(self._entries),
                "total_added": self._total_added,
                "total_resolved": self._total_resolved,
                "total_discarded": self._total_discarded,
                "total_expired": self._total_expired,
                "status_counts": status_counts,
                "resolution_rate": (
                    self._total_resolved / self._total_added
                    if self._total_added > 0 else 0
                )
            }


class DLQProcessor:
    """
    Automated processor for dead letter queue entries.
    
    Periodically attempts to reprocess failed tasks with
    potentially improved conditions or alternative strategies.
    """
    
    def __init__(
        self,
        dlq: DeadLetterQueue,
        reprocess_fn: Callable[[Dict[str, Any]], Any],
        batch_size: int = 10,
        interval: timedelta = timedelta(minutes=5),
        reprocess_timeout: Optional[timedelta] = timedelta(minutes=2),
        blocking_executor: Optional[Executor] = None,
        max_blocking_workers: int = 4
    ):
        if reprocess_timeout is not None and reprocess_timeout <= timedelta(0):
            raise ValueError("reprocess_timeout must be positive")
        if max_blocking_workers <= 0:
            raise ValueError("max_blocking_workers must be positive")

        self.dlq = dlq
        self.reprocess_fn = reprocess_fn
        self.batch_size = batch_size
        self.interval = interval
        self.reprocess_timeout = reprocess_timeout
        self._owns_executor = blocking_executor is None
        self._blocking_executor = blocking_executor or ThreadPoolExecutor(
            max_workers=max_blocking_workers,
            thread_name_prefix="dlq-reprocess"
        )
        self._running = False
        self._task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start the DLQ processor."""
        self.dlq.recover_stale_processing()
        self._running = True
        self._task = asyncio.create_task(self._process_loop())
        logger.info("DLQ processor started")
    
    async def stop(self) -> None:
        """Stop the DLQ processor."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._owns_executor:
            self._blocking_executor.shutdown(wait=False, cancel_futures=True)
        logger.info("DLQ processor stopped")
    
    async def _process_loop(self) -> None:
        """Main processing loop."""
        while self._running:
            try:
                await self._process_batch()
            except Exception as e:
                logger.error(f"DLQ processor error: {e}")
            
            await asyncio.sleep(self.interval.total_seconds())
    
    async def _process_batch(self) -> None:
        """Process a batch of pending DLQ entries."""
        entries = self.dlq.get_pending(self.batch_size)
        
        for entry in entries:
            if not self.dlq.mark_processing(entry.id):
                continue
            
            try:
                await self._run_reprocess(entry.original_request)
                self.dlq.mark_resolved(entry.id, "Automatic reprocessing succeeded")
                logger.info(f"DLQ entry {entry.id} resolved")
            except Exception as e:
                self.dlq.mark_failed(entry.id)
                logger.warning(
                    f"DLQ entry {entry.id} reprocessing failed: {e}",
                    extra={"attempt": entry.attempt_count}
                )

    async def _run_reprocess(self, request: Dict[str, Any]) -> Any:
        """Run one reprocessor with a per-entry timeout."""
        async def invoke() -> Any:
            if inspect.iscoroutinefunction(self.reprocess_fn):
                return await self.reprocess_fn(request)

            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                self._blocking_executor,
                self.reprocess_fn,
                request
            )
            if inspect.isawaitable(result):
                return await result
            return result

        if self.reprocess_timeout is None:
            return await invoke()

        return await asyncio.wait_for(
            invoke(),
            timeout=self.reprocess_timeout.total_seconds()
        )

# ============================================================================
# Block 13 (chapter listing #13)
# ============================================================================

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta, timezone
import threading
import statistics
import time


@dataclass
class ErrorPattern:
    """A detected error pattern."""
    category: ErrorCategory
    component: Optional[str]
    message_signature: str
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    affected_operations: List[str]
    sample_errors: List[AgentError]
    
    @property
    def frequency(self) -> float:
        """Occurrences per hour."""
        duration = (self.last_seen - self.first_seen).total_seconds() / 3600
        return self.occurrence_count / max(duration, 1/3600)


class ErrorAggregator:
    """
    Aggregates errors for pattern detection and analysis.
    
    Identifies recurring error patterns, correlates failures across
    components, and provides insights for debugging and prevention.
    """
    
    def __init__(
        self,
        window_size: timedelta = timedelta(hours=1),
        pattern_threshold: int = 3,
        max_samples_per_pattern: int = 5,
        max_patterns: int = 1000,
        max_temporal_buckets: int = 120,
        max_affected_operations: int = 25,
        max_errors_per_window: int = 10_000,
        max_errors_per_bucket: int = 1_000,
        cleanup_interval: float = 5.0,
    ):
        self.window_size = window_size
        self.pattern_threshold = pattern_threshold
        self.max_samples_per_pattern = max_samples_per_pattern
        self.max_patterns = max(1, max_patterns)
        self.max_temporal_buckets = max(1, max_temporal_buckets)
        self.max_affected_operations = max(1, max_affected_operations)
        self.max_errors_per_window = max(1, max_errors_per_window)
        self.max_errors_per_bucket = max(1, max_errors_per_bucket)
        self.cleanup_interval = cleanup_interval

        self._errors = deque(maxlen=self.max_errors_per_window)
        self._patterns: Dict[str, ErrorPattern] = {}
        self._lock = threading.Lock()
        # Throttle the O(N) pattern/correlation rebuild so record() stays cheap
        # on hot paths. Cleanup still runs at every read-side query.
        self._last_cleanup_at: float = 0.0

        # Correlation tracking
        self._component_correlations: Dict[Tuple[str, str], int] = defaultdict(int)
        self._temporal_buckets = defaultdict(
            lambda: deque(maxlen=self.max_errors_per_bucket)
        )

    def record(self, error: AgentError) -> None:
        """Record an error for aggregation."""
        with self._lock:
            self._errors.append(error)
            now = time.monotonic()
            if now - self._last_cleanup_at >= self.cleanup_interval:
                self._cleanup_windowed_state()
                self._last_cleanup_at = now
    
    def _cleanup_windowed_state(self) -> None:
        """Keep all aggregate state scoped to the analysis window."""
        cutoff = datetime.now(timezone.utc) - self.window_size
        self._errors = deque(
            (e for e in self._errors if e.timestamp > cutoff),
            maxlen=self.max_errors_per_window
        )
        self._patterns.clear()
        self._component_correlations.clear()
        self._temporal_buckets = defaultdict(
            lambda: deque(maxlen=self.max_errors_per_bucket)
        )

        for error in self._errors:
            self._update_patterns(error)
            self._update_correlations(error)

        self._expire_temporal_buckets(cutoff)
        self._cap_patterns()

    def _expire_temporal_buckets(self, cutoff: datetime) -> None:
        """Drop old or excess temporal buckets, then rebuild correlations."""
        bucket_cutoff = cutoff.strftime("%Y-%m-%d-%H-%M")
        for bucket_key in list(self._temporal_buckets):
            if bucket_key < bucket_cutoff:
                del self._temporal_buckets[bucket_key]

        if len(self._temporal_buckets) > self.max_temporal_buckets:
            keep = set(sorted(self._temporal_buckets)[-self.max_temporal_buckets:])
            for bucket_key in list(self._temporal_buckets):
                if bucket_key not in keep:
                    del self._temporal_buckets[bucket_key]

        self._component_correlations.clear()
        for bucket_errors in self._temporal_buckets.values():
            bucket_snapshot = list(bucket_errors)
            for index, error in enumerate(bucket_snapshot):
                if not error.component:
                    continue
                for other in bucket_snapshot[:index]:
                    if other.component and other.component != error.component:
                        pair = tuple(sorted([error.component, other.component]))
                        self._component_correlations[pair] += 1

    def _cap_patterns(self) -> None:
        """Bound retained patterns by count, keeping frequent recent patterns."""
        if len(self._patterns) <= self.max_patterns:
            return

        ranked = sorted(
            self._patterns.items(),
            key=lambda item: (item[1].occurrence_count, item[1].last_seen),
            reverse=True
        )
        self._patterns = dict(ranked[:self.max_patterns])

    def _get_message_signature(self, message: str) -> str:
        """
        Create a signature from an error message for grouping.

        Normalizes variable parts (IDs, timestamps, etc.) to group
        similar errors together.
        """
        import re

        # Replace UUIDs
        signature = re.sub(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '<UUID>',
            message,
            flags=re.IGNORECASE
        )

        # Replace numbers
        signature = re.sub(r'\b\d+\b', '<NUM>', signature)

        # Replace quoted strings
        signature = re.sub(r'"[^"]*"', '"<STR>"', signature)
        signature = re.sub(r"'[^']*'", "'<STR>'", signature)

        # Normalize whitespace
        signature = ' '.join(signature.split())

        return signature[:200]  # Limit signature length

    def _update_patterns(self, error: AgentError) -> None:
        """Update pattern tracking with new error."""
        signature = self._get_message_signature(error.message)
        pattern_key = f"{error.category.name}:{error.component}:{signature}"

        if pattern_key in self._patterns:
            pattern = self._patterns[pattern_key]
            pattern.occurrence_count += 1
            pattern.last_seen = error.timestamp
            if (
                error.context.get("operation")
                and error.context["operation"] not in pattern.affected_operations
                and len(pattern.affected_operations) < self.max_affected_operations
            ):
                pattern.affected_operations.append(error.context["operation"])
            if len(pattern.sample_errors) < self.max_samples_per_pattern:
                pattern.sample_errors.append(error)
        else:
            self._patterns[pattern_key] = ErrorPattern(
                category=error.category,
                component=error.component,
                message_signature=signature,
                occurrence_count=1,
                first_seen=error.timestamp,
                last_seen=error.timestamp,
                affected_operations=[error.context.get("operation", "unknown")],
                sample_errors=[error]
            )

    def _update_correlations(self, error: AgentError) -> None:
        """Track correlations between component failures."""
        # Bucket by minute for temporal correlation
        bucket_key = error.timestamp.strftime("%Y-%m-%d-%H-%M")
        self._temporal_buckets[bucket_key].append(error)

        # Check for correlations in the same time bucket
        bucket_errors = list(self._temporal_buckets[bucket_key])
        if len(bucket_errors) > 1 and error.component:
            for other in bucket_errors[:-1]:
                if other.component and other.component != error.component:
                    pair = tuple(sorted([error.component, other.component]))
                    self._component_correlations[pair] += 1

    def get_patterns(
        self,
        min_occurrences: Optional[int] = None
    ) -> List[ErrorPattern]:
        """Get detected error patterns, optionally filtered by occurrence count."""
        threshold = min_occurrences or self.pattern_threshold

        with self._lock:
            self._cleanup_windowed_state()
            return self._get_patterns_unlocked(threshold)

    def _get_patterns_unlocked(self, threshold: int) -> List[ErrorPattern]:
        return [
            pattern for pattern in self._patterns.values()
            if pattern.occurrence_count >= threshold
        ]

    def get_top_patterns(self, limit: int = 10) -> List[ErrorPattern]:
        """Get the most frequent error patterns."""
        with self._lock:
            self._cleanup_windowed_state()
            return self._get_top_patterns_unlocked(limit)

    def _get_top_patterns_unlocked(self, limit: int = 10) -> List[ErrorPattern]:
        patterns = self._get_patterns_unlocked(1)
        patterns.sort(key=lambda p: (p.occurrence_count, p.last_seen), reverse=True)
        return patterns[:limit]

    def get_correlations(
        self,
        min_correlation: int = 2
    ) -> List[Tuple[str, str, int]]:
        """Get correlated component failures."""
        with self._lock:
            self._cleanup_windowed_state()
            return self._get_correlations_unlocked(min_correlation)

    def _get_correlations_unlocked(
        self,
        min_correlation: int = 2
    ) -> List[Tuple[str, str, int]]:
        correlations = [
            (comp1, comp2, count)
            for (comp1, comp2), count in self._component_correlations.items()
            if count >= min_correlation
        ]
        correlations.sort(key=lambda x: x[2], reverse=True)
        return correlations

    def get_error_rate_by_category(self) -> Dict[str, float]:
        """Get error rate per hour by category."""
        with self._lock:
            self._cleanup_windowed_state()
            return self._get_error_rate_by_category_unlocked()

    def _get_error_rate_by_category_unlocked(self) -> Dict[str, float]:
        if not self._errors:
            return {}

        window_hours = self.window_size.total_seconds() / 3600
        category_counts = defaultdict(int)

        for error in self._errors:
            category_counts[error.category.name] += 1

        return {
            category: count / window_hours
            for category, count in category_counts.items()
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive error aggregation summary."""
        with self._lock:
            self._cleanup_windowed_state()
            patterns = self._get_patterns_unlocked(self.pattern_threshold)
            top_patterns = self._get_top_patterns_unlocked(5)
            correlations = self._get_correlations_unlocked()
            error_rate_by_category = self._get_error_rate_by_category_unlocked()
            
            return {
                "total_errors": len(self._errors),
                "unique_patterns": len(patterns),
                "error_rate_by_category": error_rate_by_category,
                "top_patterns": [
                    {
                        "signature": p.message_signature[:100],
                        "category": p.category.name,
                        "component": p.component,
                        "count": p.occurrence_count,
                        "frequency_per_hour": round(p.frequency, 2)
                    }
                    for p in top_patterns
                ],
                "component_correlations": [
                    {"components": [c1, c2], "correlation_count": count}
                    for c1, c2, count in correlations[:5]
                ],
                "window_size_hours": self.window_size.total_seconds() / 3600
            }

# ============================================================================
# Block 14 (chapter listing #14)
# ============================================================================

# What happened (problematic code)
async def get_product_recommendation(user_query: str) -> str:
    # No retry policy, no circuit breaker
    return await llm_client.complete(user_query)

llm_circuit = CircuitBreaker(
    name="primary_llm",
    config=CircuitBreakerConfig(
        failure_threshold=5,
        timeout=timedelta(seconds=30)
    )
)

@with_retry(max_retries=3, base_delay=1.0)
async def get_product_recommendation(
    user_query: str,
    fallback_chain: FallbackChain[str]
) -> str:
    async def recommendation_fallback() -> str:
        result = await fallback_chain.execute({
            "messages": [{"role": "user", "content": user_query}]
        })
        return result.value

    return await llm_circuit.execute_async(
        lambda: llm_client.complete(user_query),
        fallback=recommendation_fallback
    )

# ============================================================================
# Block 15 (chapter listing #15)
# ============================================================================

# Wrapped in an ``if __name__ == "__main__":`` guard because the body of this
# example references collaborators (``recommendation_agent``, ``classifier``,
# ``degraded_response``) that real applications must supply. Keeping the
# function definition inside the guard lets ``import error_handling`` succeed
# in test/import contexts that don't provide those collaborators.
if __name__ == "__main__":
    async def handle_multi_agent_request(request: UserRequest) -> Response:
        error_handler = MultiAgentErrorHandler(
            max_concurrent_failures=2,
            failure_window=timedelta(minutes=5)
        )
        
        try:
            recommendation = await recommendation_agent.process(request)
        except Exception as e:
            context = AgentErrorContext(
                error=classifier.classify(e),
                agent_id="recommendation_agent",
                agent_type="recommendation"
            )
            error_handler.record_error(context)
            
            if error_handler.should_halt_orchestration():
                # Graceful degradation instead of cascade
                return await degraded_response(request)
            
            raise

# ============================================================================
# Block 16 (chapter listing #16)
# ============================================================================

# Wrapped in an ``if __name__ == "__main__":`` guard (same pattern Block 15
# uses) because the body executes at module import: ``aggregator.get_summary()``
# returns an empty ``top_patterns`` list on a fresh aggregator, so
# ``summary["top_patterns"][0]`` raises IndexError at import time, and
# ``alert_ops_team`` / ``degradation_manager`` are undefined demo collaborators.
if __name__ == "__main__":
    aggregator = ErrorAggregator(
        window_size=timedelta(minutes=10),
        pattern_threshold=50
    )

    # Pattern detection revealed:
    # - 500+ rate limit errors from LLM provider
    # - Strong correlation between recommendation and cart failures
    # - Error frequency: 100+ per minute

    summary = aggregator.get_summary()
    if summary["top_patterns"][0]["count"] > 100:
        alert_ops_team(summary)
        degradation_manager.set_level(DegradationLevel.MODERATE)

# ============================================================================
# Block 17 (chapter listing #17)
# ============================================================================

async def handle_with_resilience(
    request: UserRequest,
    fallback_chain_factory: Callable[[], Awaitable[FallbackChain[str]]],
    simple_response_handler: Callable[[UserRequest], Awaitable[Response]],
    cached_response_handler: Callable[[UserRequest], Awaitable[Response]],
    dead_letter_queue: DeadLetterQueue,
    error_classifier: Optional[ErrorClassifier] = None,
    degradation_manager: Optional[DegradationManager] = None
) -> Response:
    """Handle a request with injected resilience collaborators.

    The chapter's production app wires these dependencies at startup. Keeping
    them explicit avoids import-time NameError failures when readers reuse this
    function outside the demo ``__main__`` blocks.
    """
    fallback_chain = await fallback_chain_factory()
    degradation_manager = degradation_manager or setup_agent_degradation()
    error_classifier = error_classifier or ErrorClassifier()
    
    try:
        # Check degradation level first
        if not degradation_manager.is_available("multi_step_reasoning"):
            return await simple_response_handler(request)
        
        # Try with fallback chain
        result = await fallback_chain.execute({
            "messages": [{"role": "user", "content": request.query}]
        })
        
        if result.degraded:
            # Log degraded response for monitoring
            logger.info(
                f"Served degraded response via {result.provider_used}",
                extra={"latency": result.total_latency.total_seconds()}
            )
        
        return Response(content=result.value, degraded=result.degraded)
        
    except Exception as e:
        # Last resort: add to DLQ and return cached response
        dead_letter_queue.add(
            request=request.to_dict(),
            error_context=AgentErrorContext(
                error=error_classifier.classify(e),
                agent_id="orchestrator",
                agent_type="main"
            )
        )
        return await cached_response_handler(request)
