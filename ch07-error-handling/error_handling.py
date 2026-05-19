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
import random
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Optional, Set, TypeVar, Generic, Awaitable
from functools import wraps
import logging

logger = logging.getLogger(__name__)

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
        jitter_factor: float = 0.1
    ):
        self.multiplier = multiplier
        self.max_delay = max_delay
        self.jitter = jitter
        self.jitter_factor = jitter_factor
    
    def calculate_delay(self, attempt: int, base_delay: float) -> float:
        # 'Full jitter' per the AWS Architecture Blog: pick uniformly in
        # [0, exponential_cap]. This empirically minimizes contention vs.
        # additive symmetric jitter when many clients retry simultaneously.
        cap = min(base_delay * (self.multiplier ** attempt), self.max_delay)
        if self.jitter:
            return random.uniform(0, cap)
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

    Note: This implementation keeps per-sequence state in thread-local
    storage. A single DecorrelatedJitter instance can be shared across
    threads (and across concurrent retry sequences in a shared RetryPolicy)
    without one sequence's prior delay leaking into another's.
    """

    def __init__(self, max_delay: float = 60.0):
        self.max_delay = max_delay
        # Per-thread state so that concurrent retry sequences do not
        # share _previous_delay through the same instance.
        self._local = threading.local()

    def calculate_delay(self, attempt: int, base_delay: float) -> float:
        prev = getattr(self._local, "previous_delay", None)
        if prev is None:
            prev = base_delay

        delay = random.uniform(base_delay, prev * 3)
        delay = min(delay, self.max_delay)
        self._local.previous_delay = delay
        return delay


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
        
        for attempt in range(self.max_retries + 1):
            try:
                return await operation()
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
                
                delay = self.get_delay(attempt)
                logger.info(
                    f"Retry {attempt + 1}/{self.max_retries} for {component} "
                    f"after {delay:.2f}s: {agent_error.message}"
                )
                
                if self.on_retry:
                    self.on_retry(agent_error, attempt)
                
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
        
        for attempt in range(self.max_retries + 1):
            try:
                return operation()
            except Exception as e:
                agent_error = self.error_classifier.classify(
                    e, context=context, component=component
                )
                agent_error.retry_count = attempt
                last_error = agent_error
                
                if not self.should_retry(agent_error, attempt):
                    raise
                
                delay = self.get_delay(attempt)
                logger.info(
                    f"Retry {attempt + 1}/{self.max_retries} after {delay:.2f}s"
                )
                
                if self.on_retry:
                    self.on_retry(agent_error, attempt)
                
                time.sleep(delay)
        
        if last_error:
            if last_error.original_exception is not None:
                raise last_error.original_exception
            raise RuntimeError(f"Retries exhausted: {last_error.message}")
        raise RuntimeError("Unexpected retry loop termination")


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

    _calls: deque = field(default_factory=lambda: deque())
    _retries: deque = field(default_factory=lambda: deque())
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
    sliding_window_size: int = 100  # Size of measurement window


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
    
    This implementation supports both count-based and rate-based
    failure detection, thread-safe state transitions, and 
    comprehensive metrics for monitoring.
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
        self._half_open_calls = 0
        self._half_open_successes = 0
        
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
        if self._last_failure_time is None:
            return True
        elapsed = datetime.now(timezone.utc) - self._last_failure_time
        return elapsed >= self.config.timeout
    
    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state with callback notification."""
        old_state = self._state
        self._state = new_state
        
        if new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0
            self._half_open_successes = 0
        
        logger.info(
            f"Circuit '{self.name}' transitioned from {old_state.name} "
            f"to {new_state.name}"
        )
        
        if self.on_state_change:
            self.on_state_change(old_state, new_state)
    
    def _record_success(self) -> None:
        """Record a successful call and potentially close circuit."""
        with self._state_lock:
            self._total_successes += 1
            self._call_history.append(CallResult(
                timestamp=datetime.now(timezone.utc),
                success=True,
                duration=timedelta(0)  # Would be populated by actual call
            ))
            
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_successes += 1
                if self._half_open_successes >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)
    
    def _record_failure(self, error: Exception) -> None:
        """Record a failure and potentially open circuit."""
        with self._state_lock:
            self._total_failures += 1
            self._last_failure_time = datetime.now(timezone.utc)
            self._call_history.append(CallResult(
                timestamp=datetime.now(timezone.utc),
                success=False,
                duration=timedelta(0),
                error=error
            ))
            
            if self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._should_open():
                    self._transition_to(CircuitState.OPEN)
    
    def _should_open(self) -> bool:
        """Determine if circuit should open based on failure metrics."""
        # Count-based threshold
        recent_failures = sum(
            1 for call in self._call_history
            if not call.success
            and (datetime.now(timezone.utc) - call.timestamp) < timedelta(minutes=1)
        )
        if recent_failures >= self.config.failure_threshold:
            return True
        
        # Rate-based threshold
        if len(self._call_history) >= self.config.minimum_calls:
            failure_rate = sum(
                1 for call in self._call_history if not call.success
            ) / len(self._call_history)
            if failure_rate >= self.config.failure_rate_threshold:
                return True
        
        return False
    
    def _can_execute(self) -> bool:
        """Check if a call can be executed given current state."""
        with self._state_lock:
            current_state = self.state  # This may trigger state transition
            
            if current_state == CircuitState.CLOSED:
                return True
            elif current_state == CircuitState.OPEN:
                return False
            else:  # HALF_OPEN
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
    
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
        
        if not self._can_execute():
            self._total_rejections += 1
            if self.on_rejected:
                self.on_rejected()
            
            if fallback:
                return await fallback()
            
            time_until_retry = (
                self.config.timeout -
                (datetime.now(timezone.utc) - self._last_failure_time)
                if self._last_failure_time else self.config.timeout
            )
            raise CircuitBreakerError(self.name, time_until_retry)
        
        try:
            result = await operation()
            self._record_success()
            return result
        except Exception as e:
            self._record_failure(e)
            raise
    
    def execute_sync(
        self,
        operation: Callable[[], T],
        fallback: Optional[Callable[[], T]] = None
    ) -> T:
        """Synchronous version of execute_async."""
        self._total_calls += 1
        
        if not self._can_execute():
            self._total_rejections += 1
            if self.on_rejected:
                self.on_rejected()
            
            if fallback:
                return fallback()
            
            time_until_retry = (
                self.config.timeout -
                (datetime.now(timezone.utc) - self._last_failure_time)
                if self._last_failure_time else self.config.timeout
            )
            raise CircuitBreakerError(self.name, time_until_retry)
        
        try:
            result = operation()
            self._record_success()
            return result
        except Exception as e:
            self._record_failure(e)
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current circuit breaker metrics for monitoring."""
        with self._state_lock:
            recent_calls = [
                c for c in self._call_history
                if (datetime.now(timezone.utc) - c.timestamp) < timedelta(minutes=5)
            ]
            recent_failures = sum(1 for c in recent_calls if not c.success)
            
            return {
                "name": self.name,
                "state": self._state.name,
                "total_calls": self._total_calls,
                "total_successes": self._total_successes,
                "total_failures": self._total_failures,
                "total_rejections": self._total_rejections,
                "recent_failure_rate": (
                    recent_failures / len(recent_calls)
                    if recent_calls else 0
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
    """
    
    _instance: Optional['CircuitBreakerRegistry'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._breakers: Dict[str, CircuitBreaker] = {}
        return cls._instance
    
    def register(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Register a new circuit breaker or return existing one."""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, config)
        return self._breakers[name]
    
    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get a circuit breaker by name."""
        return self._breakers.get(name)
    
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
result = with_fallbacks(request, fallbacks)

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, TypeVar, Generic, Callable, Awaitable, Any
from datetime import datetime, timedelta, timezone
import hashlib
import json

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


class FallbackChain(Generic[T]):
    """
    Executes requests through a chain of fallback providers.
    
    Providers are tried in priority order until one succeeds.
    Comprehensive metrics are collected for monitoring and optimization.
    """
    
    def __init__(
        self,
        providers: List[FallbackProvider[T]],
        on_fallback: Optional[Callable[[str, str, Exception], None]] = None
    ):
        # Sort by priority (lower = higher priority)
        self.providers = sorted(providers, key=lambda p: p.priority)
        self.on_fallback = on_fallback
        
        # Metrics
        self._total_requests = 0
        self._provider_usage: Dict[str, int] = {p.name: 0 for p in providers}
        self._fallback_counts: Dict[str, int] = {p.name: 0 for p in providers}
    
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
                result = await provider.execute(request)
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
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get fallback chain metrics for monitoring."""
        return {
            "total_requests": self._total_requests,
            "provider_usage": self._provider_usage,
            "fallback_counts": self._fallback_counts,
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

# Example: Setting up a production fallback chain for LLM calls

async def create_production_fallback_chain() -> FallbackChain[str]:
    """Create a production-ready fallback chain for LLM requests."""
    
    registry = CircuitBreakerRegistry()
    
    # Primary: Claude 3 Opus
    primary_circuit = registry.register(
        "claude_opus",
        CircuitBreakerConfig(
            failure_threshold=3,
            timeout=timedelta(seconds=30)
        )
    )
    
    # Secondary: Claude 3 Haiku (faster, cheaper)
    secondary_circuit = registry.register(
        "claude_haiku",
        CircuitBreakerConfig(
            failure_threshold=5,
            timeout=timedelta(seconds=20)
        )
    )
    
    providers = [
        LLMProvider(
            provider_name="anthropic",
            model="claude-3-opus-20240229",
            client=anthropic_client,
            _priority=0,
            circuit_breaker=primary_circuit
        ),
        LLMProvider(
            provider_name="anthropic",
            model="claude-3-haiku-20240307",
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
        self._capabilities[capability.name] = capability
    
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
        capability = self._capabilities.get(capability_name)
        if not capability:
            return False
        
        # Check degradation level
        if self._current_level > capability.minimum_level:
            return False
        
        # Check dependencies
        for dep in capability.dependencies:
            if not self.is_available(dep):
                return False
        
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
from datetime import datetime
import uuid


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
        failure_window: timedelta = timedelta(minutes=5)
    ):
        self.max_concurrent_failures = max_concurrent_failures
        self.failure_window = failure_window
        self._error_contexts: List[AgentErrorContext] = []
        self._context_lock = threading.Lock()
    
    def record_error(self, context: AgentErrorContext) -> None:
        """Record an error context for analysis."""
        with self._context_lock:
            self._error_contexts.append(context)
            self._cleanup_old_contexts()
    
    def _cleanup_old_contexts(self) -> None:
        """Remove contexts outside the failure window."""
        cutoff = datetime.now(timezone.utc) - self.failure_window
        self._error_contexts = [
            ctx for ctx in self._error_contexts
            if ctx.error.timestamp > cutoff
        ]
    
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
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
import json
import uuid
import threading
from collections import deque


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
            "attempt_count": self.attempt_count,
            "status": self.status.name,
            "metadata": self.metadata
        }


class DeadLetterQueue:
    """
    Production dead letter queue for failed agent tasks.
    
    Provides storage, retrieval, and reprocessing capabilities
    for tasks that have exhausted normal error handling.
    """
    
    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: timedelta = timedelta(days=7),
        max_reprocess_attempts: int = 3,
        on_entry_added: Optional[Callable[[DLQEntry], None]] = None,
        on_entry_resolved: Optional[Callable[[DLQEntry], None]] = None
    ):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.max_reprocess_attempts = max_reprocess_attempts
        self.on_entry_added = on_entry_added
        self.on_entry_resolved = on_entry_resolved
        
        self._entries: Dict[str, DLQEntry] = {}
        self._entry_order: deque[str] = deque()
        self._lock = threading.Lock()
        
        # Metrics
        self._total_added = 0
        self._total_resolved = 0
        self._total_discarded = 0
        self._total_expired = 0
    
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
        
        with self._lock:
            # Evict oldest if at capacity
            while len(self._entries) >= self.max_size:
                self._evict_oldest()
            
            self._entries[entry.id] = entry
            self._entry_order.append(entry.id)
            self._total_added += 1
        
        logger.warning(
            f"Task added to DLQ: {entry.id}",
            extra={"dlq_entry": entry.to_dict()}
        )
        
        if self.on_entry_added:
            self.on_entry_added(entry)
        
        return entry
    
    def _evict_oldest(self) -> None:
        """Evict the oldest entry to make room."""
        if self._entry_order:
            oldest_id = self._entry_order.popleft()
            if oldest_id in self._entries:
                self._entries[oldest_id].status = DLQEntryStatus.EXPIRED
                self._total_expired += 1
                del self._entries[oldest_id]
    
    def get(self, entry_id: str) -> Optional[DLQEntry]:
        """Get a specific DLQ entry by ID."""
        return self._entries.get(entry_id)
    
    def get_pending(self, limit: int = 100) -> List[DLQEntry]:
        """Get pending entries for reprocessing."""
        with self._lock:
            self._expire_old_entries()
            
            pending = [
                entry for entry in self._entries.values()
                if entry.status == DLQEntryStatus.PENDING
                and entry.attempt_count < self.max_reprocess_attempts
            ]
            
            # Sort by creation time (oldest first)
            pending.sort(key=lambda e: e.created_at)
            
            return pending[:limit]
    
    def _expire_old_entries(self) -> None:
        """Mark entries past TTL as expired."""
        cutoff = datetime.now(timezone.utc) - self.default_ttl
        for entry in self._entries.values():
            if entry.created_at < cutoff and entry.status == DLQEntryStatus.PENDING:
                entry.status = DLQEntryStatus.EXPIRED
                self._total_expired += 1
    
    def mark_processing(self, entry_id: str) -> bool:
        """Mark an entry as being processed."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry and entry.status == DLQEntryStatus.PENDING:
                entry.status = DLQEntryStatus.PROCESSING
                entry.last_attempt_at = datetime.now(timezone.utc)
                entry.attempt_count += 1
                return True
            return False
    
    def mark_resolved(
        self,
        entry_id: str,
        resolution_notes: Optional[str] = None
    ) -> bool:
        """Mark an entry as successfully resolved."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.status = DLQEntryStatus.RESOLVED
                entry.resolution_notes = resolution_notes
                self._total_resolved += 1
                
                if self.on_entry_resolved:
                    self.on_entry_resolved(entry)
                
                return True
            return False
    
    def mark_failed(self, entry_id: str) -> bool:
        """Mark a reprocessing attempt as failed, return to pending."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                if entry.attempt_count >= self.max_reprocess_attempts:
                    entry.status = DLQEntryStatus.DISCARDED
                    self._total_discarded += 1
                else:
                    entry.status = DLQEntryStatus.PENDING
                return True
            return False
    
    def discard(
        self,
        entry_id: str,
        reason: Optional[str] = None
    ) -> bool:
        """Manually discard an entry."""
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.status = DLQEntryStatus.DISCARDED
                entry.resolution_notes = reason
                self._total_discarded += 1
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
        interval: timedelta = timedelta(minutes=5)
    ):
        self.dlq = dlq
        self.reprocess_fn = reprocess_fn
        self.batch_size = batch_size
        self.interval = interval
        self._running = False
        self._task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start the DLQ processor."""
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
                await self.reprocess_fn(entry.original_request)
                self.dlq.mark_resolved(entry.id, "Automatic reprocessing succeeded")
                logger.info(f"DLQ entry {entry.id} resolved")
            except Exception as e:
                self.dlq.mark_failed(entry.id)
                logger.warning(
                    f"DLQ entry {entry.id} reprocessing failed: {e}",
                    extra={"attempt": entry.attempt_count}
                )

# ============================================================================
# Block 13 (chapter listing #13)
# ============================================================================

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta, timezone
import threading
import statistics


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
        max_samples_per_pattern: int = 5
    ):
        self.window_size = window_size
        self.pattern_threshold = pattern_threshold
        self.max_samples_per_pattern = max_samples_per_pattern
        
        self._errors: List[AgentError] = []
        self._patterns: Dict[str, ErrorPattern] = {}
        self._lock = threading.Lock()
        
        # Correlation tracking
        self._component_correlations: Dict[Tuple[str, str], int] = defaultdict(int)
        self._temporal_buckets: Dict[str, List[AgentError]] = defaultdict(list)
    
    def record(self, error: AgentError) -> None:
        """Record an error for aggregation."""
        with self._lock:
            self._errors.append(error)
            self._cleanup_old_errors()
            self._update_patterns(error)
            self._update_correlations(error)
    
    def _cleanup_old_errors(self) -> None:
        """Remove errors outside the analysis window."""
        cutoff = datetime.now(timezone.utc) - self.window_size
        self._errors = [e for e in self._errors if e.timestamp > cutoff]
    
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
            if error.context.get("operation"):
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
        bucket_errors = self._temporal_buckets[bucket_key]
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
            return [
                pattern for pattern in self._patterns.values()
                if pattern.occurrence_count >= threshold
            ]
    
    def get_top_patterns(self, limit: int = 10) -> List[ErrorPattern]:
        """Get the most frequent error patterns."""
        patterns = self.get_patterns(min_occurrences=1)
        patterns.sort(key=lambda p: p.occurrence_count, reverse=True)
        return patterns[:limit]
    
    def get_correlations(
        self,
        min_correlation: int = 2
    ) -> List[Tuple[str, str, int]]:
        """Get correlated component failures."""
        with self._lock:
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
            patterns = self.get_patterns()
            correlations = self.get_correlations()
            
            return {
                "total_errors": len(self._errors),
                "unique_patterns": len(patterns),
                "error_rate_by_category": self.get_error_rate_by_category(),
                "top_patterns": [
                    {
                        "signature": p.message_signature[:100],
                        "category": p.category.name,
                        "component": p.component,
                        "count": p.occurrence_count,
                        "frequency_per_hour": round(p.frequency, 2)
                    }
                    for p in self.get_top_patterns(5)
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
async def get_product_recommendation(user_query: str) -> str:
    return await llm_circuit.execute_async(
        lambda: llm_client.complete(user_query),
        fallback=lambda: fallback_chain.execute({"query": user_query})
    )

# ============================================================================
# Block 15 (chapter listing #15)
# ============================================================================

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

async def handle_with_resilience(request: UserRequest) -> Response:
    fallback_chain = await create_production_fallback_chain()
    degradation_manager = setup_agent_degradation()
    
    try:
        # Check degradation level first
        if not degradation_manager.is_available("multi_step_reasoning"):
            return await simple_response(request)
        
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
        dlq.add(
            request=request.to_dict(),
            error_context=AgentErrorContext(
                error=classifier.classify(e),
                agent_id="orchestrator",
                agent_type="main"
            )
        )
        return await cached_response(request)
