"""
Rate Limiting and Cost Control

Code listings from Chapter 03, Book 2:
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

from dataclasses import dataclass, field
from typing import Optional
from collections import deque
import time
import threading


DEFAULT_REQUEST_WAIT_TIMEOUT_SECONDS = 30.0


@dataclass
class RequestRateLimiter:
    """
    Sliding window rate limiter for API requests.
    
    Uses a deque to track request timestamps within the current window,
    providing accurate rate limiting without the boundary issues of
    fixed-window approaches.
    """
    max_requests: int
    window_seconds: float
    _timestamps: deque = field(init=False)  # initialized in __post_init__ with maxlen
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.max_requests < 1:
            raise ValueError("max_requests must be positive")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        # Bound the deque so direct manipulation can't grow unbounded; the
        # sliding-window logic in try_acquire already keeps len <= max_requests,
        # so 2x max_requests is a safe upper bound for transient additions.
        self._timestamps = deque(maxlen=self.max_requests * 2)
    
    def _clean_old_timestamps(self, now: float) -> None:
        """Remove timestamps outside the current window."""
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
    
    def try_acquire(self) -> bool:
        """
        Attempt to acquire permission for a request.
        
        Returns True if the request is allowed, False if rate limited.
        Thread-safe for concurrent access.
        """
        with self._lock:
            now = time.monotonic()
            self._clean_old_timestamps(now)
            
            if len(self._timestamps) < self.max_requests:
                self._timestamps.append(now)
                return True
            return False

    def refund(self) -> bool:
        """
        Return one request slot after a failed multi-scope acquisition.

        This is intended for rollback paths that just called try_acquire().
        Expired timestamps are cleaned first; if the slot already aged out,
        there is nothing left to refund.
        """
        with self._lock:
            self._clean_old_timestamps(time.monotonic())
            if not self._timestamps:
                return False
            self._timestamps.pop()
            return True
    
    def wait_for_capacity(
        self,
        timeout: Optional[float] = DEFAULT_REQUEST_WAIT_TIMEOUT_SECONDS,
    ) -> bool:
        """
        Block until capacity is available or timeout is reached.
        
        Args:
            timeout: Maximum seconds to wait. Defaults to 30 seconds.
                Pass None only when the caller explicitly wants to wait
                indefinitely.
            
        Returns:
            True if capacity was acquired, False if timeout was reached.
        """
        start_time = time.monotonic()
        
        while True:
            if self.try_acquire():
                return True
            
            remaining_timeout = None
            if timeout is not None:
                elapsed = time.monotonic() - start_time
                remaining_timeout = timeout - elapsed
                if remaining_timeout <= 0:
                    return False
            
            # Calculate sleep time until oldest request expires
            with self._lock:
                if self._timestamps:
                    sleep_time = (
                        self._timestamps[0] + self.window_seconds - time.monotonic()
                    )
                    sleep_time = max(0.01, min(sleep_time, 1.0))
                else:
                    sleep_time = 0.01
            
            if remaining_timeout is not None:
                sleep_time = min(sleep_time, remaining_timeout)

            time.sleep(sleep_time)
    
    def get_remaining_capacity(self) -> int:
        """Return the number of requests available in the current window."""
        with self._lock:
            self._clean_old_timestamps(time.monotonic())
            return self.max_requests - len(self._timestamps)
    
    def get_reset_time(self) -> Optional[float]:
        """
        Return seconds until the next request slot becomes available.
        
        Returns None if capacity is available now.
        """
        with self._lock:
            self._clean_old_timestamps(time.monotonic())
            if len(self._timestamps) < self.max_requests:
                return None
            if self._timestamps:
                return self._timestamps[0] + self.window_seconds - time.monotonic()
            return None

# ============================================================================
# Block 2 (chapter listing #2)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from collections import deque
from enum import Enum
import time
import threading


class TokenType(Enum):
    """Token types with different cost implications."""
    INPUT = "input"
    OUTPUT = "output"
    CACHED = "cached"


@dataclass
class TokenBucket:
    """
    Token bucket implementation for rate limiting.
    
    Tokens are added at a constant rate up to a maximum capacity.
    This allows for controlled bursting while maintaining an
    average rate limit.
    """
    capacity: int
    refill_rate: float  # tokens per second
    _tokens: float = field(init=False)
    _last_refill: float = field(default_factory=time.monotonic)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        self._tokens = float(self.capacity)
    
    def _refill(self, now: float) -> None:
        """Add tokens based on elapsed time."""
        elapsed = now - self._last_refill
        self._tokens = min(
            self.capacity,
            self._tokens + elapsed * self.refill_rate
        )
        self._last_refill = now
    
    def try_consume(self, tokens: int) -> bool:
        """Attempt to consume tokens. Returns True if successful."""
        with self._lock:
            self._refill(time.monotonic())
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False
    
    def get_available_tokens(self) -> int:
        """Return available tokens; negative means overage debt is outstanding."""
        with self._lock:
            self._refill(time.monotonic())
            return int(self._tokens)

    def refund(self, tokens: int) -> None:
        """
        Return tokens to the bucket (e.g., to rollback a failed multi-bucket
        acquire). Takes the bucket's own lock and clamps to capacity so the
        bucket never exceeds its configured maximum.
        """
        with self._lock:
            self._tokens = min(self.capacity, self._tokens + tokens)

    def adjust(self, delta: int) -> None:
        """
        Adjust the bucket's available tokens by `delta` (positive or negative),
        clamped only at capacity. Negative balances are preserved as debt, so
        an underestimated request must be repaid by future refills before more
        tokens can be consumed.
        """
        with self._lock:
            self._tokens = min(float(self.capacity), self._tokens + delta)


@dataclass
class TokenRateLimiter:
    """
    Comprehensive token-based rate limiter for AI API calls.
    
    Tracks both input and output tokens separately, as many APIs
    have different rate limits for each. Also supports tracking
    cached tokens which may have different pricing.
    """
    max_input_tokens_per_minute: int
    max_output_tokens_per_minute: int
    max_total_tokens_per_minute: int
    burst_multiplier: float = 1.5  # Bucket capacity = 1.5x per-minute limit;
                                   # a fully-idle bucket allows an instantaneous
                                   # burst of 1.5x max_per_minute.
    
    _input_bucket: TokenBucket = field(init=False)
    _output_bucket: TokenBucket = field(init=False)
    _total_bucket: TokenBucket = field(init=False)
    _usage_history: deque = field(default_factory=lambda: deque(maxlen=1000))
    # Counter incremented whenever the bounded _usage_history evicts an
    # oldest entry; callers can read this for observability (e.g. emit
    # as a "rate_limiter.usage_history_dropped" gauge).
    _usage_history_dropped: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        # Bucket capacity allows for bursting, refill rate maintains average
        self._input_bucket = TokenBucket(
            capacity=int(self.max_input_tokens_per_minute * self.burst_multiplier),
            refill_rate=self.max_input_tokens_per_minute / 60.0
        )
        self._output_bucket = TokenBucket(
            capacity=int(self.max_output_tokens_per_minute * self.burst_multiplier),
            refill_rate=self.max_output_tokens_per_minute / 60.0
        )
        self._total_bucket = TokenBucket(
            capacity=int(self.max_total_tokens_per_minute * self.burst_multiplier),
            refill_rate=self.max_total_tokens_per_minute / 60.0
        )

    @staticmethod
    def _validate_token_counts(**token_counts: int) -> None:
        """Reject invalid token counts before touching bucket state."""
        for name, value in token_counts.items():
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
    
    def check_capacity(
        self,
        estimated_input_tokens: int,
        estimated_output_tokens: int
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if there's capacity for an API call without consuming tokens.
        
        Args:
            estimated_input_tokens: Expected input token count
            estimated_output_tokens: Expected output token count
            
        Returns:
            Tuple of (has_capacity, reason_if_limited)
        """
        self._validate_token_counts(
            estimated_input_tokens=estimated_input_tokens,
            estimated_output_tokens=estimated_output_tokens,
        )
        total = estimated_input_tokens + estimated_output_tokens
        
        if self._input_bucket.get_available_tokens() < estimated_input_tokens:
            return False, "Input token limit exceeded"
        if self._output_bucket.get_available_tokens() < estimated_output_tokens:
            return False, "Output token limit exceeded"
        if self._total_bucket.get_available_tokens() < total:
            return False, "Total token limit exceeded"
        
        return True, None
    
    def try_acquire(
        self,
        input_tokens: int,
        output_tokens: int
    ) -> Tuple[bool, Optional[str]]:
        """
        Attempt to acquire token capacity for an API call.
        
        This should be called before making the API call with estimated
        token counts. After the call completes, use record_actual_usage
        to adjust for any difference between estimated and actual usage.
        """
        self._validate_token_counts(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        with self._lock:
            has_capacity, reason = self.check_capacity(input_tokens, output_tokens)
            if not has_capacity:
                return False, reason
            
            total = input_tokens + output_tokens
            
            # Consume from all buckets
            if not self._input_bucket.try_consume(input_tokens):
                return False, "Input token limit exceeded"
            if not self._output_bucket.try_consume(output_tokens):
                # Rollback input consumption via the bucket's own lock/clamp.
                self._input_bucket.refund(input_tokens)
                return False, "Output token limit exceeded"
            if not self._total_bucket.try_consume(total):
                # Rollback both via each bucket's own lock/clamp.
                self._input_bucket.refund(input_tokens)
                self._output_bucket.refund(output_tokens)
                return False, "Total token limit exceeded"
            
            # Record usage; track FIFO evictions for observability.
            if len(self._usage_history) == self._usage_history.maxlen:
                self._usage_history_dropped += 1
            self._usage_history.append({
                "timestamp": time.monotonic(),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens
            })
            
            return True, None
    
    def record_actual_usage(
        self,
        estimated_input: int,
        estimated_output: int,
        actual_input: int,
        actual_output: int
    ) -> None:
        """
        Adjust token counts after an API call completes.
        
        If actual usage differs from estimated, this method adjusts
        the buckets accordingly. This is important for accurate rate
        limiting when actual token counts vary significantly from
        estimates.
        """
        self._validate_token_counts(
            estimated_input=estimated_input,
            estimated_output=estimated_output,
            actual_input=actual_input,
            actual_output=actual_output,
        )
        with self._lock:
            input_diff = actual_input - estimated_input
            output_diff = actual_output - estimated_output

            # Reconcile against each bucket through its own lock. Underestimates
            # subtract more tokens (delta<0) and may drive a bucket negative;
            # that debt is repaid by future refills before new work is admitted.
            self._input_bucket.adjust(-input_diff)
            self._output_bucket.adjust(-output_diff)
            self._total_bucket.adjust(-(input_diff + output_diff))
    
    def get_usage_stats(self, window_seconds: float = 60.0) -> Dict:
        """Return usage statistics for the specified time window."""
        now = time.monotonic()
        cutoff = now - window_seconds
        
        with self._lock:
            recent = [
                u for u in self._usage_history
                if u["timestamp"] >= cutoff
            ]
        
        if not recent:
            return {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "request_count": 0
            }
        
        return {
            "input_tokens": sum(u["input_tokens"] for u in recent),
            "output_tokens": sum(u["output_tokens"] for u in recent),
            "total_tokens": sum(
                u["input_tokens"] + u["output_tokens"] for u in recent
            ),
            "request_count": len(recent)
        }

    def refund(self, input_tokens: int, output_tokens: int) -> None:
        """
        Return tokens to all internal buckets. Used by HierarchicalRateLimiter
        to roll back partial acquisitions when a downstream limit fails. Each
        bucket clamps to its own capacity through its own lock.
        """
        self._validate_token_counts(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        with self._lock:
            self._input_bucket.refund(input_tokens)
            self._output_bucket.refund(output_tokens)
            self._total_bucket.refund(input_tokens + output_tokens)

# ============================================================================
# Block 3 (chapter listing #3)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any, Set
from enum import Enum
import time
import threading
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)


class LimitScope(Enum):
    """Hierarchy levels for rate limiting."""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    USER = "user"
    AGENT = "agent"
    SESSION = "session"


@dataclass
class RateLimitConfig:
    """Configuration for a single rate limit."""
    max_requests_per_minute: Optional[int] = None
    max_tokens_per_minute: Optional[int] = None
    max_tokens_per_hour: Optional[int] = None
    max_cost_per_hour: Optional[float] = None
    max_cost_per_day: Optional[float] = None
    burst_multiplier: float = 1.5


@dataclass
class HierarchicalRateLimiter:
    """
    Implements hierarchical rate limiting across multiple scopes.
    
    Requests must pass rate checks at all applicable levels of the
    hierarchy. This reduces cross-level exhaustion only when parent and
    child quotas are configured consistently, acquisition is atomic, and
    callers cannot bypass the limiter.
    """
    
    global_config: RateLimitConfig
    max_scopes: int = 10_000
    scope_ttl_seconds: float = 3600.0
    _limiters: Dict[str, TokenRateLimiter] = field(default_factory=dict)
    _request_limiters: Dict[str, RequestRateLimiter] = field(default_factory=dict)
    _configs: Dict[str, RateLimitConfig] = field(default_factory=dict)
    _parent_scopes: Dict[str, str] = field(default_factory=dict)
    _scope_last_seen: Dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        if self.max_scopes <= 0:
            raise ValueError("max_scopes must be positive")
        if self.scope_ttl_seconds <= 0:
            raise ValueError("scope_ttl_seconds must be positive")
        # Initialize global limiters
        self._initialize_limiters("global", self.global_config)

    def _delete_scope(self, key: str) -> None:
        """Drop all per-scope limiter state for a non-global key."""
        if key == "global":
            return
        self._limiters.pop(key, None)
        self._request_limiters.pop(key, None)
        self._configs.pop(key, None)
        self._parent_scopes.pop(key, None)
        self._scope_last_seen.pop(key, None)

    def _evict_inactive_scopes(self, now: Optional[float] = None) -> None:
        """Evict expired or least-recently-seen dynamic scopes."""
        now = time.monotonic() if now is None else now
        cutoff = now - self.scope_ttl_seconds

        for key, last_seen in list(self._scope_last_seen.items()):
            if last_seen < cutoff:
                self._delete_scope(key)

        while len(self._scope_last_seen) > self.max_scopes:
            oldest_key = min(
                self._scope_last_seen,
                key=lambda scope_key: self._scope_last_seen[scope_key],
            )
            self._delete_scope(oldest_key)

    def _touch_scope(self, key: str, now: Optional[float] = None) -> None:
        """Record recent use for configured non-global scopes."""
        if key != "global" and key in self._configs:
            self._scope_last_seen[key] = time.monotonic() if now is None else now

    @staticmethod
    def _scope_key(scope: LimitScope, identifier: str) -> str:
        """Build the internal key used for configured non-global scopes."""
        scope_name = scope.value if isinstance(scope, LimitScope) else str(scope)
        return f"{scope_name}:{identifier}"

    def _add_scope_with_ancestors(
        self,
        key: str,
        keys: List[str],
        seen: Set[str],
        visiting: Set[str]
    ) -> None:
        """Append a scope after its configured parents, avoiding duplicates."""
        if key in visiting:
            return

        visiting.add(key)
        parent_key = self._parent_scopes.get(key)
        if parent_key and parent_key not in seen:
            self._add_scope_with_ancestors(parent_key, keys, seen, visiting)
        visiting.remove(key)

        if key not in seen:
            keys.append(key)
            seen.add(key)

    def _keys_for_scopes(
        self,
        scopes: List[Tuple[LimitScope, str]]
    ) -> List[str]:
        """Return global plus each scope's full configured parent chain."""
        keys = ["global"]
        seen = {"global"}

        for scope, identifier in scopes:
            self._add_scope_with_ancestors(
                self._scope_key(scope, identifier),
                keys,
                seen,
                set(),
            )

        return keys
    
    def _initialize_limiters(self, key: str, config: RateLimitConfig) -> None:
        """Create rate limiters for a given configuration."""
        self._limiters.pop(key, None)
        self._request_limiters.pop(key, None)

        if key != "global":
            now = time.monotonic()
            self._evict_inactive_scopes(now)
            if key not in self._configs and len(self._scope_last_seen) >= self.max_scopes:
                oldest_key = min(
                    self._scope_last_seen,
                    key=lambda scope_key: self._scope_last_seen[scope_key],
                )
                self._delete_scope(oldest_key)
            self._scope_last_seen[key] = now

        if config.max_tokens_per_minute:
            self._limiters[key] = TokenRateLimiter(
                max_input_tokens_per_minute=config.max_tokens_per_minute // 2,
                max_output_tokens_per_minute=config.max_tokens_per_minute // 2,
                max_total_tokens_per_minute=config.max_tokens_per_minute,
                burst_multiplier=config.burst_multiplier
            )
        
        if config.max_requests_per_minute:
            self._request_limiters[key] = RequestRateLimiter(
                max_requests=config.max_requests_per_minute,
                window_seconds=60.0
            )
        
        self._configs[key] = config
    
    def configure_scope(
        self,
        scope: LimitScope,
        identifier: str,
        config: RateLimitConfig,
        parent_scope: Optional[LimitScope] = None,
        parent_identifier: Optional[str] = None
    ) -> None:
        """
        Configure rate limits for a specific scope.
        
        Args:
            scope: The hierarchy level (organization, user, agent, etc.)
            identifier: Unique identifier within that scope
            config: Rate limit configuration
            parent_scope: Optional parent scope for inheritance
            parent_identifier: Optional parent identifier
        """
        key = self._scope_key(scope, identifier)
        
        with self._lock:
            self._evict_inactive_scopes()
            self._initialize_limiters(key, config)
            
            # Store parent relationship for hierarchy traversal
            if parent_scope and parent_identifier:
                parent_key = self._scope_key(parent_scope, parent_identifier)
                self._parent_scopes[key] = parent_key
    
    def check_all_limits(
        self,
        scopes: List[Tuple[LimitScope, str]],
        estimated_input_tokens: int,
        estimated_output_tokens: int
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check rate limits across all specified scopes.
        
        Args:
            scopes: List of (scope, identifier) tuples to check,
                   ordered from most specific to most general
            estimated_input_tokens: Expected input tokens
            estimated_output_tokens: Expected output tokens
            
        Returns:
            Tuple of (allowed, scope_that_blocked, reason)
        """
        with self._lock:
            self._evict_inactive_scopes()
            keys_to_check = self._keys_for_scopes(scopes)
            for key in keys_to_check:
                self._touch_scope(key)
                # Check request limit
                if key in self._request_limiters:
                    if self._request_limiters[key].get_remaining_capacity() < 1:
                        return False, key, "Request rate limit exceeded"
                
                # Check token limit
                if key in self._limiters:
                    has_capacity, reason = self._limiters[key].check_capacity(
                        estimated_input_tokens,
                        estimated_output_tokens
                    )
                    if not has_capacity:
                        return False, key, reason
        
        return True, None, None
    
    def acquire(
        self,
        scopes: List[Tuple[LimitScope, str]],
        input_tokens: int,
        output_tokens: int
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Acquire rate limit capacity across all scopes.
        
        This is an atomic operation - either all scopes approve
        the request or none do (with rollback).
        """
        acquired_keys: List[Tuple[str, str]] = []

        with self._lock:
            self._evict_inactive_scopes()
            keys_to_check = self._keys_for_scopes(scopes)
            try:
                for key in keys_to_check:
                    self._touch_scope(key)
                    # Try to acquire request capacity
                    if key in self._request_limiters:
                        if not self._request_limiters[key].try_acquire():
                            raise RateLimitExceeded(key, "Request limit")
                        acquired_keys.append(("request", key))

                    # Try to acquire token capacity
                    if key in self._limiters:
                        success, reason = self._limiters[key].try_acquire(
                            input_tokens, output_tokens
                        )
                        if not success:
                            raise RateLimitExceeded(key, reason)
                        acquired_keys.append(("token", key))

                return True, None, None

            except RateLimitExceeded as e:
                # Rollback all capacity successfully acquired prior to the
                # failure so partial acquisitions do not leak quota.
                for limiter_type, key in reversed(acquired_keys):
                    if limiter_type == "request" and key in self._request_limiters:
                        self._request_limiters[key].refund()
                    elif limiter_type == "token" and key in self._limiters:
                        self._limiters[key].refund(input_tokens, output_tokens)
                logger.warning(
                    f"Rate limit exceeded at {e.scope}: {e.reason}"
                )
                return False, e.scope, e.reason

    def refund_acquisition(
        self,
        scopes: List[Tuple[LimitScope, str]],
        input_tokens: int,
        output_tokens: int
    ) -> None:
        """Return request and token capacity for work that never ran."""
        with self._lock:
            self._evict_inactive_scopes()
            keys_to_update = self._keys_for_scopes(scopes)
            for key in keys_to_update:
                self._touch_scope(key)
                request_limiter = self._request_limiters.get(key)
                if request_limiter is not None:
                    request_limiter.refund()

                token_limiter = self._limiters.get(key)
                if token_limiter is not None:
                    token_limiter.refund(input_tokens, output_tokens)

    def record_actual_usage(
        self,
        scopes: List[Tuple[LimitScope, str]],
        estimated_input_tokens: int,
        estimated_output_tokens: int,
        actual_input_tokens: int,
        actual_output_tokens: int
    ) -> None:
        """Reconcile estimated token acquisitions with actual usage."""
        with self._lock:
            self._evict_inactive_scopes()
            keys_to_update = self._keys_for_scopes(scopes)
            for key in keys_to_update:
                self._touch_scope(key)
                limiter = self._limiters.get(key)
                if limiter is None:
                    continue
                limiter.record_actual_usage(
                    estimated_input_tokens,
                    estimated_output_tokens,
                    actual_input_tokens,
                    actual_output_tokens,
                )
    
    @contextmanager
    def rate_limited_call(
        self,
        scopes: List[Tuple[LimitScope, str]],
        estimated_input_tokens: int,
        estimated_output_tokens: int
    ):
        """
        Context manager for rate-limited API calls.
        
        Usage:
            with limiter.rate_limited_call(scopes, 1000, 500) as acquired:
                if acquired:
                    result = make_api_call()
                    limiter.record_actual_usage(...)
        """
        success, blocked_scope, reason = self.acquire(
            scopes, estimated_input_tokens, estimated_output_tokens
        )
        
        if not success:
            yield RateLimitResult(
                allowed=False,
                blocked_scope=blocked_scope,
                reason=reason
            )
        else:
            yield RateLimitResult(allowed=True)


class RateLimitExceeded(Exception):
    """Raised when a rate limit is exceeded during acquisition."""
    def __init__(self, scope: str, reason: str):
        self.scope = scope
        self.reason = reason
        super().__init__(f"Rate limit exceeded at {scope}: {reason}")


@dataclass
class RateLimitResult:
    """Result of a rate limit check or acquisition."""
    allowed: bool
    blocked_scope: Optional[str] = None
    reason: Optional[str] = None

# ============================================================================
# Block 4 (chapter listing #4)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Tuple
from enum import Enum
from datetime import datetime, timedelta, timezone
import threading
import json
import logging

logger = logging.getLogger(__name__)


class BudgetPeriod(Enum):
    """Time periods for budget allocation.

    Notes:
        FIXED_30_DAYS is a rolling 30-day window, not a calendar month.
        Choose this when the deployment treats spend as a fixed-length
        rolling budget (e.g., a 30-day burn cap that resets relative to
        the period_start timestamp). For calendar-aligned billing
        (1st-of-month rollover, variable 28/29/30/31-day cycle), wire
        a calendar-aware period upstream and pass the resolved start
        and end as explicit timestamps; see operator notes in the
        chapter text.
    """
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    FIXED_30_DAYS = "fixed_30_days"


@dataclass
class ModelPricing:
    """Pricing information for an AI model."""
    model_id: str
    input_cost_per_1k_tokens: float
    output_cost_per_1k_tokens: float
    cached_input_cost_per_1k_tokens: Optional[float] = None
    
    def calculate_cost(
        self,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0
    ) -> float:
        """Calculate the cost for a given token usage."""
        if input_tokens < 0 or output_tokens < 0 or cached_tokens < 0:
            raise ValueError("Token counts must be non-negative")

        billable_cached_tokens = min(cached_tokens, input_tokens)
        uncached_input_tokens = input_tokens - billable_cached_tokens
        cached_rate = (
            self.cached_input_cost_per_1k_tokens
            if self.cached_input_cost_per_1k_tokens is not None
            else self.input_cost_per_1k_tokens
        )

        input_cost = (
            uncached_input_tokens / 1000
        ) * self.input_cost_per_1k_tokens
        cached_cost = (billable_cached_tokens / 1000) * cached_rate
        output_cost = (output_tokens / 1000) * self.output_cost_per_1k_tokens
        
        return input_cost + output_cost + cached_cost


# Example pricing - ILLUSTRATIVE ONLY
# Treat these numbers as local configuration placeholders for tests and
# examples. Load production rates from your provider contract, region, and
# model configuration instead of relying on this static table.
STANDARD_PRICING = {
    "claude-3-opus": ModelPricing(
        model_id="claude-3-opus",
        input_cost_per_1k_tokens=0.015,
        output_cost_per_1k_tokens=0.075,
        cached_input_cost_per_1k_tokens=0.00375
    ),
    "claude-3-sonnet": ModelPricing(
        model_id="claude-3-sonnet",
        input_cost_per_1k_tokens=0.003,
        output_cost_per_1k_tokens=0.015,
        cached_input_cost_per_1k_tokens=0.00075
    ),
    "claude-3-haiku": ModelPricing(
        model_id="claude-3-haiku",
        input_cost_per_1k_tokens=0.00025,
        output_cost_per_1k_tokens=0.00125,
        cached_input_cost_per_1k_tokens=0.0000625
    ),
    "gpt-4-turbo": ModelPricing(
        model_id="gpt-4-turbo",
        input_cost_per_1k_tokens=0.01,
        output_cost_per_1k_tokens=0.03
    ),
    "gpt-4o": ModelPricing(
        model_id="gpt-4o",
        input_cost_per_1k_tokens=0.005,
        output_cost_per_1k_tokens=0.015
    ),
}


@dataclass
class Budget:
    """Represents a budget allocation for a specific scope and period."""
    scope_type: str  # "global", "organization", "user", "agent"
    scope_id: str
    period: BudgetPeriod
    allocated_amount: float
    spent_amount: float = 0.0
    reserved_amount: float = 0.0
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alerts_sent: Dict[str, bool] = field(default_factory=dict)
    
    @property
    def remaining(self) -> float:
        return max(
            0.0,
            self.allocated_amount - self.spent_amount - self.reserved_amount,
        )
    
    @property
    def utilization_percent(self) -> float:
        if self.allocated_amount == 0:
            return 100.0
        return (self.spent_amount / self.allocated_amount) * 100
    
    def is_period_expired(self) -> bool:
        """Check if the current budget period has ended."""
        now = datetime.now(timezone.utc)
        if self.period == BudgetPeriod.HOURLY:
            return now >= self.period_start + timedelta(hours=1)
        elif self.period == BudgetPeriod.DAILY:
            return now >= self.period_start + timedelta(days=1)
        elif self.period == BudgetPeriod.WEEKLY:
            return now >= self.period_start + timedelta(weeks=1)
        elif self.period == BudgetPeriod.FIXED_30_DAYS:
            return now >= self.period_start + timedelta(days=30)
        return False
    
    def reset_if_expired(self) -> bool:
        """Reset budget if period has expired. Returns True if reset."""
        if self.is_period_expired():
            self.spent_amount = 0.0
            self.reserved_amount = 0.0
            self.period_start = datetime.now(timezone.utc)
            self.alerts_sent = {}
            return True
        return False


@dataclass
class BudgetReservation:
    """Estimated spend held before an API call completes."""
    reservation_id: str
    scopes: List[Tuple[str, str]]
    budget_entries: List[Tuple[str, str, BudgetPeriod]]
    estimated_cost: float
    expires_at: datetime
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BudgetManager:
    """
    Manages budget allocation and enforcement across the system.
    
    Provides hierarchical budget control with automatic period resets,
    spending projections, and alert thresholds.
    """
    
    pricing: Dict[str, ModelPricing] = field(
        default_factory=lambda: STANDARD_PRICING.copy()
    )
    alert_callback: Optional[Callable[[str, Dict], None]] = None
    reservation_ttl_seconds: float = 300.0
    max_active_reservations: int = 10_000
    
    _budgets: Dict[str, Budget] = field(default_factory=dict)
    _reservations: Dict[str, BudgetReservation] = field(default_factory=dict)
    # Bounded so a high-traffic gateway cannot OOM on history growth; the
    # alerting / projection paths only need recent samples.
    _spending_history: deque = field(default_factory=lambda: deque(maxlen=10_000))
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    # Alert thresholds (percentage of budget)
    _alert_thresholds: List[int] = field(
        default_factory=lambda: [50, 75, 90, 95, 100]
    )
    
    def _budget_key(
        self,
        scope_type: str,
        scope_id: str,
        period: BudgetPeriod
    ) -> str:
        """Generate a unique key for a budget."""
        return f"{scope_type}:{scope_id}:{period.value}"

    def _release_reservation_locked(
        self,
        reservation: BudgetReservation
    ) -> None:
        """Release a reservation hold. Caller must hold _lock."""
        for scope_type, scope_id, period in reservation.budget_entries:
            key = self._budget_key(scope_type, scope_id, period)
            budget = self._budgets.get(key)
            if budget is None:
                continue
            budget.reset_if_expired()
            budget.reserved_amount = max(
                0.0,
                budget.reserved_amount - reservation.estimated_cost,
            )

    def _cleanup_expired_reservations_locked(
        self,
        now: datetime
    ) -> int:
        """Release expired reservation leases. Caller must hold _lock."""
        expired_ids = [
            reservation_id
            for reservation_id, reservation in self._reservations.items()
            if reservation.expires_at <= now
        ]
        for reservation_id in expired_ids:
            reservation = self._reservations.pop(reservation_id)
            self._release_reservation_locked(reservation)
        return len(expired_ids)

    def cleanup_expired_reservations(self) -> int:
        """Release expired reservation leases and return the cleanup count."""
        with self._lock:
            return self._cleanup_expired_reservations_locked(
                datetime.now(timezone.utc)
            )
    
    def allocate_budget(
        self,
        scope_type: str,
        scope_id: str,
        period: BudgetPeriod,
        amount: float
    ) -> Budget:
        # 1. Allocation: create or update the tenant's budget envelope.
        """
        Allocate a budget for a specific scope and period.
        
        If a budget already exists, this updates the allocation.
        Existing spend is preserved.
        """
        key = self._budget_key(scope_type, scope_id, period)
        
        with self._lock:
            self._cleanup_expired_reservations_locked(datetime.now(timezone.utc))

            if key in self._budgets:
                self._budgets[key].allocated_amount = amount
                self._budgets[key].reset_if_expired()
            else:
                self._budgets[key] = Budget(
                    scope_type=scope_type,
                    scope_id=scope_id,
                    period=period,
                    allocated_amount=amount
                )
            
            return self._budgets[key]
    
    def check_budget(
        self,
        scope_type: str,
        scope_id: str,
        period: BudgetPeriod,
        estimated_cost: float
    ) -> Tuple[bool, float, str]:
        # 2. Enforcement: check estimated spend before work starts.
        """
        Check if a cost is within budget.
        
        Returns:
            Tuple of (within_budget, remaining_after, message)
        """
        key = self._budget_key(scope_type, scope_id, period)
        
        with self._lock:
            self._cleanup_expired_reservations_locked(datetime.now(timezone.utc))

            if key not in self._budgets:
                # No budget configured means no limit
                return True, float('inf'), "No budget configured"
            
            budget = self._budgets[key]
            budget.reset_if_expired()
            
            remaining_after = budget.remaining - estimated_cost
            
            if remaining_after < 0:
                return (
                    False,
                    budget.remaining,
                    f"Would exceed {period.value} budget by ${-remaining_after:.4f}"
                )
            
            return True, remaining_after, "Within budget"

    def reserve_spend(
        self,
        scopes: List[Tuple[str, str]],
        periods: List[BudgetPeriod],
        estimated_cost: float
    ) -> Tuple[bool, Optional[BudgetReservation], str]:
        """
        Atomically check and hold estimated spend for a pending request.

        The reservation prevents concurrent requests from all passing the same
        pre-check and later overspending a hard budget. Budgets that are not
        configured are skipped, preserving the existing "no budget means no
        limit" behavior.
        """
        import uuid

        with self._lock:
            now = datetime.now(timezone.utc)
            self._cleanup_expired_reservations_locked(now)

            budget_entries: List[Tuple[str, str, BudgetPeriod]] = []

            for scope_type, scope_id in scopes:
                for period in periods:
                    key = self._budget_key(scope_type, scope_id, period)
                    budget = self._budgets.get(key)
                    if budget is None:
                        continue

                    budget.reset_if_expired()
                    remaining_after = budget.remaining - estimated_cost
                    if remaining_after < 0:
                        return (
                            False,
                            None,
                            f"Would exceed {period.value} budget by "
                            f"${-remaining_after:.4f}",
                        )
                    budget_entries.append((scope_type, scope_id, period))

            if not budget_entries:
                return True, None, "No budget configured"

            if self.max_active_reservations <= 0:
                return False, None, "Budget reservations are disabled"
            if len(self._reservations) >= self.max_active_reservations:
                return (
                    False,
                    None,
                    "Too many active budget reservations; retry after leases expire",
                )

            for scope_type, scope_id, period in budget_entries:
                key = self._budget_key(scope_type, scope_id, period)
                self._budgets[key].reserved_amount += estimated_cost

            reservation = BudgetReservation(
                reservation_id=str(uuid.uuid4()),
                scopes=list(scopes),
                budget_entries=budget_entries,
                estimated_cost=estimated_cost,
                expires_at=now + timedelta(seconds=self.reservation_ttl_seconds),
            )
            self._reservations[reservation.reservation_id] = reservation
            return True, reservation, "Reserved"

    def refund_reservation(self, reservation_id: str) -> bool:
        """Release estimated spend for a request that did not complete."""
        with self._lock:
            self._cleanup_expired_reservations_locked(datetime.now(timezone.utc))
            reservation = self._reservations.pop(reservation_id, None)
            if reservation is None:
                return False

            self._release_reservation_locked(reservation)
            return True

    def commit_reservation(
        self,
        reservation_id: str,
        actual_cost: float,
        scope_type: str,
        scope_id: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Convert a pending budget reservation into committed spend.

        The estimated hold is released and the actual cost is recorded under
        the same lock, so concurrent request admission observes the transition
        atomically.
        """
        metadata = metadata or {}

        with self._lock:
            self._cleanup_expired_reservations_locked(datetime.now(timezone.utc))
            reservation = self._reservations.pop(reservation_id, None)
            if reservation is None:
                return False

            for entry in reservation.budget_entries:
                budget_scope_type, budget_scope_id, period = entry
                key = self._budget_key(budget_scope_type, budget_scope_id, period)
                budget = self._budgets.get(key)
                if budget is None:
                    continue

                budget.reset_if_expired()
                budget.reserved_amount = max(
                    0.0,
                    budget.reserved_amount - reservation.estimated_cost,
                )
                budget.spent_amount += actual_cost
                self._check_alerts(budget)

            self._append_spending_history(
                reservation.scopes,
                scope_type,
                scope_id,
                model_id,
                input_tokens,
                output_tokens,
                cached_tokens,
                actual_cost,
                metadata,
            )

            return True

    def _spend_scope_chain(
        self,
        scope_type: str,
        scope_id: str,
        metadata: Dict
    ) -> List[Tuple[str, str]]:
        """Return the child-to-parent budget scopes charged for one event."""
        scopes: List[Tuple[str, str]] = []

        def add(scope: str, identifier: object) -> None:
            if identifier is None:
                return
            candidate = (scope, str(identifier))
            if candidate not in scopes:
                scopes.append(candidate)

        add(scope_type, scope_id)

        org_id = metadata.get("org_id") or metadata.get("organization_id")
        user_id = metadata.get("user_id")

        if scope_type == "agent":
            add("user", user_id)
            add("organization", org_id)
        elif scope_type == "user":
            add("organization", org_id)

        global_scope_id = metadata.get("global_scope_id", "system")
        add("global", global_scope_id)

        return scopes

    def _append_spending_history(
        self,
        spend_scopes: List[Tuple[str, str]],
        source_scope_type: str,
        source_scope_id: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int,
        cost: float,
        metadata: Dict
    ) -> None:
        """Append per-scope spend samples. Caller must hold _lock."""
        timestamp = datetime.now(timezone.utc).isoformat()
        for budget_scope_type, budget_scope_id in spend_scopes:
            self._spending_history.append({
                "timestamp": timestamp,
                "scope_type": budget_scope_type,
                "scope_id": budget_scope_id,
                "source_scope_type": source_scope_type,
                "source_scope_id": source_scope_id,
                "model_id": model_id,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cached_tokens": cached_tokens,
                "cost": cost,
                "metadata": metadata
            })
    
    def record_spend(
        self,
        scope_type: str,
        scope_id: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
        metadata: Optional[Dict] = None
    ) -> float:
        # 3. Spend recording: post actual model usage after execution.
        """
        Record spending against budgets.
        
        Records against all configured budget periods for the scope
        and its parent scopes, then checks alert thresholds.
        
        Returns the calculated cost.
        """
        metadata = metadata or {}

        # Calculate cost
        pricing = self.pricing.get(model_id)
        if not pricing:
            logger.warning(f"No pricing found for model {model_id}")
            # Use a conservative estimate
            cost = ((input_tokens + output_tokens) / 1000) * 0.01
        else:
            cost = pricing.calculate_cost(input_tokens, output_tokens, cached_tokens)

        spend_scopes = self._spend_scope_chain(scope_type, scope_id, metadata)

        with self._lock:
            self._cleanup_expired_reservations_locked(datetime.now(timezone.utc))

            # Record against all budget periods for every enforced scope.
            for budget_scope_type, budget_scope_id in spend_scopes:
                for period in BudgetPeriod:
                    key = self._budget_key(
                        budget_scope_type, budget_scope_id, period
                    )
                    if key in self._budgets:
                        budget = self._budgets[key]
                        budget.reset_if_expired()
                        budget.spent_amount += cost

                        # Check alert thresholds
                        self._check_alerts(budget)

            self._append_spending_history(
                spend_scopes,
                scope_type,
                scope_id,
                model_id,
                input_tokens,
                output_tokens,
                cached_tokens,
                cost,
                metadata,
            )
        
        return cost
    
    def _check_alerts(self, budget: Budget) -> None:
        """Check and send alerts for budget thresholds."""
        utilization = budget.utilization_percent
        
        for threshold in self._alert_thresholds:
            alert_key = f"threshold_{threshold}"
            
            if utilization >= threshold and not budget.alerts_sent.get(alert_key):
                budget.alerts_sent[alert_key] = True
                
                if self.alert_callback:
                    self.alert_callback(
                        "budget_threshold",
                        {
                            "scope_type": budget.scope_type,
                            "scope_id": budget.scope_id,
                            "period": budget.period.value,
                            "threshold_percent": threshold,
                            "current_percent": utilization,
                            "spent": budget.spent_amount,
                            "allocated": budget.allocated_amount,
                            "remaining": budget.remaining
                        }
                    )
    
    def get_budget_status(
        self,
        scope_type: str,
        scope_id: str
    ) -> Dict[str, Dict]:
        # 4. Reporting: expose current allocation, spend, and remaining balance.
        """Get status of all budgets for a scope."""
        status = {}
        
        with self._lock:
            self._cleanup_expired_reservations_locked(datetime.now(timezone.utc))

            for period in BudgetPeriod:
                key = self._budget_key(scope_type, scope_id, period)
                if key in self._budgets:
                    budget = self._budgets[key]
                    budget.reset_if_expired()
                    
                    status[period.value] = {
                        "allocated": budget.allocated_amount,
                        "spent": budget.spent_amount,
                        "reserved": budget.reserved_amount,
                        "remaining": budget.remaining,
                        "utilization_percent": budget.utilization_percent,
                        "period_start": budget.period_start.isoformat()
                    }
        
        return status
    
    def project_spend(
        self,
        scope_type: str,
        scope_id: str,
        period: BudgetPeriod,
        hours_to_project: int = 24
    ) -> Dict:
        # 5. Projection: estimate end-of-period spend from recent samples.
        """
        Project future spending based on recent patterns.
        
        Uses spending history to estimate future costs.
        """
        key = self._budget_key(scope_type, scope_id, period)
        
        with self._lock:
            if key not in self._budgets:
                return {"error": "No budget configured"}
            
            budget = self._budgets[key]
            
            # Get recent spending for this scope
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_to_project)
            recent_spend = [
                s for s in self._spending_history
                if (s["scope_type"] == scope_type and
                    s["scope_id"] == scope_id and
                    datetime.fromisoformat(s["timestamp"]) >= cutoff)
            ]
            
            if not recent_spend:
                return {
                    "current_spend": budget.spent_amount,
                    "projected_spend": budget.spent_amount,
                    "projection_confidence": "low",
                    "message": "Insufficient history for projection"
                }
            
            # Calculate hourly rate
            total_recent = sum(s["cost"] for s in recent_spend)
            hourly_rate = total_recent / hours_to_project
            
            # Project to end of period
            if period == BudgetPeriod.HOURLY:
                hours_remaining = 1 - (
                    (datetime.now(timezone.utc) - budget.period_start).total_seconds() / 3600
                )
            elif period == BudgetPeriod.DAILY:
                hours_remaining = 24 - (
                    (datetime.now(timezone.utc) - budget.period_start).total_seconds() / 3600
                )
            elif period == BudgetPeriod.WEEKLY:
                hours_remaining = 168 - (
                    (datetime.now(timezone.utc) - budget.period_start).total_seconds() / 3600
                )
            else:  # FIXED_30_DAYS
                hours_remaining = 720 - (
                    (datetime.now(timezone.utc) - budget.period_start).total_seconds() / 3600
                )
            
            projected_additional = hourly_rate * max(0, hours_remaining)
            projected_total = budget.spent_amount + projected_additional
            
            return {
                "current_spend": budget.spent_amount,
                "projected_spend": projected_total,
                "hourly_rate": hourly_rate,
                "hours_remaining": hours_remaining,
                "will_exceed_budget": projected_total > budget.allocated_amount,
                "projected_overage": max(0, projected_total - budget.allocated_amount),
                "projection_confidence": "medium" if len(recent_spend) > 10 else "low"
            }

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any, Tuple
from enum import Enum
from collections import deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import statistics
import time
import logging
import uuid

logger = logging.getLogger(__name__)

# Bounds for in-memory degradation state. Queue overflow is rejected explicitly
# so the caller can fall through to another degradation strategy; cached
# responses still use bounded FIFO eviction.
MAX_QUEUE_SIZE = 10_000
MAX_CACHE_SIZE = 1024


class DegradationStrategy(Enum):
    """Strategies for handling rate limit or budget exhaustion."""
    QUEUE = "queue"           # Queue requests for later processing
    DOWNGRADE_MODEL = "downgrade_model"  # Use a cheaper model
    REDUCE_QUALITY = "reduce_quality"    # Reduce output quality/length
    CACHE_FALLBACK = "cache_fallback"    # Return cached results
    REJECT = "reject"         # Reject the request entirely
    PARTIAL = "partial"       # Return partial results


@dataclass
class ModelTier:
    """Represents a model tier for degradation purposes."""
    model_id: str
    cost_multiplier: float
    quality_score: float  # 0-1, higher is better
    
    
MODEL_TIERS = [
    ModelTier("claude-3-opus", 1.0, 1.0),
    ModelTier("claude-3-sonnet", 0.2, 0.85),
    ModelTier("claude-3-haiku", 0.017, 0.7),
]


@dataclass
class DegradationConfig:
    """Configuration for graceful degradation behavior."""
    # Ordered list of strategies to try
    strategies: List[DegradationStrategy] = field(
        default_factory=lambda: [
            DegradationStrategy.DOWNGRADE_MODEL,
            DegradationStrategy.REDUCE_QUALITY,
            DegradationStrategy.QUEUE,
            DegradationStrategy.REJECT
        ]
    )
    
    # Model downgrade path
    model_downgrade_path: List[str] = field(
        default_factory=lambda: [
            "claude-3-opus",
            "claude-3-sonnet",
            "claude-3-haiku"
        ]
    )
    
    # Maximum queue wait time in seconds
    max_queue_wait: float = 300.0

    # Maximum queued requests before queueing fails explicitly
    max_queue_size: int = MAX_QUEUE_SIZE

    # Maximum cached responses retained for fallback before FIFO eviction
    max_cache_size: int = MAX_CACHE_SIZE

    # Per-item processor timeout for queued work. Set to None only when the
    # processor has its own deadline enforcement.
    queue_item_timeout_seconds: Optional[float] = 30.0

    # Bounded worker count for queued processors that need timeout supervision.
    # Timed-out synchronous processors cannot be killed safely, so each running
    # processor keeps one slot until it returns or cooperatively observes
    # deadline_at.
    queue_processor_workers: int = 4
    
    # Cache TTL for fallback responses
    cache_ttl_seconds: float = 3600.0
    
    # Quality reduction settings
    max_output_tokens_degraded: int = 1000
    
    # Whether to notify users of degradation
    notify_user: bool = True


@dataclass
class GracefulDegradationManager:
    """
    Manages graceful degradation when rate limits or budgets are exhausted.
    
    Provides multiple strategies for maintaining service quality while
    respecting resource constraints.
    """
    
    config: DegradationConfig = field(default_factory=DegradationConfig)
    rate_limiter: Optional[HierarchicalRateLimiter] = None
    budget_manager: Optional[BudgetManager] = None
    
    # Bounded manually in _try_queue() so overflow is visible rather than
    # silently evicting the oldest queued request.
    _request_queue: deque = field(default_factory=deque)
    _response_cache: "OrderedDict[str, Dict]" = field(
        default_factory=OrderedDict
    )
    _degradation_stats: Dict[str, int] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _queue_processor_executor: Optional[ThreadPoolExecutor] = field(
        default=None,
        init=False,
        repr=False,
    )
    _queue_processor_slots: threading.BoundedSemaphore = field(
        init=False,
        repr=False,
    )
    # Rolling window of recent processor latencies in seconds. Bounded at 100
    # samples so a long-running process keeps a representative recent view
    # instead of an all-time average dragged by stale tail latency.
    _processing_latency: "deque[float]" = field(
        default_factory=lambda: deque(maxlen=100),
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.config.max_queue_size < 1:
            raise ValueError("max_queue_size must be at least 1")
        if (
            self.config.queue_item_timeout_seconds is not None
            and self.config.queue_item_timeout_seconds <= 0
        ):
            raise ValueError("queue_item_timeout_seconds must be positive or None")
        if self.config.queue_processor_workers < 1:
            raise ValueError("queue_processor_workers must be at least 1")
        self._queue_processor_slots = threading.BoundedSemaphore(
            self.config.queue_processor_workers
        )
    
    def handle_rate_limit(
        self,
        original_request: Dict,
        blocked_scope: str,
        reason: str
    ) -> Dict:
        """
        Handle a rate-limited request using configured degradation strategies.
        
        Returns a response dict with either the degraded result or
        instructions for the caller.
        """
        for strategy in self.config.strategies:
            result = self._try_strategy(strategy, original_request, reason)
            if result["success"]:
                self._record_degradation(strategy.value)
                return result
        
        # All strategies failed
        return {
            "success": False,
            "strategy": "none",
            "error": "All degradation strategies exhausted",
            "original_reason": reason,
            "retry_after": self._calculate_retry_after(blocked_scope)
        }
    
    def _try_strategy(
        self,
        strategy: DegradationStrategy,
        request: Dict,
        reason: str
    ) -> Dict:
        """Attempt a specific degradation strategy."""
        
        if strategy == DegradationStrategy.DOWNGRADE_MODEL:
            return self._try_model_downgrade(request)
        
        elif strategy == DegradationStrategy.REDUCE_QUALITY:
            return self._try_quality_reduction(request)
        
        elif strategy == DegradationStrategy.QUEUE:
            return self._try_queue(request)
        
        elif strategy == DegradationStrategy.CACHE_FALLBACK:
            return self._try_cache_fallback(request)
        
        elif strategy == DegradationStrategy.PARTIAL:
            return self._try_partial_response(request)
        
        elif strategy == DegradationStrategy.REJECT:
            return {
                "success": False,
                "strategy": "reject",
                "message": f"Request rejected: {reason}"
            }
        
        return {"success": False, "strategy": "unknown"}
    
    def _try_model_downgrade(self, request: Dict) -> Dict:
        """Attempt to use a cheaper model."""
        current_model = request.get("model", "claude-3-opus")
        
        # Find current position in downgrade path
        try:
            current_index = self.config.model_downgrade_path.index(current_model)
        except ValueError:
            current_index = 0
        
        # Try each subsequent model
        for i in range(current_index + 1, len(self.config.model_downgrade_path)):
            downgraded_model = self.config.model_downgrade_path[i]

            modified_request = {**request, "model": downgraded_model}
            reserved, governance_metadata, _ = self._reserve_capacity_for_request(
                modified_request, downgraded_model
            )
            if reserved:
                modified_request["governance"] = self._merge_governance_metadata(
                    modified_request, governance_metadata or {}
                )
                logger.info(
                    f"Downgrading from {current_model} to {downgraded_model}"
                )
                return {
                    "success": True,
                    "strategy": "downgrade_model",
                    "original_model": current_model,
                    "downgraded_model": downgraded_model,
                    "modified_request": modified_request,
                    "governance": modified_request["governance"],
                    "user_message": (
                        f"Using {downgraded_model} due to rate limits"
                        if self.config.notify_user else None
                    )
                }
        
        return {"success": False, "strategy": "downgrade_model"}
    
    def _try_quality_reduction(self, request: Dict) -> Dict:
        """Reduce output quality to lower costs."""
        modified_request = request.copy()
        
        # Reduce max tokens
        original_max_tokens = request.get("max_tokens", 4096)
        reduced_max_tokens = min(
            original_max_tokens,
            self.config.max_output_tokens_degraded
        )
        modified_request["max_tokens"] = reduced_max_tokens
        estimated_input, estimated_output = self._estimated_tokens_for_request(
            modified_request
        )
        estimated_output = min(estimated_output, reduced_max_tokens)
        modified_request["estimated_input_tokens"] = estimated_input
        modified_request["estimated_output_tokens"] = estimated_output
        
        # Add instruction to be concise
        original_system = request.get("system", "")
        modified_request["system"] = (
            original_system +
            "\n\nIMPORTANT: Due to resource constraints, provide a concise "
            "response. Focus on the most critical information only."
        )

        model = modified_request.get("model", "claude-3-opus")
        reserved, governance_metadata, reason = self._reserve_capacity_for_request(
            modified_request, model
        )
        if not reserved:
            return {
                "success": False,
                "strategy": "reduce_quality",
                "reason": reason
            }
        modified_request["governance"] = self._merge_governance_metadata(
            modified_request, governance_metadata or {}
        )
        
        return {
            "success": True,
            "strategy": "reduce_quality",
            "original_max_tokens": original_max_tokens,
            "reduced_max_tokens": reduced_max_tokens,
            "modified_request": modified_request,
            "governance": modified_request["governance"],
            "user_message": (
                "Response may be shorter due to current load"
                if self.config.notify_user else None
            )
        }
    
    def _try_queue(self, request: Dict) -> Dict:
        """Queue the request for later processing."""
        with self._lock:
            if len(self._request_queue) >= self.config.max_queue_size:
                queue_size = len(self._request_queue)
                logger.warning(
                    "Degradation queue full; rejecting queue strategy "
                    "without evicting pending requests"
                )
                self._record_degradation("queue_full")
                return {
                    "success": False,
                    "strategy": "queue",
                    "reason": "queue_full",
                    "queue_size": queue_size,
                    "max_queue_size": self.config.max_queue_size,
                }

            queued_at = time.monotonic()
            queue_entry = {
                "request": request,
                "queued_at": queued_at,
                "expires_at": queued_at + self.config.max_queue_wait
            }

            self._request_queue.append(queue_entry)

            queue_position = len(self._request_queue)
            estimated_wait = self._estimate_queue_wait(queue_position)

            return {
                "success": True,
                "strategy": "queue",
                "queue_position": queue_position,
                "estimated_wait_seconds": estimated_wait,
                "user_message": (
                    f"Request queued. Estimated wait: {int(estimated_wait)}s"
                    if self.config.notify_user else None
                )
            }
    
    def _try_cache_fallback(self, request: Dict) -> Dict:
        """Return cached result if available."""
        cache_key = self._compute_cache_key(request)

        with self._lock:
            if cache_key in self._response_cache:
                cached = self._response_cache[cache_key]

                # Check if cache is still valid
                if time.monotonic() - cached["cached_at"] < self.config.cache_ttl_seconds:
                    return {
                        "success": True,
                        "strategy": "cache_fallback",
                        "cached_response": cached["response"],
                        "cached_at": cached["cached_at"],
                        "user_message": (
                            "Returning cached response due to rate limits"
                            if self.config.notify_user else None
                        )
                    }
        
        return {"success": False, "strategy": "cache_fallback"}
    
    def _try_partial_response(self, request: Dict) -> Dict:
        """Return a partial response with available information."""
        # This would integrate with streaming APIs to return
        # whatever was generated before hitting limits
        return {"success": False, "strategy": "partial"}

    def _estimated_tokens_for_request(self, request: Dict) -> Tuple[int, int]:
        """Return non-negative estimated input and output tokens."""
        estimated_input = max(
            0,
            int(request.get("estimated_input_tokens", 1000))
        )
        estimated_output = max(
            0,
            int(request.get("estimated_output_tokens", 500))
        )
        return estimated_input, estimated_output

    def _estimated_cost_for_model(
        self,
        model: str,
        estimated_input: int,
        estimated_output: int
    ) -> float:
        """Estimate request cost for budget reservation."""
        pricing = (
            self.budget_manager.pricing.get(model)
            if self.budget_manager is not None
            else None
        )
        if pricing:
            return pricing.calculate_cost(estimated_input, estimated_output, 0)
        return ((estimated_input + estimated_output) / 1000) * 0.01

    def _merge_governance_metadata(
        self,
        request: Dict,
        governance_metadata: Dict
    ) -> Dict:
        """Attach admission metadata without discarding caller metadata."""
        existing = request.get("governance", {})
        merged = dict(existing) if isinstance(existing, dict) else {}
        merged.update(governance_metadata)
        return merged

    def _reserve_capacity_for_request(
        self,
        request: Dict,
        model: str
    ) -> Tuple[bool, Optional[Dict], str]:
        """
        Reserve budget and acquire rate-limit capacity for a degraded request.

        Budget reservation happens before rate-limit acquisition so a rate
        failure can release the reservation and leave no partial admission.
        """
        estimated_input, estimated_output = self._estimated_tokens_for_request(
            request
        )
        budget_scopes = self._budget_scopes_for_request(request)
        estimated_cost = self._estimated_cost_for_model(
            model, estimated_input, estimated_output
        )
        budget_reservation = None

        if self.budget_manager:
            budget_reserved, budget_reservation, msg = (
                self.budget_manager.reserve_spend(
                    budget_scopes,
                    [BudgetPeriod.DAILY, BudgetPeriod.FIXED_30_DAYS],
                    estimated_cost,
                )
            )
            if not budget_reserved:
                return False, None, msg

        scopes = request.get("scopes", [])
        if self.rate_limiter and scopes:
            success, blocked_scope, reason = self.rate_limiter.acquire(
                scopes, estimated_input, estimated_output
            )
            if not success:
                if budget_reservation is not None:
                    self.budget_manager.refund_reservation(
                        budget_reservation.reservation_id
                    )
                if blocked_scope and reason:
                    return False, None, f"{blocked_scope}: {reason}"
                return False, None, reason or "Rate limit exceeded"

        governance_metadata = {
            "governance_id": str(uuid.uuid4()),
            "rate_limit_acquisition": (
                {
                    "scopes": scopes,
                    "estimated_input_tokens": estimated_input,
                    "estimated_output_tokens": estimated_output,
                }
                if self.rate_limiter and scopes
                else None
            ),
            "budget_reservation_id": (
                budget_reservation.reservation_id
                if budget_reservation is not None
                else None
            ),
            "budget_scopes": budget_scopes,
            "estimated_cost": estimated_cost,
        }
        return True, governance_metadata, "Reserved"

    def _refund_reserved_capacity(self, request: Dict) -> None:
        """Release admission holds when queued work fails before completion."""
        governance_metadata = request.get("governance", {})
        if not isinstance(governance_metadata, dict):
            return

        reservation_id = governance_metadata.get("budget_reservation_id")
        if reservation_id and self.budget_manager:
            self.budget_manager.refund_reservation(reservation_id)

        rate_limit_acquisition = governance_metadata.get("rate_limit_acquisition")
        if rate_limit_acquisition and self.rate_limiter:
            self.rate_limiter.refund_acquisition(
                rate_limit_acquisition["scopes"],
                rate_limit_acquisition["estimated_input_tokens"],
                rate_limit_acquisition["estimated_output_tokens"],
            )
    
    def _check_capacity_for_model(self, request: Dict, model: str) -> bool:
        """Check if there's capacity for a specific model."""
        # Estimate tokens for the downgraded model
        # (cheaper models might use more tokens for same task)
        estimated_input = request.get("estimated_input_tokens", 1000)
        estimated_output = request.get("estimated_output_tokens", 500)
        
        scopes = request.get("scopes", [])
        if self.rate_limiter and scopes:
            allowed, _, _ = self.rate_limiter.check_all_limits(
                scopes, estimated_input, estimated_output
            )
            if not allowed:
                return False

        if self.budget_manager:
            pricing = self.budget_manager.pricing.get(model)
            if pricing:
                estimated_cost = pricing.calculate_cost(
                    estimated_input, estimated_output, 0
                )
            else:
                estimated_cost = (
                    (estimated_input + estimated_output) / 1000
                ) * 0.01

            for scope_type, scope_id in self._budget_scopes_for_request(request):
                for period in [BudgetPeriod.DAILY, BudgetPeriod.FIXED_30_DAYS]:
                    within_budget, _, _ = self.budget_manager.check_budget(
                        scope_type, scope_id, period, estimated_cost
                    )
                    if not within_budget:
                        return False

        return True

    def _budget_scopes_for_request(self, request: Dict) -> List[Tuple[str, str]]:
        """Derive budget scopes to enforce for a degraded request."""
        configured_scopes = request.get("budget_scopes")
        if configured_scopes:
            return [
                (
                    scope_type.value
                    if isinstance(scope_type, LimitScope)
                    else str(scope_type),
                    str(scope_id)
                )
                for scope_type, scope_id in configured_scopes
            ]

        budget_scopes: List[Tuple[str, str]] = []

        def add(scope_type: str, scope_id: object) -> None:
            if scope_id is None:
                return
            candidate = (scope_type, str(scope_id))
            if candidate not in budget_scopes:
                budget_scopes.append(candidate)

        add("global", request.get("global_scope_id", "system"))

        for scope, scope_id in request.get("scopes", []):
            scope_type = scope.value if isinstance(scope, LimitScope) else str(scope)
            if scope_type in {"organization", "user", "agent"}:
                add(scope_type, scope_id)

        add("organization", request.get("org_id"))
        add("user", request.get("user_id"))
        add("agent", request.get("agent_id"))

        return budget_scopes
    
    def _calculate_retry_after(self, blocked_scope: str) -> float:
        """
        Calculate recommended retry delay using decorrelated jitter.

        The decorrelated jitter approach (AWS backoff guidance, Brooker),
        building on exponential backoff and multiple-access contention
        analysis (Metcalfe & Boggs; Hastad et al.), reduces correlation
        between retry attempts from multiple clients, preventing
        thundering herd problems.

        Formula: sleep = min(cap, random(base, sleep * 3))

        Convergence: The expected delay E[d_i] = (base + 3*d_{i-1})/2 converges to a
        stationary distribution with mean ~1.5*base, spreading retries more uniformly
        than standard exponential backoff which clusters around power-of-2 intervals.
        """
        import random

        base_delay = 1.0
        cap = 60.0
        # _last_delay is an instance attribute (initialized lazily via getattr)
        # so concurrent GracefulDegradationManager instances cannot stomp on a
        # shared module-level value.
        with self._lock:
            previous_delay = getattr(self, '_last_delay', base_delay)
            delay = min(cap, random.uniform(base_delay, previous_delay * 3))
            self._last_delay = delay
        return delay
    
    def _estimate_queue_wait(self, queue_position: int) -> float:
        """Estimate wait time for an item at the given queue position.

        Uses the rolling average of recent processing latencies (last 100
        items). Falls back to a 5-second default until enough history
        accumulates so freshly started managers still return a sane number
        instead of zero.
        """
        with self._lock:
            samples = list(self._processing_latency)
        if not samples:
            avg_latency = 5.0  # fallback when no telemetry available yet
        else:
            avg_latency = statistics.mean(samples)
        return queue_position * avg_latency
    
    def _compute_cache_key(self, request: Dict) -> str:
        """Generate a cache key for a request."""
        import hashlib
        import json
        
        # Include relevant request fields in cache key
        key_data = {
            "messages": request.get("messages", []),
            "system": request.get("system", "")
        }
        
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()
    
    def _record_degradation(self, strategy: str) -> None:
        """Record degradation event for monitoring."""
        with self._lock:
            self._degradation_stats[strategy] = (
                self._degradation_stats.get(strategy, 0) + 1
            )

    def _get_queue_processor_executor(self) -> ThreadPoolExecutor:
        """Return the shared bounded executor used for timed queue items."""
        with self._lock:
            if self._queue_processor_executor is None:
                self._queue_processor_executor = ThreadPoolExecutor(
                    max_workers=self.config.queue_processor_workers,
                    thread_name_prefix="degradation-queue",
                )
            return self._queue_processor_executor

    def shutdown_queue_processor(self, wait: bool = True) -> None:
        """Shut down the shared queue processor executor."""
        with self._lock:
            executor = self._queue_processor_executor
            self._queue_processor_executor = None
        if executor is not None:
            executor.shutdown(wait=wait, cancel_futures=True)
    
    def cache_response(self, request: Dict, response: Dict) -> None:
        """Cache a response for potential future fallback."""
        cache_key = self._compute_cache_key(request)
        with self._lock:
            # Refresh recency on hit, then enforce MAX_CACHE_SIZE via FIFO eviction.
            if cache_key in self._response_cache:
                self._response_cache.move_to_end(cache_key)
            self._response_cache[cache_key] = {
                "response": response,
                "cached_at": time.monotonic()
            }
            while len(self._response_cache) > self.config.max_cache_size:
                self._response_cache.popitem(last=False)
    
    def get_degradation_stats(self) -> Dict[str, int]:
        """Return statistics on degradation events."""
        with self._lock:
            return self._degradation_stats.copy()
    
    def process_queue(
        self,
        processor: Callable[[Dict], Dict],
        item_timeout_seconds: Optional[float] = None
    ) -> List[Dict]:
        """
        Process queued requests when capacity is available.

        Args:
            processor: Function to process a request and return response.
                Successful processors should record completion using the
                request's governance metadata; exceptions or
                {"success": False} results release the reservation.
            item_timeout_seconds: Optional override for the configured
                per-item timeout. Pass None to use the configuration; set the
                configuration to None only if the processor enforces its own
                deadline using the request's ``deadline_at`` field.

        Returns:
            List of processed results

        Operator note:
            When future.cancel() returns False the worker is wedged inside
            an uncancelable Python C-extension or syscall, so the executor
            slot stays held until the call returns naturally. We surface
            this case as the "queue_timeout_uncancelable" counter on
            self._degradation_events; monitor it for sustained growth.
            A rising counter means workers are not honoring deadlines and
            the process likely needs a restart, since Python cannot force
            a thread out of native code. Pair the counter with a worker
            saturation alarm (slots held vs. configured capacity) so the
            on-call sees both signals before throughput collapses.
        """
        results = []
        effective_timeout = (
            self.config.queue_item_timeout_seconds
            if item_timeout_seconds is None
            else item_timeout_seconds
        )
        if effective_timeout is not None and effective_timeout <= 0:
            raise ValueError("item_timeout_seconds must be positive or None")
        
        while True:
            now = time.monotonic()
            with self._lock:
                # Remove expired entries without changing queue admission policy.
                # Preserve the bounded-memory invariant by carrying the
                # original maxlen through the rebuild.
                self._request_queue = deque(
                    (entry for entry in self._request_queue
                     if entry["expires_at"] > now),
                    maxlen=self._request_queue.maxlen,
                )

                if not self._request_queue:
                    break

                entry = self._request_queue[0]
                request = entry["request"]

            processor_slot_acquired = False
            if effective_timeout is not None:
                processor_slot_acquired = self._queue_processor_slots.acquire(
                    blocking=False
                )
                if not processor_slot_acquired:
                    self._record_degradation("queue_processor_saturated")
                    break

            try:
                reserved, governance_metadata, _ = (
                    self._reserve_capacity_for_request(
                        request, request.get("model", "claude-3-opus")
                    )
                )
            except Exception:
                if processor_slot_acquired:
                    self._queue_processor_slots.release()
                raise
            if not reserved:
                # No capacity, stop processing and keep the request queued.
                if processor_slot_acquired:
                    self._queue_processor_slots.release()
                break

            governed_request = {
                **request,
                "governance": self._merge_governance_metadata(
                    request, governance_metadata or {}
                ),
            }

            with self._lock:
                if not self._request_queue or self._request_queue[0] is not entry:
                    self._refund_reserved_capacity(governed_request)
                    if processor_slot_acquired:
                        self._queue_processor_slots.release()
                    continue
                self._request_queue.popleft()

            processor_request = governed_request
            processor_start = time.monotonic()
            if effective_timeout is not None:
                processor_request = {
                    **governed_request,
                    "deadline_at": time.monotonic() + effective_timeout,
                }
                executor = self._get_queue_processor_executor()
                try:
                    future = executor.submit(processor, processor_request)
                except Exception:
                    self._queue_processor_slots.release()
                    self._refund_reserved_capacity(processor_request)
                    raise

                timed_out = False
                refund_after_timeout = False
                try:
                    result = future.result(timeout=effective_timeout)
                except FutureTimeoutError:
                    timed_out = True
                    if not future.cancel():
                        # Worker still holds the slot past the deadline; surface
                        # the wedge to SREs as a distinct counter so they can
                        # distinguish "clean timeout" from "stuck worker".
                        self._record_degradation("queue_timeout_uncancelable")
                        def release_after_completion(_future):
                            try:
                                completed_result = _future.result()
                            except Exception:
                                self._refund_reserved_capacity(processor_request)
                            else:
                                if (
                                    isinstance(completed_result, dict)
                                    and completed_result.get("success") is False
                                ):
                                    self._refund_reserved_capacity(processor_request)
                            finally:
                                self._queue_processor_slots.release()

                        future.add_done_callback(release_after_completion)
                    else:
                        self._queue_processor_slots.release()
                        refund_after_timeout = True
                    result = {
                        "success": False,
                        "error": "queue_item_timeout",
                        "timeout_seconds": effective_timeout,
                        "capacity_refunded": refund_after_timeout,
                    }
                except Exception:
                    self._queue_processor_slots.release()
                    self._refund_reserved_capacity(processor_request)
                    raise
                else:
                    self._queue_processor_slots.release()
            else:
                timed_out = False
                try:
                    result = processor(processor_request)
                except Exception:
                    self._refund_reserved_capacity(processor_request)
                    raise

            # Record processing latency for the rolling queue-wait estimate.
            # Only successful, non-timed-out runs contribute, so a stuck
            # processor cannot poison the rolling average and stall callers
            # with permanently inflated wait predictions.
            if not timed_out:
                processor_elapsed = time.monotonic() - processor_start
                with self._lock:
                    self._processing_latency.append(processor_elapsed)

            if timed_out:
                if refund_after_timeout:
                    self._refund_reserved_capacity(processor_request)
                self._record_degradation("queue_timeout")
            elif isinstance(result, dict) and result.get("success") is False:
                self._refund_reserved_capacity(processor_request)

            queue_time = time.monotonic() - entry["queued_at"]
            results.append({
                "request": processor_request,
                "result": result,
                "queue_time": queue_time,
                "timed_out": timed_out,
            })

        return results

# ============================================================================
# Block 6 (chapter listing #6)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
import threading
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class CostEvent:
    """Represents a single cost event."""
    timestamp: datetime
    scope_type: str
    scope_id: str
    model_id: str
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost: float
    request_id: str
    metadata: Dict


@dataclass
class CostAggregation:
    """Aggregated cost statistics."""
    total_cost: float = 0.0
    total_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cached_tokens: int = 0
    by_model: Dict[str, float] = field(default_factory=dict)
    by_hour: Dict[str, float] = field(default_factory=dict)


@dataclass
class CostTracker:
    """
    Freshness-bounded cost tracking and aggregation system.
    
    Provides synchronous in-process callbacks for new cost events,
    aggregation at multiple time granularities, and integration hooks
    for monitoring systems.
    """
    
    pricing: Dict[str, ModelPricing] = field(
        default_factory=lambda: STANDARD_PRICING.copy()
    )
    retention_hours: int = 168  # 7 days
    # Hard cap on retained cost events to bound memory growth in
    # long-running trackers. Oldest events are dropped FIFO once the
    # cap is reached.
    max_cost_events: int = 100_000
    max_aggregation_scopes: int = 10_000
    aggregation_scope_ttl_hours: int = 168
    aggregation_hour_retention_hours: Optional[int] = None

    _events: "deque[CostEvent]" = field(init=False)
    _aggregations: Dict[str, CostAggregation] = field(default_factory=dict)
    _aggregation_last_seen: Dict[str, datetime] = field(default_factory=dict)
    _subscribers: List[Callable[[CostEvent], None]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self._events = deque(maxlen=self.max_cost_events)
    
    def record(
        self,
        scope_type: str,
        scope_id: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
        request_id: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> CostEvent:
        """
        Record a cost event and update aggregations.
        
        Returns the created CostEvent for reference.
        """
        # Calculate cost
        pricing = self.pricing.get(model_id)
        if pricing:
            cost = pricing.calculate_cost(
                input_tokens, output_tokens, cached_tokens
            )
        else:
            logger.warning(f"Unknown model: {model_id}, using estimate")
            cost = ((input_tokens + output_tokens) / 1000) * 0.01
        
        event = CostEvent(
            timestamp=datetime.now(timezone.utc),
            scope_type=scope_type,
            scope_id=scope_id,
            model_id=model_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached_tokens,
            cost=cost,
            request_id=request_id or self._generate_request_id(),
            metadata=metadata or {}
        )
        
        with self._lock:
            self._events.append(event)
            self._update_aggregations(event)
            # Amortize cleanup to keep the hot path cheap.
            if len(self._events) % 1000 == 0:
                self._cleanup_old_events()
        
        # Notify subscribers
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as e:
                logger.error(f"Subscriber error: {e}")
        
        return event
    
    def _generate_request_id(self) -> str:
        """Generate a unique request ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _update_aggregations(self, event: CostEvent) -> None:
        """Update aggregation buckets with new event."""
        # Aggregate by scope
        scope_key = f"{event.scope_type}:{event.scope_id}"
        if scope_key not in self._aggregations:
            self._aggregations[scope_key] = CostAggregation()
        self._aggregation_last_seen[scope_key] = event.timestamp
        
        agg = self._aggregations[scope_key]
        agg.total_cost += event.cost
        agg.total_requests += 1
        agg.total_input_tokens += event.input_tokens
        agg.total_output_tokens += event.output_tokens
        agg.total_cached_tokens += event.cached_tokens
        
        # Track by model
        agg.by_model[event.model_id] = (
            agg.by_model.get(event.model_id, 0) + event.cost
        )
        
        # Track by hour
        hour_key = event.timestamp.strftime("%Y-%m-%d-%H")
        agg.by_hour[hour_key] = (
            agg.by_hour.get(hour_key, 0) + event.cost
        )
        self._prune_aggregation_hours(agg, event.timestamp)
        self._evict_aggregation_scopes(event.timestamp)

    def _aggregation_hour_retention(self) -> int:
        if self.aggregation_hour_retention_hours is not None:
            return self.aggregation_hour_retention_hours
        return self.retention_hours

    def _prune_aggregation_hours(
        self,
        agg: CostAggregation,
        now: datetime
    ) -> None:
        """Drop per-hour buckets outside the configured retention window."""
        retention = max(0, self._aggregation_hour_retention())
        cutoff_hour = (now - timedelta(hours=retention)).strftime("%Y-%m-%d-%H")
        for hour_key in sorted(list(agg.by_hour.keys())):
            if hour_key < cutoff_hour:
                del agg.by_hour[hour_key]

    def _evict_aggregation_scopes(self, now: datetime) -> None:
        """Evict inactive scopes first, then oldest active scopes."""
        ttl = max(0, self.aggregation_scope_ttl_hours)
        cutoff = now - timedelta(hours=ttl)
        expired_keys = [
            key for key, last_seen in self._aggregation_last_seen.items()
            if last_seen < cutoff
        ]
        for key in sorted(expired_keys):
            self._aggregations.pop(key, None)
            self._aggregation_last_seen.pop(key, None)

        if self.max_aggregation_scopes <= 0:
            for key in sorted(list(self._aggregations.keys())):
                self._aggregations.pop(key, None)
                self._aggregation_last_seen.pop(key, None)
            return

        overflow = len(self._aggregations) - self.max_aggregation_scopes
        if overflow <= 0:
            return

        floor = datetime.min.replace(tzinfo=timezone.utc)
        eviction_order = sorted(
            self._aggregations.keys(),
            key=lambda key: (self._aggregation_last_seen.get(key, floor), key)
        )
        for key in eviction_order[:overflow]:
            self._aggregations.pop(key, None)
            self._aggregation_last_seen.pop(key, None)
    
    def _cleanup_old_events(self) -> None:
        """Remove events older than retention period."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=self.retention_hours)
        # Rebuild as a deque with the same maxlen so the bounded-memory
        # invariant from __post_init__ survives cleanup.
        self._events = deque(
            (e for e in self._events if e.timestamp >= cutoff),
            maxlen=self.max_cost_events,
        )
        for agg in self._aggregations.values():
            self._prune_aggregation_hours(agg, now)
        self._evict_aggregation_scopes(now)
    
    def subscribe(self, callback: Callable[[CostEvent], None]) -> None:
        """Subscribe to newly recorded cost events."""
        self._subscribers.append(callback)
    
    def unsubscribe(self, callback: Callable[[CostEvent], None]) -> None:
        """Unsubscribe from cost events."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)
    
    def get_aggregation(
        self,
        scope_type: str,
        scope_id: str
    ) -> Optional[CostAggregation]:
        """Get aggregated costs for a scope."""
        key = f"{scope_type}:{scope_id}"
        return self._aggregations.get(key)
    
    def get_costs_by_timeframe(
        self,
        scope_type: str,
        scope_id: str,
        start_time: datetime,
        end_time: datetime,
        granularity: str = "hour"  # hour, day, or total
    ) -> Dict:
        """
        Get costs for a specific timeframe with optional granularity.
        
        Args:
            scope_type: Type of scope to query
            scope_id: ID of scope to query
            start_time: Start of time range
            end_time: End of time range
            granularity: Level of detail (hour, day, total)
            
        Returns:
            Dictionary with cost data
        """
        with self._lock:
            relevant_events = [
                e for e in self._events
                if (e.scope_type == scope_type and
                    e.scope_id == scope_id and
                    start_time <= e.timestamp <= end_time)
            ]
        
        if granularity == "total":
            return {
                "total_cost": sum(e.cost for e in relevant_events),
                "total_requests": len(relevant_events),
                "total_input_tokens": sum(e.input_tokens for e in relevant_events),
                "total_output_tokens": sum(e.output_tokens for e in relevant_events)
            }
        
        # Group by time bucket
        buckets = defaultdict(lambda: {
            "cost": 0.0,
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0
        })
        
        for event in relevant_events:
            if granularity == "hour":
                bucket_key = event.timestamp.strftime("%Y-%m-%d %H:00")
            else:  # day
                bucket_key = event.timestamp.strftime("%Y-%m-%d")
            
            buckets[bucket_key]["cost"] += event.cost
            buckets[bucket_key]["requests"] += 1
            buckets[bucket_key]["input_tokens"] += event.input_tokens
            buckets[bucket_key]["output_tokens"] += event.output_tokens
        
        return dict(buckets)
    
    def get_top_spenders(
        self,
        scope_type: str,
        limit: int = 10,
        hours: int = 24
    ) -> List[Dict]:
        """Get top spending entities within a scope type."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        with self._lock:
            relevant_events = [
                e for e in self._events
                if e.scope_type == scope_type and e.timestamp >= cutoff
            ]
        
        # Aggregate by scope_id
        by_scope = defaultdict(float)
        for event in relevant_events:
            by_scope[event.scope_id] += event.cost
        
        # Sort and return top N
        sorted_scopes = sorted(
            by_scope.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        return [
            {"scope_id": scope_id, "cost": cost}
            for scope_id, cost in sorted_scopes
        ]
    
    def get_model_usage_breakdown(
        self,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
        hours: int = 24
    ) -> Dict[str, Dict]:
        """Get usage breakdown by model."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        with self._lock:
            events = self._events
            if scope_type:
                events = [e for e in events if e.scope_type == scope_type]
            if scope_id:
                events = [e for e in events if e.scope_id == scope_id]
            events = [e for e in events if e.timestamp >= cutoff]
        
        breakdown = defaultdict(lambda: {
            "cost": 0.0,
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "avg_cost_per_request": 0.0
        })
        
        for event in events:
            model = breakdown[event.model_id]
            model["cost"] += event.cost
            model["requests"] += 1
            model["input_tokens"] += event.input_tokens
            model["output_tokens"] += event.output_tokens
        
        # Calculate averages
        for model_id, data in breakdown.items():
            if data["requests"] > 0:
                data["avg_cost_per_request"] = data["cost"] / data["requests"]
        
        return dict(breakdown)
    
    def export_for_dashboard(
        self,
        hours: int = 24
    ) -> Dict:
        """
        Export data formatted for dashboard consumption.
        
        Returns data suitable for visualization in monitoring dashboards.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        with self._lock:
            recent_events = [
                e for e in self._events if e.timestamp >= cutoff
            ]
        
        # Time series data
        hourly_costs = defaultdict(float)
        for event in recent_events:
            hour_key = event.timestamp.strftime("%Y-%m-%dT%H:00:00Z")
            hourly_costs[hour_key] += event.cost
        
        return {
            "summary": {
                "total_cost": sum(e.cost for e in recent_events),
                "total_requests": len(recent_events),
                "period_hours": hours
            },
            "time_series": [
                {"timestamp": k, "cost": v}
                for k, v in sorted(hourly_costs.items())
            ],
            "by_model": self.get_model_usage_breakdown(hours=hours),
            "by_scope_type": {
                scope_type: sum(
                    e.cost for e in recent_events
                    if e.scope_type == scope_type
                )
                for scope_type in set(e.scope_type for e in recent_events)
            }
        }

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any
from enum import Enum
from datetime import datetime, timedelta, timezone
from collections import deque
import threading
import statistics
import logging

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Severity levels for alerts."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of cost/usage alerts."""
    BUDGET_THRESHOLD = "budget_threshold"
    RATE_SPIKE = "rate_spike"
    COST_SPIKE = "cost_spike"
    UNUSUAL_PATTERN = "unusual_pattern"
    MODEL_MISUSE = "model_misuse"
    RETRY_LOOP = "retry_loop"


@dataclass
class Alert:
    """Represents a single alert."""
    alert_id: str
    alert_type: AlertType
    severity: AlertSeverity
    timestamp: datetime
    scope_type: str
    scope_id: str
    message: str
    details: Dict
    acknowledged: bool = False


@dataclass
class AlertRule:
    """Configuration for an alert rule."""
    rule_id: str
    alert_type: AlertType
    severity: AlertSeverity
    condition: Callable[[Dict], bool]
    message_template: str
    cooldown_minutes: int = 15
    enabled: bool = True


@dataclass
class AlertManager:
    """
    Manages anomaly detection and alerting for cost/usage metrics.
    
    Provides configurable rules, multiple notification channels,
    and deduplication to prevent alert fatigue.
    """
    
    notification_channels: List[Callable[[Alert], None]] = field(
        default_factory=list
    )
    max_notification_channels: int = 20
    max_metric_keys: int = 10_000
    metric_ttl_hours: int = 24
    max_metric_samples_per_key: int = 1000
    max_cooldown_keys: int = 10_000
    alert_cooldown_ttl_hours: int = 24
    
    _rules: Dict[str, AlertRule] = field(default_factory=dict)
    _alerts: List[Alert] = field(default_factory=list)
    _last_alert_times: Dict[str, datetime] = field(default_factory=dict)
    _metric_history: Dict[str, deque] = field(default_factory=dict)
    _metric_last_seen: Dict[str, datetime] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        if self.max_notification_channels < 0:
            raise ValueError("max_notification_channels must be non-negative")
        self.notification_channels = self.notification_channels[
            :self.max_notification_channels
        ]
        # Register default rules
        self._register_default_rules()
    
    def _register_default_rules(self) -> None:
        """Register built-in alert rules."""
        
        # Cost spike detection
        self.add_rule(AlertRule(
            rule_id="cost_spike_3x",
            alert_type=AlertType.COST_SPIKE,
            severity=AlertSeverity.WARNING,
            condition=lambda ctx: ctx.get("cost_ratio", 1) > 3.0,
            message_template=(
                "Cost spike detected for {scope_type}:{scope_id}. "
                "Current rate is {cost_ratio:.1f}x the historical average."
            ),
            cooldown_minutes=30
        ))
        
        # Critical cost spike
        self.add_rule(AlertRule(
            rule_id="cost_spike_10x",
            alert_type=AlertType.COST_SPIKE,
            severity=AlertSeverity.CRITICAL,
            condition=lambda ctx: ctx.get("cost_ratio", 1) > 10.0,
            message_template=(
                "CRITICAL: Extreme cost spike for {scope_type}:{scope_id}. "
                "Current rate is {cost_ratio:.1f}x the historical average. "
                "Immediate investigation recommended."
            ),
            cooldown_minutes=5
        ))
        
        # Retry loop detection
        self.add_rule(AlertRule(
            rule_id="retry_loop",
            alert_type=AlertType.RETRY_LOOP,
            severity=AlertSeverity.CRITICAL,
            condition=lambda ctx: (
                ctx.get("requests_per_minute", 0) > 100 and
                ctx.get("error_rate", 0) > 0.5
            ),
            message_template=(
                "Possible retry loop detected for {scope_type}:{scope_id}. "
                "{requests_per_minute} req/min with {error_rate:.0%} error rate."
            ),
            cooldown_minutes=5
        ))
        
        # Expensive model overuse
        self.add_rule(AlertRule(
            rule_id="expensive_model_overuse",
            alert_type=AlertType.MODEL_MISUSE,
            severity=AlertSeverity.WARNING,
            condition=lambda ctx: (
                ctx.get("opus_percentage", 0) > 80 and
                ctx.get("total_cost_last_hour", 0) > 100
            ),
            message_template=(
                "High usage of expensive models for {scope_type}:{scope_id}. "
                "{opus_percentage:.0f}% of requests using Opus. "
                "Consider model optimization."
            ),
            cooldown_minutes=60
        ))
    
    def add_rule(self, rule: AlertRule) -> None:
        """Add or update an alert rule."""
        with self._lock:
            self._rules[rule.rule_id] = rule
    
    def remove_rule(self, rule_id: str) -> None:
        """Remove an alert rule."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
    
    def add_notification_channel(
        self,
        channel: Callable[[Alert], None]
    ) -> None:
        """Add a notification channel."""
        if len(self.notification_channels) >= self.max_notification_channels:
            raise ValueError("notification channel limit reached")
        self.notification_channels.append(channel)
    
    def record_metric(
        self,
        metric_name: str,
        scope_type: str,
        scope_id: str,
        value: float
    ) -> None:
        """Record a metric value for anomaly detection."""
        key = f"{metric_name}:{scope_type}:{scope_id}"
        now = datetime.now(timezone.utc)
        
        with self._lock:
            self._prune_metric_history(now)
            if self.max_metric_keys <= 0:
                return

            if key not in self._metric_history:
                self._metric_history[key] = deque(
                    maxlen=max(1, self.max_metric_samples_per_key)
                )
            self._metric_last_seen[key] = now
            
            self._metric_history[key].append({
                "timestamp": now,
                "value": value
            })
            self._evict_metric_keys()

    def _prune_metric_history(self, now: datetime) -> None:
        """Drop inactive metric keys and old samples."""
        ttl = max(0, self.metric_ttl_hours)
        cutoff = now - timedelta(hours=ttl)
        for key in sorted(list(self._metric_history.keys())):
            history = self._metric_history[key]
            while history and history[0]["timestamp"] < cutoff:
                history.popleft()
            if not history or self._metric_last_seen.get(key, cutoff) < cutoff:
                self._metric_history.pop(key, None)
                self._metric_last_seen.pop(key, None)

    def _evict_metric_keys(self) -> None:
        """Keep only the most recently used metric keys."""
        overflow = len(self._metric_history) - self.max_metric_keys
        if overflow <= 0:
            return

        floor = datetime.min.replace(tzinfo=timezone.utc)
        eviction_order = sorted(
            self._metric_history.keys(),
            key=lambda key: (self._metric_last_seen.get(key, floor), key)
        )
        for key in eviction_order[:overflow]:
            self._metric_history.pop(key, None)
            self._metric_last_seen.pop(key, None)

    def _prune_cooldown_keys(self, now: datetime) -> None:
        """Drop stale cooldown entries and cap high-cardinality keys."""
        ttl = max(0, self.alert_cooldown_ttl_hours)
        cutoff = now - timedelta(hours=ttl)
        expired_keys = [
            key for key, last_seen in self._last_alert_times.items()
            if last_seen < cutoff
        ]
        for key in sorted(expired_keys):
            self._last_alert_times.pop(key, None)

        if self.max_cooldown_keys <= 0:
            self._last_alert_times.clear()
            return

        overflow = len(self._last_alert_times) - self.max_cooldown_keys
        if overflow <= 0:
            return

        eviction_order = sorted(
            self._last_alert_times.keys(),
            key=lambda key: (self._last_alert_times[key], key)
        )
        for key in eviction_order[:overflow]:
            self._last_alert_times.pop(key, None)
    
    def check_for_anomalies(
        self,
        scope_type: str,
        scope_id: str,
        current_metrics: Dict[str, float]
    ) -> List[Alert]:
        """
        Check current metrics against alert rules.
        
        Args:
            scope_type: Type of scope being checked
            scope_id: ID of scope being checked
            current_metrics: Current metric values
            
        Returns:
            List of triggered alerts
        """
        triggered_alerts = []
        
        # Build context for rule evaluation
        context = {
            "scope_type": scope_type,
            "scope_id": scope_id,
            **current_metrics
        }
        
        # Add historical comparisons
        context["cost_ratio"] = self._calculate_cost_ratio(
            scope_type, scope_id,
            current_metrics.get("cost_per_minute", 0)
        )
        
        with self._lock:
            now = datetime.now(timezone.utc)
            self._prune_cooldown_keys(now)

            for rule_id, rule in self._rules.items():
                if not rule.enabled:
                    continue
                
                # Check cooldown
                cooldown_key = f"{rule_id}:{scope_type}:{scope_id}"
                if cooldown_key in self._last_alert_times:
                    time_since_last = (
                        now - self._last_alert_times[cooldown_key]
                    )
                    if time_since_last < timedelta(minutes=rule.cooldown_minutes):
                        continue
                
                # Evaluate rule condition
                try:
                    if rule.condition(context):
                        alert = self._create_alert(rule, context)
                        triggered_alerts.append(alert)
                        
                        # Update cooldown
                        self._last_alert_times[cooldown_key] = now
                        self._prune_cooldown_keys(now)
                        
                        # Store alert, bounding the in-memory ring.
                        self._alerts.append(alert)
                        if len(self._alerts) > 10000:
                            self._alerts = self._alerts[-5000:]
                        
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule_id}: {e}")
        
        # Send notifications
        for alert in triggered_alerts:
            self._send_notifications(alert)
        
        return triggered_alerts
    
    def _calculate_cost_ratio(
        self,
        scope_type: str,
        scope_id: str,
        current_cost_per_minute: float
    ) -> float:
        """Calculate ratio of current cost to historical average."""
        key = f"cost_per_minute:{scope_type}:{scope_id}"
        
        with self._lock:
            if key not in self._metric_history:
                return 1.0
            
            self._metric_last_seen[key] = datetime.now(timezone.utc)
            history = list(self._metric_history[key])
        
        if len(history) < 10:
            return 1.0
        
        # Use values from more than 1 hour ago as baseline
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        historical_values = [
            h["value"] for h in history
            if h["timestamp"] < cutoff
        ]
        
        if not historical_values:
            return 1.0
        
        avg_historical = statistics.mean(historical_values)
        if avg_historical == 0:
            return 10.0 if current_cost_per_minute > 0 else 1.0
        
        return current_cost_per_minute / avg_historical
    
    def _create_alert(self, rule: AlertRule, context: Dict) -> Alert:
        """Create an alert from a rule and context."""
        import uuid
        
        return Alert(
            alert_id=str(uuid.uuid4()),
            alert_type=rule.alert_type,
            severity=rule.severity,
            timestamp=datetime.now(timezone.utc),
            scope_type=context["scope_type"],
            scope_id=context["scope_id"],
            message=rule.message_template.format(**context),
            details=context.copy()
        )
    
    def _send_notifications(self, alert: Alert) -> None:
        """Send alert to all notification channels."""
        for channel in self.notification_channels:
            try:
                channel(alert)
            except Exception as e:
                logger.error(f"Notification channel error: {e}")
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    return True
        return False
    
    def get_active_alerts(
        self,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        include_acknowledged: bool = False
    ) -> List[Alert]:
        """Get active alerts with optional filtering."""
        with self._lock:
            alerts = list(self._alerts)
        
        # Filter
        if not include_acknowledged:
            alerts = [a for a in alerts if not a.acknowledged]
        if scope_type:
            alerts = [a for a in alerts if a.scope_type == scope_type]
        if scope_id:
            alerts = [a for a in alerts if a.scope_id == scope_id]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return alerts
    
    def get_alert_summary(self, hours: int = 24) -> Dict:
        """Get summary of alerts for the specified period."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        with self._lock:
            recent = [a for a in self._alerts if a.timestamp >= cutoff]
        
        return {
            "total_alerts": len(recent),
            "by_severity": {
                s.value: len([a for a in recent if a.severity == s])
                for s in AlertSeverity
            },
            "by_type": {
                t.value: len([a for a in recent if a.alert_type == t])
                for t in AlertType
            },
            "unacknowledged": len([a for a in recent if not a.acknowledged])
        }



def slack_notification_channel(webhook_url: str) -> Callable[[Alert], None]:
    """Create a Slack notification channel.

    Webhook delivery is best-effort and synchronous in this reference
    implementation: a single failure is logged and dropped. For
    high-volume production deployments, route webhooks through the
    SIEMAuditLogger pattern (Chapter 2) with a bounded queue, circuit
    breaker, and DLQ so transient outages do not silently lose alerts.
    """
    import urllib.request
    import urllib.error
    import json
    
    def send(alert: Alert) -> None:
        severity_emoji = {
            AlertSeverity.INFO: ":information_source:",
            AlertSeverity.WARNING: ":warning:",
            AlertSeverity.CRITICAL: ":rotating_light:"
        }
        
        payload = {
            "text": f"{severity_emoji[alert.severity]} *{alert.alert_type.value.upper()}*",
            "attachments": [{
                "color": {
                    AlertSeverity.INFO: "#36a64f",
                    AlertSeverity.WARNING: "#ff9800",
                    AlertSeverity.CRITICAL: "#f44336"
                }[alert.severity],
                "fields": [
                    {"title": "Scope", "value": f"{alert.scope_type}:{alert.scope_id}", "short": True},
                    {"title": "Severity", "value": alert.severity.value, "short": True},
                    {"title": "Message", "value": alert.message, "short": False}
                ],
                "ts": int(alert.timestamp.timestamp())
            }]
        }
        
        # Best-effort delivery: common serialization, request-construction,
        # and webhook I/O failures are logged and dropped so they do not mask
        # the monitored request.
        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5.0)
        except (TypeError, ValueError, OSError, urllib.error.URLError, TimeoutError) as exc:
            logger.warning("Slack webhook delivery failed: %s", exc)
    
    return send


def pagerduty_notification_channel(
    routing_key: str,
    only_critical: bool = True
) -> Callable[[Alert], None]:
    """Create a PagerDuty notification channel.

    Webhook delivery is best-effort and synchronous in this reference
    implementation: a single failure is logged and dropped. For
    high-volume production deployments, route webhooks through the
    SIEMAuditLogger pattern (Chapter 2) with a bounded queue, circuit
    breaker, and DLQ so transient outages do not silently lose alerts.
    """
    import urllib.request
    import urllib.error
    import json
    
    def send(alert: Alert) -> None:
        if only_critical and alert.severity != AlertSeverity.CRITICAL:
            return
        
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": f"{alert.scope_type}:{alert.scope_id}:{alert.alert_type.value}",
            "payload": {
                "summary": alert.message,
                "severity": {
                    AlertSeverity.INFO: "info",
                    AlertSeverity.WARNING: "warning",
                    AlertSeverity.CRITICAL: "critical"
                }[alert.severity],
                "source": f"agent-cost-monitor:{alert.scope_type}:{alert.scope_id}",
                "custom_details": alert.details
            }
        }
        
        # Best-effort delivery: common serialization, request-construction,
        # and webhook I/O failures are logged and dropped so they do not mask
        # the monitored request.
        try:
            req = urllib.request.Request(
                "https://events.pagerduty.com/v2/enqueue",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5.0)
        except (TypeError, ValueError, OSError, urllib.error.URLError, TimeoutError) as exc:
            logger.warning("PagerDuty webhook delivery failed: %s", exc)
    
    return send

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from collections import deque
from contextlib import contextmanager
import logging
import os
import threading
import uuid

logger = logging.getLogger(__name__)


@dataclass
class AgentCostGovernor:
    """
    Unified cost governance system for agent deployments.
    
    Integrates rate limiting, budget management, cost tracking,
    and alerting into a single, easy-to-use interface.
    """
    
    # Component instances
    rate_limiter: HierarchicalRateLimiter
    budget_manager: BudgetManager
    cost_tracker: CostTracker
    alert_manager: AlertManager
    degradation_manager: GracefulDegradationManager
    _finalized_governance_ids: set = field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _finalized_governance_order: deque = field(
        default_factory=lambda: deque(maxlen=10_000),
        init=False,
        repr=False,
    )
    _governance_lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )
    
    @classmethod
    def create_default(
        cls,
        global_token_limit_per_minute: int = 1_000_000,
        global_request_limit_per_minute: int = 1000,
        global_daily_budget: float = 1000.0,
        slack_webhook: Optional[str] = None,
        pagerduty_key: Optional[str] = None
    ) -> "AgentCostGovernor":
        """Create a governor with sensible defaults."""
        
        # Create rate limiter
        rate_limiter = HierarchicalRateLimiter(
            global_config=RateLimitConfig(
                max_requests_per_minute=global_request_limit_per_minute,
                max_tokens_per_minute=global_token_limit_per_minute
            )
        )
        
        # Create budget manager
        budget_manager = BudgetManager()
        budget_manager.allocate_budget(
            "global", "system",
            BudgetPeriod.DAILY,
            global_daily_budget
        )
        
        # Create cost tracker
        cost_tracker = CostTracker()
        
        # Create alert manager with notification channels
        alert_manager = AlertManager()
        if slack_webhook:
            alert_manager.add_notification_channel(
                slack_notification_channel(slack_webhook)
            )
        if pagerduty_key:
            alert_manager.add_notification_channel(
                pagerduty_notification_channel(pagerduty_key)
            )
        
        # Create degradation manager
        degradation_manager = GracefulDegradationManager(
            rate_limiter=rate_limiter,
            budget_manager=budget_manager
        )
        
        # Wire up cost tracking to budget manager
        def on_cost_event(event: CostEvent):
            reservation_id = event.metadata.get("budget_reservation_id")
            committed = False
            if reservation_id:
                committed = budget_manager.commit_reservation(
                    reservation_id,
                    event.cost,
                    event.scope_type,
                    event.scope_id,
                    event.model_id,
                    event.input_tokens,
                    event.output_tokens,
                    event.cached_tokens,
                    event.metadata
                )
                if not committed:
                    logger.warning(
                        "Budget reservation %s was not active; "
                        "recording spend directly",
                        reservation_id,
                    )

            if not reservation_id or not committed:
                budget_manager.record_spend(
                    event.scope_type,
                    event.scope_id,
                    event.model_id,
                    event.input_tokens,
                    event.output_tokens,
                    event.cached_tokens,
                    event.metadata
                )
            
            # Check for anomalies
            alert_manager.check_for_anomalies(
                event.scope_type,
                event.scope_id,
                {
                    "cost_per_minute": event.cost * 60,  # Rough estimate
                    "requests_per_minute": 1,  # Would need aggregation
                }
            )
        
        cost_tracker.subscribe(on_cost_event)
        
        return cls(
            rate_limiter=rate_limiter,
            budget_manager=budget_manager,
            cost_tracker=cost_tracker,
            alert_manager=alert_manager,
            degradation_manager=degradation_manager
        )
    
    def configure_organization(
        self,
        org_id: str,
        tokens_per_minute: int,
        daily_budget: float,
        monthly_budget: float
    ) -> None:
        """Configure limits for an organization."""
        self.rate_limiter.configure_scope(
            LimitScope.ORGANIZATION,
            org_id,
            RateLimitConfig(max_tokens_per_minute=tokens_per_minute)
        )
        
        self.budget_manager.allocate_budget(
            "organization", org_id,
            BudgetPeriod.DAILY, daily_budget
        )
        self.budget_manager.allocate_budget(
            "organization", org_id,
            BudgetPeriod.FIXED_30_DAYS, monthly_budget
        )
    
    def configure_user(
        self,
        user_id: str,
        org_id: str,
        tokens_per_minute: int,
        daily_budget: float
    ) -> None:
        """Configure limits for a user within an organization."""
        self.rate_limiter.configure_scope(
            LimitScope.USER,
            user_id,
            RateLimitConfig(max_tokens_per_minute=tokens_per_minute),
            parent_scope=LimitScope.ORGANIZATION,
            parent_identifier=org_id
        )
        
        self.budget_manager.allocate_budget(
            "user", user_id,
            BudgetPeriod.DAILY, daily_budget
        )
    
    def process_request(
        self,
        request: Dict,
        org_id: str,
        user_id: str,
        agent_id: Optional[str] = None
    ) -> Dict:
        """
        Process an agent request through the governance system.
        
        This is the main entry point for governed API calls.
        Returns either the original request (if approved), a modified
        request (if degraded), or an error response (if rejected).
        """
        # Build scope hierarchy
        scopes = [
            (LimitScope.ORGANIZATION, org_id),
            (LimitScope.USER, user_id)
        ]
        if agent_id:
            scopes.append((LimitScope.AGENT, agent_id))
        
        budget_scopes = [
            ("global", "system"),
            ("organization", org_id),
            ("user", user_id)
        ]
        if agent_id:
            budget_scopes.append(("agent", agent_id))

        governed_request = {
            **request,
            "scopes": scopes,
            "budget_scopes": budget_scopes,
            "org_id": org_id,
            "user_id": user_id,
            "agent_id": agent_id,
        }

        # Estimate costs
        estimated_input = request.get("estimated_input_tokens", 1000)
        estimated_output = request.get("estimated_output_tokens", 500)
        model = request.get("model", "claude-3-sonnet")
        
        pricing = self.budget_manager.pricing.get(model)
        if pricing:
            estimated_cost = pricing.calculate_cost(
                estimated_input, estimated_output, 0
            )
        else:
            estimated_cost = ((estimated_input + estimated_output) / 1000) * 0.01
        
        # Check rate limits
        allowed, blocked_scope, reason = self.rate_limiter.check_all_limits(
            scopes, estimated_input, estimated_output
        )
        
        if not allowed:
            return self.degradation_manager.handle_rate_limit(
                governed_request, blocked_scope, reason
            )
        
        budget_reserved, budget_reservation, msg = self.budget_manager.reserve_spend(
            budget_scopes,
            [BudgetPeriod.DAILY, BudgetPeriod.FIXED_30_DAYS],
            estimated_cost,
        )
        if not budget_reserved:
            return self.degradation_manager.handle_rate_limit(
                governed_request, "budget", msg
            )

        # Acquire capacity
        success, blocked_scope, reason = self.rate_limiter.acquire(
            scopes, estimated_input, estimated_output
        )
        
        if not success:
            if budget_reservation is not None:
                self.budget_manager.refund_reservation(
                    budget_reservation.reservation_id
                )
            return self.degradation_manager.handle_rate_limit(
                governed_request, blocked_scope, reason
            )
        
        governance_metadata = {
            "governance_id": str(uuid.uuid4()),
            "rate_limit_acquisition": {
                "scopes": scopes,
                "estimated_input_tokens": estimated_input,
                "estimated_output_tokens": estimated_output,
            },
            "budget_reservation_id": (
                budget_reservation.reservation_id
                if budget_reservation is not None
                else None
            ),
            "budget_scopes": budget_scopes,
            "estimated_cost": estimated_cost,
        }
        governed_request["governance"] = governance_metadata

        # Request approved
        return {
            "approved": True,
            "request": governed_request,
            "scopes": scopes,
            "budget_scopes": budget_scopes,
            "governance": governance_metadata
        }

    def _extract_governance_metadata(self, metadata: Optional[Dict]) -> Dict:
        """Accept governance metadata, a result, or a governed request."""
        if not isinstance(metadata, dict):
            return {}

        governance_metadata = metadata.get("governance")
        if isinstance(governance_metadata, dict):
            return governance_metadata

        for request_key in ("request", "modified_request"):
            request = metadata.get(request_key)
            if not isinstance(request, dict):
                continue
            request_governance = request.get("governance")
            if isinstance(request_governance, dict):
                return request_governance

        return metadata

    def _has_unfinished_admission(self, result: Dict) -> bool:
        """Return True for admitted work that still needs finalization."""
        if not isinstance(result, dict):
            return False

        if result.get("approved") is True:
            return True

        if result.get("success") is not True:
            return False

        governance_metadata = self._extract_governance_metadata(result)
        return any(
            governance_metadata.get(key)
            for key in (
                "governance_id",
                "budget_reservation_id",
                "rate_limit_acquisition",
            )
        )

    def _governance_finalization_key(
        self,
        governance_metadata: Dict
    ) -> Optional[str]:
        governance_id = governance_metadata.get("governance_id")
        if governance_id:
            return str(governance_id)

        reservation_id = governance_metadata.get("budget_reservation_id")
        if reservation_id:
            return f"budget:{reservation_id}"

        return None

    def _mark_governance_finalized(self, governance_metadata: Dict) -> bool:
        """
        Return True once for each admitted request.

        Success and failure both finalize the admission. The bounded memory of
        finalized ids prevents a later failure handler from refunding capacity
        that was already consumed by a successful completion.
        """
        finalization_key = self._governance_finalization_key(
            governance_metadata
        )
        if finalization_key is None:
            return True

        with self._governance_lock:
            if finalization_key in self._finalized_governance_ids:
                return False

            maxlen = self._finalized_governance_order.maxlen
            if maxlen is not None and len(self._finalized_governance_order) >= maxlen:
                expired_key = self._finalized_governance_order.popleft()
                self._finalized_governance_ids.discard(expired_key)

            self._finalized_governance_order.append(finalization_key)
            self._finalized_governance_ids.add(finalization_key)
            return True

    def record_failure(self, metadata: Optional[Dict] = None) -> bool:
        """
        Release admission holds for an approved request that did not complete.

        Pass the ``governance`` metadata returned by process_request, the
        process_request result itself, or the governed request. The method is
        idempotent for admissions produced by this governor: after
        record_completion succeeds, this returns False and does not refund rate
        capacity.
        """
        governance_metadata = self._extract_governance_metadata(metadata)
        if not governance_metadata:
            return False

        if not self._mark_governance_finalized(governance_metadata):
            return False

        released = False
        reservation_id = governance_metadata.get("budget_reservation_id")
        if reservation_id:
            released = self.budget_manager.refund_reservation(reservation_id)

        rate_limit_acquisition = governance_metadata.get("rate_limit_acquisition")
        if rate_limit_acquisition:
            self.rate_limiter.refund_acquisition(
                rate_limit_acquisition["scopes"],
                rate_limit_acquisition["estimated_input_tokens"],
                rate_limit_acquisition["estimated_output_tokens"],
            )
            released = True

        return released

    @contextmanager
    def governed_call(
        self,
        request: Dict,
        org_id: str,
        user_id: str,
        agent_id: Optional[str] = None
    ):
        """
        Context manager for governed work with automatic failure release.

        Call record_completion inside the ``with`` block after successful
        downstream work. If the block exits before completion is recorded, any
        held budget and rate-limit capacity is released.
        """
        result = self.process_request(request, org_id, user_id, agent_id)
        try:
            yield result
        finally:
            if self._has_unfinished_admission(result):
                self.record_failure(result)
    
    def record_completion(
        self,
        org_id: str,
        user_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> float:
        """
        Record a completed API call.
        
        Should be called after each successful API call to track
        actual usage. Pass the ``governance`` metadata returned by
        process_request so token and budget reservations can be reconciled.
        
        Returns the calculated cost.
        """
        completion_metadata = dict(metadata or {})
        governance_metadata = self._extract_governance_metadata(
            completion_metadata
        )
        rate_limit_acquisition = governance_metadata.get("rate_limit_acquisition")
        if rate_limit_acquisition:
            self.rate_limiter.record_actual_usage(
                rate_limit_acquisition["scopes"],
                rate_limit_acquisition["estimated_input_tokens"],
                rate_limit_acquisition["estimated_output_tokens"],
                input_tokens,
                output_tokens,
            )

        reservation_id = governance_metadata.get("budget_reservation_id")
        if reservation_id:
            completion_metadata["budget_reservation_id"] = reservation_id

        # Record at user level; BudgetManager rolls up org/global spend
        # from the metadata when the cost event subscriber records it.
        event = self.cost_tracker.record(
            scope_type="user",
            scope_id=user_id,
            model_id=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached_tokens,
            metadata={
                "org_id": org_id,
                "agent_id": agent_id,
                **completion_metadata
            }
        )

        self._mark_governance_finalized(governance_metadata)
        
        return event.cost
    
    def get_dashboard_data(self, hours: int = 24) -> Dict:
        """Get data for monitoring dashboards."""
        return {
            "costs": self.cost_tracker.export_for_dashboard(hours=hours),
            "alerts": self.alert_manager.get_alert_summary(hours=hours),
            "degradations": self.degradation_manager.get_degradation_stats()
        }


def example_usage():
    """Demonstrate the cost governance system."""
    
    # Create governor with default settings. Read the Slack webhook from
    # an environment variable rather than embedding a literal URL: webhook
    # URLs are secrets, and a single literal token can overflow the PDF
    # code-block right margin (no break opportunity inside one token).
    # Use .get() with an empty default so an unset env var does not raise
    # KeyError before the user has a chance to configure alerting.
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not slack_webhook:
        raise RuntimeError(
            "Set SLACK_WEBHOOK_URL to enable Slack alerts before running this "
            "example."
        )
    governor = AgentCostGovernor.create_default(
        global_daily_budget=500.0,
        slack_webhook=slack_webhook,
    )
    
    # Configure an organization
    governor.configure_organization(
        org_id="acme-corp",
        tokens_per_minute=100_000,
        daily_budget=200.0,
        monthly_budget=5000.0
    )
    
    # Configure a user
    governor.configure_user(
        user_id="user-123",
        org_id="acme-corp",
        tokens_per_minute=10_000,
        daily_budget=50.0
    )
    
    # Process a request
    request = {
        "model": "claude-3-sonnet",
        "messages": [{"role": "user", "content": "Analyze this data..."}],
        "max_tokens": 2000,
        "estimated_input_tokens": 500,
        "estimated_output_tokens": 1500
    }
    
    result = governor.process_request(
        request,
        org_id="acme-corp",
        user_id="user-123",
        agent_id="data-analyst"
    )
    
    if result.get("approved"):
        # Make the actual API call here
        # actual_response = anthropic_client.messages.create(...)
        
        # Record the completion
        governor.record_completion(
            org_id="acme-corp",
            user_id="user-123",
            model="claude-3-sonnet",
            input_tokens=487,
            output_tokens=1423,
            agent_id="data-analyst",
            metadata=result["governance"]
        )
    else:
        # Handle degraded or rejected request
        if result.get("strategy") == "downgrade_model":
            # Use the degraded request
            modified_request = result["modified_request"]
            # Make API call with modified request
        elif result.get("strategy") == "queue":
            # Request was queued
            print(f"Queued: {result.get('user_message')}")
        else:
            # Request was rejected
            print(f"Rejected: {result.get('error')}")

# ============================================================================
# Block 9 (chapter block #9) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_9_listing = r"""
# Hypothetical budget exercise:
# assume $0.30/paper after retrieval, prompting, summarization,
# and bookkeeping. Replace this with your measured unit cost.
# Validation: 500 papers * $0.30/paper = $150

Hour 1:  500 papers analyzed          $150
Hour 2:  2,500 papers (5x growth)     $750
Hour 3:  12,500 papers                $3,750
Hour 4:  62,500 papers                $18,750
Hour 5:  312,500 papers               $93,750
         (manual cutoff)

Total hypothetical exposure: $117,000+ before cutoff
"""

# ============================================================================
# Block 10 (chapter block #10) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_10_listing = r"""
15 minutes: 166 papers analyzed       $49.80
            Next paper rejected (user daily budget: $50)
            
System response:
1. Blocked further processing
2. Alerted user: "Daily analysis budget would be exceeded"
3. Offered option to continue with a less expensive model
4. Cached partial results for immediate delivery

Modeled cost: $49.80
"""
