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
    _timestamps: deque = field(default_factory=deque)  # bounded by try_acquire below
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
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
            now = time.time()
            self._clean_old_timestamps(now)
            
            if len(self._timestamps) < self.max_requests:
                self._timestamps.append(now)
                return True
            return False
    
    def wait_for_capacity(self, timeout: Optional[float] = None) -> bool:
        """
        Block until capacity is available or timeout is reached.
        
        Args:
            timeout: Maximum seconds to wait. None means wait indefinitely.
            
        Returns:
            True if capacity was acquired, False if timeout was reached.
        """
        start_time = time.time()
        
        while True:
            if self.try_acquire():
                return True
            
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    return False
            
            # Calculate sleep time until oldest request expires
            with self._lock:
                if self._timestamps:
                    sleep_time = (
                        self._timestamps[0] + self.window_seconds - time.time()
                    )
                    sleep_time = max(0.01, min(sleep_time, 1.0))
                else:
                    sleep_time = 0.01
            
            time.sleep(sleep_time)
    
    def get_remaining_capacity(self) -> int:
        """Return the number of requests available in the current window."""
        with self._lock:
            self._clean_old_timestamps(time.time())
            return self.max_requests - len(self._timestamps)
    
    def get_reset_time(self) -> Optional[float]:
        """
        Return seconds until the next request slot becomes available.
        
        Returns None if capacity is available now.
        """
        with self._lock:
            self._clean_old_timestamps(time.time())
            if len(self._timestamps) < self.max_requests:
                return None
            if self._timestamps:
                return self._timestamps[0] + self.window_seconds - time.time()
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
    _last_refill: float = field(default_factory=time.time)
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
            self._refill(time.time())
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False
    
    def get_available_tokens(self) -> int:
        """Return currently available tokens."""
        with self._lock:
            self._refill(time.time())
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
        clamped to [0, capacity]. Takes the bucket's own lock so callers do
        not have to reach across the bucket boundary.
        """
        with self._lock:
            self._tokens = max(0.0, min(float(self.capacity), self._tokens + delta))


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
                "timestamp": time.time(),
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
        with self._lock:
            input_diff = actual_input - estimated_input
            output_diff = actual_output - estimated_output

            # Reconcile against each bucket through its own lock; underestimates
            # subtract more tokens (delta<0), overestimates refund them. Each
            # bucket clamps to [0, capacity].
            self._input_bucket.adjust(-input_diff)
            self._output_bucket.adjust(-output_diff)
            self._total_bucket.adjust(-(input_diff + output_diff))
    
    def get_usage_stats(self, window_seconds: float = 60.0) -> Dict:
        """Return usage statistics for the specified time window."""
        now = time.time()
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
        with self._lock:
            self._input_bucket.refund(input_tokens)
            self._output_bucket.refund(output_tokens)
            self._total_bucket.refund(input_tokens + output_tokens)

# ============================================================================
# Block 3 (chapter listing #3)
# ============================================================================

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any
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
    hierarchy. This ensures that even if a user has available quota,
    they cannot exceed organization or global limits.
    """
    
    global_config: RateLimitConfig
    _limiters: Dict[str, TokenRateLimiter] = field(default_factory=dict)
    _request_limiters: Dict[str, RequestRateLimiter] = field(default_factory=dict)
    _configs: Dict[str, RateLimitConfig] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
        # Initialize global limiters
        self._initialize_limiters("global", self.global_config)
    
    def _initialize_limiters(self, key: str, config: RateLimitConfig) -> None:
        """Create rate limiters for a given configuration."""
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
        key = f"{scope.value}:{identifier}"
        
        with self._lock:
            self._initialize_limiters(key, config)
            
            # Store parent relationship for hierarchy traversal
            if parent_scope and parent_identifier:
                parent_key = f"{parent_scope.value}:{parent_identifier}"
                # In a full implementation, store this relationship
                # for quota inheritance and rollup reporting
    
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
        # Always check global limits
        keys_to_check = ["global"] + [
            f"{scope.value}:{identifier}" for scope, identifier in scopes
        ]
        
        with self._lock:
            for key in keys_to_check:
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
        keys_to_check = ["global"] + [
            f"{scope.value}:{identifier}" for scope, identifier in scopes
        ]
        
        acquired_keys: List[Tuple[str, str]] = []

        with self._lock:
            try:
                for key in keys_to_check:
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
                for limiter_type, key in acquired_keys:
                    if limiter_type == "token" and key in self._limiters:
                        self._limiters[key].refund(input_tokens, output_tokens)
                    # Request limiters expose no rollback; failing fast on
                    # the request limit is acceptable because request slots
                    # refill on a fixed cadence.
                logger.warning(
                    f"Rate limit exceeded at {e.scope}: {e.reason}"
                )
                return False, e.scope, e.reason
    
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
from typing import Optional, Dict, List, Callable
from enum import Enum
from datetime import datetime, timedelta, timezone
import threading
import json
import logging

logger = logging.getLogger(__name__)


class BudgetPeriod(Enum):
    """Time periods for budget allocation."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


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
        input_cost = (input_tokens / 1000) * self.input_cost_per_1k_tokens
        output_cost = (output_tokens / 1000) * self.output_cost_per_1k_tokens
        
        cached_cost = 0.0
        if cached_tokens and self.cached_input_cost_per_1k_tokens:
            cached_cost = (
                (cached_tokens / 1000) * self.cached_input_cost_per_1k_tokens
            )
        
        return input_cost + output_cost + cached_cost


# Standard pricing - ILLUSTRATIVE ONLY
# These values represent approximate pricing tiers at time of writing.
# IMPORTANT: Always verify current pricing from provider documentation
# before production deployment, as rates change frequently (typically
# decreasing 20-40% annually for equivalent capability tiers).
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
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alerts_sent: Dict[str, bool] = field(default_factory=dict)
    
    @property
    def remaining(self) -> float:
        return max(0.0, self.allocated_amount - self.spent_amount)
    
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
        elif self.period == BudgetPeriod.MONTHLY:
            return now >= self.period_start + timedelta(days=30)
        return False
    
    def reset_if_expired(self) -> bool:
        """Reset budget if period has expired. Returns True if reset."""
        if self.is_period_expired():
            self.spent_amount = 0.0
            self.period_start = datetime.now(timezone.utc)
            self.alerts_sent = {}
            return True
        return False


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
    
    _budgets: Dict[str, Budget] = field(default_factory=dict)
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
    
    def allocate_budget(
        self,
        scope_type: str,
        scope_id: str,
        period: BudgetPeriod,
        amount: float
    ) -> Budget:
        """
        Allocate a budget for a specific scope and period.
        
        If a budget already exists, this updates the allocation.
        Existing spend is preserved.
        """
        key = self._budget_key(scope_type, scope_id, period)
        
        with self._lock:
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
        """
        Check if a cost is within budget.
        
        Returns:
            Tuple of (within_budget, remaining_after, message)
        """
        key = self._budget_key(scope_type, scope_id, period)
        
        with self._lock:
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
        """
        Record spending against budgets.
        
        Records against all configured budget periods for the scope
        and checks alert thresholds.
        
        Returns the calculated cost.
        """
        # Calculate cost
        pricing = self.pricing.get(model_id)
        if not pricing:
            logger.warning(f"No pricing found for model {model_id}")
            # Use a conservative estimate
            cost = ((input_tokens + output_tokens) / 1000) * 0.01
        else:
            cost = pricing.calculate_cost(input_tokens, output_tokens, cached_tokens)
        
        with self._lock:
            # Record against all budget periods for this scope
            for period in BudgetPeriod:
                key = self._budget_key(scope_type, scope_id, period)
                if key in self._budgets:
                    budget = self._budgets[key]
                    budget.reset_if_expired()
                    budget.spent_amount += cost
                    
                    # Check alert thresholds
                    self._check_alerts(budget)
            
            # Store in spending history
            self._spending_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "scope_type": scope_type,
                "scope_id": scope_id,
                "model_id": model_id,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cached_tokens": cached_tokens,
                "cost": cost,
                "metadata": metadata or {}
            })
        
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
        """Get status of all budgets for a scope."""
        status = {}
        
        with self._lock:
            for period in BudgetPeriod:
                key = self._budget_key(scope_type, scope_id, period)
                if key in self._budgets:
                    budget = self._budgets[key]
                    budget.reset_if_expired()
                    
                    status[period.value] = {
                        "allocated": budget.allocated_amount,
                        "spent": budget.spent_amount,
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
                    (datetime.now(timezone.utc) - budget.period_start).seconds / 3600
                )
            elif period == BudgetPeriod.DAILY:
                hours_remaining = 24 - (
                    (datetime.now(timezone.utc) - budget.period_start).seconds / 3600
                )
            elif period == BudgetPeriod.WEEKLY:
                hours_remaining = 168 - (
                    (datetime.now(timezone.utc) - budget.period_start).total_seconds() / 3600
                )
            else:  # Monthly
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
from typing import Optional, Dict, List, Callable, Any
from enum import Enum
import time
import logging

logger = logging.getLogger(__name__)


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
    
    _request_queue: List[Dict] = field(default_factory=list)
    _response_cache: Dict[str, Dict] = field(default_factory=dict)
    _degradation_stats: Dict[str, int] = field(default_factory=dict)
    
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
            
            # Check if we have budget/rate capacity for the cheaper model
            if self._check_capacity_for_model(request, downgraded_model):
                logger.info(
                    f"Downgrading from {current_model} to {downgraded_model}"
                )
                return {
                    "success": True,
                    "strategy": "downgrade_model",
                    "original_model": current_model,
                    "downgraded_model": downgraded_model,
                    "modified_request": {**request, "model": downgraded_model},
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
        
        # Add instruction to be concise
        original_system = request.get("system", "")
        modified_request["system"] = (
            original_system +
            "\n\nIMPORTANT: Due to resource constraints, provide a concise "
            "response. Focus on the most critical information only."
        )
        
        return {
            "success": True,
            "strategy": "reduce_quality",
            "original_max_tokens": original_max_tokens,
            "reduced_max_tokens": reduced_max_tokens,
            "modified_request": modified_request,
            "user_message": (
                "Response may be shorter due to current load"
                if self.config.notify_user else None
            )
        }
    
    def _try_queue(self, request: Dict) -> Dict:
        """Queue the request for later processing."""
        queue_entry = {
            "request": request,
            "queued_at": time.time(),
            "expires_at": time.time() + self.config.max_queue_wait
        }
        
        self._request_queue.append(queue_entry)
        
        estimated_wait = self._estimate_queue_wait()
        
        return {
            "success": True,
            "strategy": "queue",
            "queue_position": len(self._request_queue),
            "estimated_wait_seconds": estimated_wait,
            "user_message": (
                f"Request queued. Estimated wait: {int(estimated_wait)}s"
                if self.config.notify_user else None
            )
        }
    
    def _try_cache_fallback(self, request: Dict) -> Dict:
        """Return cached result if available."""
        cache_key = self._compute_cache_key(request)
        
        if cache_key in self._response_cache:
            cached = self._response_cache[cache_key]
            
            # Check if cache is still valid
            if time.time() - cached["cached_at"] < self.config.cache_ttl_seconds:
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
    
    def _check_capacity_for_model(self, request: Dict, model: str) -> bool:
        """Check if there's capacity for a specific model."""
        if not self.rate_limiter:
            return True
        
        # Estimate tokens for the downgraded model
        # (cheaper models might use more tokens for same task)
        estimated_input = request.get("estimated_input_tokens", 1000)
        estimated_output = request.get("estimated_output_tokens", 500)
        
        scopes = request.get("scopes", [])
        allowed, _, _ = self.rate_limiter.check_all_limits(
            scopes, estimated_input, estimated_output
        )
        
        return allowed
    
    def _calculate_retry_after(self, blocked_scope: str) -> float:
        """
        Calculate recommended retry delay using decorrelated jitter.

        The decorrelated jitter approach~\cite{aws-backoff}, building on exponential
        backoff principles~\cite{metcalfe-backoff}, reduces correlation between retry
        attempts from multiple clients, preventing thundering herd problems.

        Formula: sleep = min(cap, random(base, sleep * 3))

        Convergence: The expected delay E[d_i] = (base + 3*d_{i-1})/2 converges to a
        stationary distribution with mean ~1.5*base, spreading retries more uniformly
        than standard exponential backoff which clusters around power-of-2 intervals.
        """
        import random

        base_delay = 1.0
        cap = 60.0
        # In production, track previous delay per scope
        previous_delay = getattr(self, '_last_delay', base_delay)

        delay = min(cap, random.uniform(base_delay, previous_delay * 3))
        self._last_delay = delay
        return delay
    
    def _estimate_queue_wait(self) -> float:
        """Estimate queue wait time based on processing rate."""
        # Simple estimate: 5 seconds per queued item
        return len(self._request_queue) * 5.0
    
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
        self._degradation_stats[strategy] = (
            self._degradation_stats.get(strategy, 0) + 1
        )
    
    def cache_response(self, request: Dict, response: Dict) -> None:
        """Cache a response for potential future fallback."""
        cache_key = self._compute_cache_key(request)
        self._response_cache[cache_key] = {
            "response": response,
            "cached_at": time.time()
        }
    
    def get_degradation_stats(self) -> Dict[str, int]:
        """Return statistics on degradation events."""
        return self._degradation_stats.copy()
    
    def process_queue(
        self,
        processor: Callable[[Dict], Dict]
    ) -> List[Dict]:
        """
        Process queued requests when capacity is available.
        
        Args:
            processor: Function to process a request and return response
            
        Returns:
            List of processed results
        """
        results = []
        now = time.time()
        
        # Remove expired entries
        self._request_queue = [
            entry for entry in self._request_queue
            if entry["expires_at"] > now
        ]
        
        # Process what we can
        while self._request_queue:
            entry = self._request_queue[0]
            
            # Check if we have capacity now
            request = entry["request"]
            if self._check_capacity_for_model(
                request, request.get("model", "claude-3-opus")
            ):
                self._request_queue.pop(0)
                result = processor(request)
                results.append({
                    "request": request,
                    "result": result,
                    "queue_time": now - entry["queued_at"]
                })
            else:
                # No capacity, stop processing
                break
        
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
    Real-time cost tracking and aggregation system.
    
    Provides streaming cost updates, aggregation at multiple time
    granularities, and integration with monitoring systems.
    """
    
    pricing: Dict[str, ModelPricing] = field(
        default_factory=lambda: STANDARD_PRICING.copy()
    )
    retention_hours: int = 168  # 7 days
    # Hard cap on retained cost events to bound memory growth in
    # long-running trackers. Oldest events are dropped FIFO once the
    # cap is reached.
    max_cost_events: int = 100_000

    _events: "deque[CostEvent]" = field(init=False)
    _aggregations: Dict[str, CostAggregation] = field(default_factory=dict)
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
    
    def _cleanup_old_events(self) -> None:
        """Remove events older than retention period."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)
        # Rebuild as a deque with the same maxlen so the bounded-memory
        # guarantee from __post_init__ survives cleanup.
        self._events = deque(
            (e for e in self._events if e.timestamp >= cutoff),
            maxlen=self.max_cost_events,
        )
    
    def subscribe(self, callback: Callable[[CostEvent], None]) -> None:
        """Subscribe to real-time cost events."""
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
    
    _rules: Dict[str, AlertRule] = field(default_factory=dict)
    _alerts: List[Alert] = field(default_factory=list)
    _last_alert_times: Dict[str, datetime] = field(default_factory=dict)
    _metric_history: Dict[str, deque] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    def __post_init__(self):
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
        
        with self._lock:
            if key not in self._metric_history:
                self._metric_history[key] = deque(maxlen=1000)
            
            self._metric_history[key].append({
                "timestamp": datetime.now(timezone.utc),
                "value": value
            })
    
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
            for rule_id, rule in self._rules.items():
                if not rule.enabled:
                    continue
                
                # Check cooldown
                cooldown_key = f"{rule_id}:{scope_type}:{scope_id}"
                if cooldown_key in self._last_alert_times:
                    time_since_last = (
                        datetime.now(timezone.utc) -
                        self._last_alert_times[cooldown_key]
                    )
                    if time_since_last < timedelta(minutes=rule.cooldown_minutes):
                        continue
                
                # Evaluate rule condition
                try:
                    if rule.condition(context):
                        alert = self._create_alert(rule, context)
                        triggered_alerts.append(alert)
                        
                        # Update cooldown
                        self._last_alert_times[cooldown_key] = datetime.now(timezone.utc)
                        
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
    """Create a Slack notification channel."""
    import urllib.request
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
        
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req)
    
    return send


def pagerduty_notification_channel(
    routing_key: str,
    only_critical: bool = True
) -> Callable[[Alert], None]:
    """Create a PagerDuty notification channel."""
    import urllib.request
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
        
        req = urllib.request.Request(
            "https://events.pagerduty.com/v2/enqueue",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req)
    
    return send

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

from dataclasses import dataclass
from typing import Optional, Dict, List, Any
import logging

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
            BudgetPeriod.MONTHLY, monthly_budget
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
        
        # Check budget
        for scope_type, scope_id in [("organization", org_id), ("user", user_id)]:
            for period in [BudgetPeriod.DAILY, BudgetPeriod.MONTHLY]:
                within_budget, remaining, msg = self.budget_manager.check_budget(
                    scope_type, scope_id, period, estimated_cost
                )
                if not within_budget:
                    return self.degradation_manager.handle_rate_limit(
                        request, f"{scope_type}:{scope_id}", msg
                    )
        
        # Check rate limits
        allowed, blocked_scope, reason = self.rate_limiter.check_all_limits(
            scopes, estimated_input, estimated_output
        )
        
        if not allowed:
            return self.degradation_manager.handle_rate_limit(
                request, blocked_scope, reason
            )
        
        # Acquire capacity
        success, blocked_scope, reason = self.rate_limiter.acquire(
            scopes, estimated_input, estimated_output
        )
        
        if not success:
            return self.degradation_manager.handle_rate_limit(
                request, blocked_scope, reason
            )
        
        # Request approved
        return {
            "approved": True,
            "request": request,
            "scopes": scopes
        }
    
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
        actual usage.
        
        Returns the calculated cost.
        """
        # Record at user level (will roll up to org)
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
                **(metadata or {})
            }
        )
        
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
    
    # Create governor with default settings
    governor = AgentCostGovernor.create_default(
        global_daily_budget=500.0,
        slack_webhook="https://hooks.slack.com/services/xxx"
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
            agent_id="data-analyst"
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
# Cost projection assuming ~1000 tokens/paper at $0.015/1K input + $0.075/1K output
# Validation: 500 papers * 1000 tokens * ($0.015 + $0.075)/1000 = $45 (input) + $225 (output)
# Actual costs vary based on paper length and response verbosity

Hour 1:  500 papers analyzed          $150
Hour 2:  2,500 papers (5x growth)     $750
Hour 3:  12,500 papers                $3,750
Hour 4:  62,500 papers                $18,750
Hour 5:  312,500 papers               $93,750
         (API provider cuts access)

Total potential damage: $47,000+ before intervention
"""

# ============================================================================
# Block 10 (chapter block #10) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_10_listing = r"""
15 minutes: 125 papers analyzed       $37.50
            Daily budget hit (user: $50)
            
System response:
1. Blocked further processing
2. Alerted user: "Daily analysis budget reached"
3. Offered option to continue with Haiku model
4. Cached partial results for immediate delivery

Actual cost: $37.50
"""
