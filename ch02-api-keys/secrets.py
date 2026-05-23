"""
API Keys and Secrets Management

Code listings from Chapter 02, Book 2:
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

# DO NOT DO THIS - Hardcoded secrets
class ResearchAgent:
    def __init__(self):
        self.openai_key = "<EXAMPLE-DO-NOT-USE>"
        self.serp_api_key = "<EXAMPLE-DO-NOT-USE>"
        self.database_password = "<EXAMPLE-DO-NOT-USE>"
        self.slack_webhook = "<https://hooks.slack.com/services/PLACEHOLDER>"

# ============================================================================
# Block 2 (chapter listing #2)
# ============================================================================

{
    "timestamp": "2026-04-28T14:32:17.892Z",
    "event_type": "secret_access",
    "secret_id": "prod/openai/api-key",
    "secret_version": "v7",
    "accessor": {
        "agent_id": "research-agent-prod-3",
        "agent_role": "research",
        "instance_id": "i-0abc123def456",
        "ip_address": "10.0.1.47"
    },
    "operation": "read",
    "result": "success",
    "context": {
        "task_id": "task-789xyz",
        "correlation_id": "corr-456abc",
        "purpose": "external_api_call"
    }
}

# ============================================================================
# Block 3 (chapter listing #3)
# ============================================================================

"""
Secret management for agentic AI systems.

This module provides a unified interface for secret management across multiple
backends, with support for caching, rotation, and audit logging.

Code Navigation (line numbers are approximate):
- Enums & Data Models (SecretBackend, SecretMetadata, CachedSecret) ... ~20
- Audit Logging (AuditEvent, AuditLogger, StructuredAuditLogger) ... ~55
- Backend Interface (SecretBackendProvider ABC) ... ~120
- HashiCorp Vault Provider ... ~185
- AWS Secrets Manager Provider ... ~335
- SecretManager (main class) ... ~455
- ScopedSecretContext ... ~895
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Optional
import botocore.exceptions
import hashlib
import json
import logging
import secrets
import threading
import time
import weakref

try:  # Optional provider SDK; keep this module importable without it.
    import hvac  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - dependency not required for examples
    class _HvacStub:
        """Fallback shim so ``except hvac.exceptions.*`` clauses still resolve.

        When the real ``hvac`` package is not installed, the Vault provider's
        error-handling clauses (``except hvac.exceptions.Forbidden`` and
        friends) would otherwise raise ``NameError`` at except-evaluation
        time. The stub exposes the exception names this module references;
        the stub classes never actually fire because no real call site can
        raise them.
        """

        class exceptions:
            class VaultError(Exception):
                pass

            class Forbidden(VaultError):
                pass

            class InvalidPath(VaultError):
                pass

    hvac = _HvacStub  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


class SecretBackend(Enum):
    """Supported secret management backends."""
    HASHICORP_VAULT = "vault"
    AWS_SECRETS_MANAGER = "aws"
    AZURE_KEY_VAULT = "azure"
    ENVIRONMENT = "env"  # For development only


@dataclass
class SecretMetadata:
    """Metadata associated with a secret."""
    secret_id: str
    version: str
    created_at: datetime
    expires_at: Optional[datetime]
    rotation_due: Optional[datetime]
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class CachedSecret:
    """A secret with caching metadata."""
    value: str
    metadata: SecretMetadata
    cached_at: datetime
    ttl_seconds: int
    
    @property
    def is_expired(self) -> bool:
        """Check if the cached value has expired."""
        age = datetime.now(timezone.utc) - self.cached_at
        return age.total_seconds() > self.ttl_seconds


@dataclass
class AuditEvent:
    """An audit event for secret access."""
    timestamp: datetime
    event_type: str
    secret_id: str
    secret_version: Optional[str]
    agent_id: str
    agent_role: str
    operation: str
    result: str
    context: dict[str, Any]
    error_message: Optional[str] = None


class AuditLogger(ABC):
    """Abstract base class for audit logging."""
    
    @abstractmethod
    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        pass


class StructuredAuditLogger(AuditLogger):
    """
    Structured audit logger that outputs JSON-formatted events.
    
    In production, this would write to a secure, append-only log
    aggregation system like Splunk, ELK, or CloudWatch Logs.
    """
    
    def __init__(
        self,
        logger_name: str = "secret_audit",
        output_handler: Optional[Callable[[dict], None]] = None
    ):
        self._logger = logging.getLogger(logger_name)
        self._output_handler = output_handler
        
    def log(self, event: AuditEvent) -> None:
        """Log an audit event as structured JSON."""
        event_dict = {
            # isoformat() on a tz-aware datetime already emits an offset
            # ("+00:00"); appending "Z" would produce an invalid ISO 8601
            # string. Normalize to UTC and format explicitly with a "Z".
            "timestamp": event.timestamp.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            ) + "Z",
            "event_type": event.event_type,
            "secret_id": event.secret_id,
            "secret_version": event.secret_version,
            "accessor": {
                "agent_id": event.agent_id,
                "agent_role": event.agent_role,
            },
            "operation": event.operation,
            "result": event.result,
            "context": event.context,
        }
        
        if event.error_message:
            event_dict["error"] = event.error_message
            
        # Output to configured handler or default logger
        if self._output_handler:
            self._output_handler(event_dict)
        else:
            self._logger.info(json.dumps(event_dict))


class SecretBackendProvider(ABC):
    """Abstract base class for secret backend implementations."""
    
    @abstractmethod
    def get_secret(self, secret_id: str, version: Optional[str] = None) -> tuple[str, SecretMetadata]:
        """
        Retrieve a secret from the backend.
        
        Args:
            secret_id: The identifier of the secret to retrieve.
            version: Optional specific version to retrieve.
            
        Returns:
            A tuple of (secret_value, metadata).
            
        Raises:
            SecretNotFoundError: If the secret does not exist.
            SecretAccessDeniedError: If access is denied.
        """
        pass
    
    @abstractmethod
    def rotate_secret(self, secret_id: str) -> tuple[str, SecretMetadata]:
        """
        Rotate a secret, generating a new value.
        
        Args:
            secret_id: The identifier of the secret to rotate.
            
        Returns:
            A tuple of (new_secret_value, metadata).
        """
        pass
    
    @abstractmethod
    def revoke_secret(self, secret_id: str, version: Optional[str] = None) -> None:
        """
        Revoke a secret, making it immediately invalid.
        
        Args:
            secret_id: The identifier of the secret to revoke.
            version: Optional specific version to revoke.
        """
        pass


class SecretNotFoundError(Exception):
    """Raised when a requested secret does not exist."""
    pass


class SecretAccessDeniedError(Exception):
    """Raised when access to a secret is denied."""
    pass


class SecretRotationError(Exception):
    """Raised when secret rotation fails."""
    pass

# ============================================================================
# Block 4 (chapter listing #4)
# ============================================================================

class HashiCorpVaultProvider(SecretBackendProvider):
    """
    HashiCorp Vault secret backend implementation.
    
    This implementation uses AppRole authentication and supports
    the KV v2 secrets engine.
    """
    
    def __init__(
        self,
        vault_addr: str,
        role_id: str,
        secret_id: str,
        namespace: Optional[str] = None,
        mount_point: str = "secret"
    ):
        self._vault_addr = vault_addr
        self._role_id = role_id
        self._secret_id = secret_id
        self._namespace = namespace
        self._mount_point = mount_point
        self._client: Optional[Any] = None
        self._token_expiry: Optional[datetime] = None
        self._lock = threading.Lock()
        
    def _get_client(self) -> Any:
        """Get or create an authenticated Vault client."""
        import hvac
        
        with self._lock:
            # Check if we need to re-authenticate
            if self._client is None or self._is_token_expired():
                # Explicit (connect, read) timeouts so a hung Vault doesn't
                # freeze the calling agent; 5s connect / 10s read fits typical
                # WAN deployments. Raise for high-latency network paths and
                # tune in conjunction with the retry policy below.
                self._client = hvac.Client(
                    url=self._vault_addr,
                    namespace=self._namespace,
                    timeout=(5, 10),
                )
                
                # Authenticate with AppRole
                auth_response = self._client.auth.approle.login(
                    role_id=self._role_id,
                    secret_id=self._secret_id
                )
                
                # Track token expiry for renewal
                # Note: lease_duration behavior may vary by Vault version (tested with Vault 1.12+)
                ttl = auth_response['auth']['lease_duration']
                self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl - 60)
                
            return self._client
    
    def _is_token_expired(self) -> bool:
        """Check if the current token is expired or about to expire."""
        if self._token_expiry is None:
            return True
        return datetime.now(timezone.utc) >= self._token_expiry
        
    def get_secret(self, secret_id: str, version: Optional[str] = None) -> tuple[str, SecretMetadata]:
        """Retrieve a secret from Vault."""
        client = self._get_client()
        
        try:
            # Read from KV v2 secrets engine
            response = client.secrets.kv.v2.read_secret_version(
                path=secret_id,
                version=int(version) if version else None,
                mount_point=self._mount_point
            )
            
            data = response['data']
            secret_value = data['data'].get('value')
            
            if secret_value is None:
                raise SecretNotFoundError(f"Secret {secret_id} has no 'value' key")
            
            metadata = SecretMetadata(
                secret_id=secret_id,
                version=str(data['metadata']['version']),
                created_at=datetime.fromisoformat(
                    data['metadata']['created_time'].replace('Z', '+00:00')
                ),
                expires_at=None,  # KV secrets don't expire
                rotation_due=self._calculate_rotation_due(data['metadata']),
                tags=data['data'].get('tags', {})
            )
            
            return secret_value, metadata
            
        except hvac.exceptions.Forbidden as e:
            raise SecretAccessDeniedError(
                f"Access denied to secret {secret_id}"
            ) from e
        except hvac.exceptions.InvalidPath as e:
            raise SecretNotFoundError(
                f"Secret {secret_id} not found"
            ) from e
        except hvac.exceptions.VaultError:
            raise
    
    def _calculate_rotation_due(self, metadata: dict) -> Optional[datetime]:
        """Calculate when rotation is due based on metadata."""
        # Custom metadata field for rotation policy
        rotation_days = metadata.get('custom_metadata', {}).get('rotation_days')
        if rotation_days:
            created = datetime.fromisoformat(
                metadata['created_time'].replace('Z', '+00:00')
            )
            return created + timedelta(days=int(rotation_days))
        return None
            
    def rotate_secret(self, secret_id: str) -> tuple[str, SecretMetadata]:
        """Rotate a secret in Vault."""
        client = self._get_client()
        
        # Read current secret to preserve tags
        try:
            current = client.secrets.kv.v2.read_secret_version(
                path=secret_id,
                mount_point=self._mount_point
            )
            tags = current['data']['data'].get('tags', {})
        except hvac.exceptions.InvalidPath:
            tags = {}
        except hvac.exceptions.VaultError as e:
            logger.warning(
                f"Could not preserve tags during rotation of {secret_id}: {e}"
            )
            tags = {}

        # Generate new secret value. (secrets imported at module top.)
        new_value = secrets.token_urlsafe(32)
        
        # Write new version
        client.secrets.kv.v2.create_or_update_secret(
            path=secret_id,
            secret={'value': new_value, 'tags': tags},
            mount_point=self._mount_point
        )
        
        # Retrieve updated metadata
        return self.get_secret(secret_id)
    
    def revoke_secret(self, secret_id: str, version: Optional[str] = None) -> None:
        """Revoke a secret version in Vault."""
        client = self._get_client()
        
        if version:
            # Destroy specific version
            client.secrets.kv.v2.destroy_secret_versions(
                path=secret_id,
                versions=[int(version)],
                mount_point=self._mount_point
            )
        else:
            # Delete all versions (metadata remains)
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=secret_id,
                mount_point=self._mount_point
            )


class AWSSecretsManagerProvider(SecretBackendProvider):
    """
    AWS Secrets Manager backend implementation.
    
    Uses IAM role authentication when running on AWS infrastructure,
    or explicit credentials for local development.
    """
    
    def __init__(
        self,
        region_name: str = "us-east-1",
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None
    ):
        self._region_name = region_name
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._client: Optional[Any] = None
        
    def _get_client(self) -> Any:
        """Get or create a Secrets Manager client."""
        if self._client is None:
            import boto3
            from botocore.config import Config

            # Explicit timeouts and retry policy: a hung AWS endpoint
            # would otherwise hold up every secret-read on the agent.
            # 'adaptive' retry mode honors throttling responses with
            # exponential backoff plus jitter.
            client_config = Config(
                connect_timeout=5,
                read_timeout=10,
                retries={"max_attempts": 3, "mode": "adaptive"},
            )

            kwargs = {"region_name": self._region_name, "config": client_config}

            # Only use explicit credentials if provided
            # Otherwise, rely on IAM role or environment
            if self._aws_access_key_id and self._aws_secret_access_key:
                kwargs['aws_access_key_id'] = self._aws_access_key_id
                kwargs['aws_secret_access_key'] = self._aws_secret_access_key

            self._client = boto3.client('secretsmanager', **kwargs)

        return self._client
        
    def get_secret(self, secret_id: str, version: Optional[str] = None) -> tuple[str, SecretMetadata]:
        """Retrieve a secret from AWS Secrets Manager."""
        client = self._get_client()
        
        try:
            kwargs = {'SecretId': secret_id}
            if version:
                kwargs['VersionId'] = version
                
            response = client.get_secret_value(**kwargs)
            
            # Secrets Manager stores either string or binary
            if 'SecretString' in response:
                secret_value = response['SecretString']
            else:
                import base64
                secret_value = base64.b64decode(response['SecretBinary']).decode()
            
            # Get additional metadata
            describe_response = client.describe_secret(SecretId=secret_id)
            
            metadata = SecretMetadata(
                secret_id=secret_id,
                version=response['VersionId'],
                created_at=response['CreatedDate'],
                expires_at=None,
                rotation_due=describe_response.get('NextRotationDate'),
                tags={t['Key']: t['Value'] for t in describe_response.get('Tags', [])}
            )
            
            return secret_value, metadata
            
        except client.exceptions.ResourceNotFoundException:
            raise SecretNotFoundError(f"Secret {secret_id} not found")
        except client.exceptions.AccessDeniedException:
            raise SecretAccessDeniedError(f"Access denied to secret {secret_id}")
            
    def rotate_secret(self, secret_id: str) -> tuple[str, SecretMetadata]:
        """Trigger rotation for a secret in AWS Secrets Manager."""
        client = self._get_client()
        
        try:
            # Trigger the rotation Lambda
            client.rotate_secret(SecretId=secret_id)
            
            # Wait for rotation to complete with exponential backoff + jitter
            # so a flaky describe_secret endpoint does not get hammered by a
            # tight 1-second poll loop. Total budget is roughly the same
            # (~30s worst case) but the backoff distributes load.
            import random
            max_attempts = 8
            base_delay = 0.5
            cap = 8.0
            for attempt in range(max_attempts):
                response = client.describe_secret(SecretId=secret_id)
                if not response.get('RotationInProgress', False):
                    break
                # Exponential backoff: 0.5, 1, 2, 4, 8, 8, 8, 8 seconds
                # with full jitter per the AWS exponential-backoff guidance.
                delay = min(cap, base_delay * (2 ** attempt))
                time.sleep(random.uniform(0, delay))
            else:
                raise SecretRotationError(
                    f"Rotation timeout for secret {secret_id}"
                )
            
            return self.get_secret(secret_id)

        except botocore.exceptions.ClientError as e:
            raise SecretRotationError(f"Failed to rotate {secret_id}: {e}") from e
            
    def revoke_secret(self, secret_id: str, version: Optional[str] = None) -> None:
        """Mark a secret for deletion in AWS Secrets Manager."""
        client = self._get_client()
        
        if version:
            # AWS doesn't support deleting specific versions directly
            # We can deprecate by updating version stage
            client.update_secret_version_stage(
                SecretId=secret_id,
                VersionStage='AWSCURRENT',
                RemoveFromVersionId=version
            )
        else:
            # Schedule deletion (minimum 7 days in AWS)
            # For immediate revocation, update the secret value instead
            client.delete_secret(
                SecretId=secret_id,
                ForceDeleteWithoutRecovery=True
            )

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

class SecretManager:
    """
    Unified secret management for agentic AI systems.
    
    This class provides a high-level interface for secret management with:
    - Multi-backend support (Vault, AWS, Azure)
    - Automatic caching with TTL
    - Background rotation monitoring
    - Comprehensive audit logging
    - Scope-based access control
    
    Example:
        >>> manager = SecretManager(
        ...     agent_id="research-agent-1",
        ...     agent_role="research",
        ...     backend=SecretBackend.AWS_SECRETS_MANAGER,
        ...     backend_config={"region_name": "us-east-1"}
        ... )
        >>> 
        >>> # Get a secret with automatic caching
        >>> api_key = manager.get_secret("openai/api-key")
        >>> 
        >>> # Use context manager for JIT injection
        >>> with manager.scoped_secret("sensitive/payment-key") as key:
        ...     process_payment(key)
        >>> # Secret is cleared from memory after context exits
    """
    
    def __init__(
        self,
        agent_id: str,
        agent_role: str,
        backend: SecretBackend,
        backend_config: dict[str, Any],
        allowed_secret_patterns: Optional[list[str]] = None,
        default_cache_ttl: int = 300,
        audit_logger: Optional[AuditLogger] = None,
        rotation_check_interval: int = 3600
    ):
        """
        Initialize the SecretManager.
        
        Args:
            agent_id: Unique identifier for this agent instance.
            agent_role: Role of this agent (used for access control).
            backend: Which secret backend to use.
            backend_config: Backend-specific configuration.
            allowed_secret_patterns: Glob patterns for secrets this agent can access.
            default_cache_ttl: Default cache TTL in seconds.
            audit_logger: Custom audit logger implementation.
            rotation_check_interval: How often to check for rotation needs (seconds).
        """
        self._agent_id = agent_id
        self._agent_role = agent_role
        self._allowed_patterns = allowed_secret_patterns or ["*"]
        self._default_cache_ttl = default_cache_ttl
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._rotation_check_interval = rotation_check_interval
        
        # Initialize backend provider
        self._provider = self._create_provider(backend, backend_config)
        
        # Secret cache (bounded to avoid unbounded growth in long-running agents)
        from cachetools import TTLCache
        self._cache: TTLCache = TTLCache(maxsize=1000, ttl=default_cache_ttl)
        self._cache_lock = threading.Lock()
        
        # Rotation monitoring
        self._rotation_callbacks: dict[str, list[Callable[[str, str], None]]] = {}
        self._rotation_monitor_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        
        # Start rotation monitor
        self._start_rotation_monitor()
        
    def _create_provider(
        self,
        backend: SecretBackend,
        config: dict[str, Any]
    ) -> SecretBackendProvider:
        """Create the appropriate backend provider."""
        if backend == SecretBackend.HASHICORP_VAULT:
            return HashiCorpVaultProvider(**config)
        elif backend == SecretBackend.AWS_SECRETS_MANAGER:
            return AWSSecretsManagerProvider(**config)
        elif backend == SecretBackend.AZURE_KEY_VAULT:
            # Azure implementation would go here
            raise NotImplementedError("Azure Key Vault support coming soon")
        elif backend == SecretBackend.ENVIRONMENT:
            return EnvironmentSecretProvider(**config)
        else:
            raise ValueError(f"Unknown backend: {backend}")
            
    def _is_secret_allowed(self, secret_id: str) -> bool:
        """Check if this agent is allowed to access the specified secret."""
        import fnmatch
        
        for pattern in self._allowed_patterns:
            if fnmatch.fnmatch(secret_id, pattern):
                return True
        return False
        
    def _audit(
        self,
        event_type: str,
        secret_id: str,
        operation: str,
        result: str,
        version: Optional[str] = None,
        context: Optional[dict] = None,
        error: Optional[str] = None
    ) -> None:
        """Record an audit event."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            secret_id=secret_id,
            secret_version=version,
            agent_id=self._agent_id,
            agent_role=self._agent_role,
            operation=operation,
            result=result,
            context=context or {},
            error_message=error
        )
        self._audit_logger.log(event)
        
    def get_secret(
        self,
        secret_id: str,
        version: Optional[str] = None,
        bypass_cache: bool = False,
        cache_ttl: Optional[int] = None,
        context: Optional[dict] = None
    ) -> str:
        """
        Retrieve a secret value.
        
        Args:
            secret_id: The identifier of the secret to retrieve.
            version: Optional specific version to retrieve.
            bypass_cache: If True, skip the cache and fetch fresh.
            cache_ttl: Override the default cache TTL for this secret.
            context: Additional context for audit logging.
            
        Returns:
            The secret value as a string.
            
        Raises:
            SecretAccessDeniedError: If this agent cannot access the secret.
            SecretNotFoundError: If the secret does not exist.
        """
        # Check access control
        if not self._is_secret_allowed(secret_id):
            self._audit(
                "secret_access",
                secret_id,
                "read",
                "denied",
                context=context,
                error="Access denied by scope policy"
            )
            raise SecretAccessDeniedError(
                f"Agent {self._agent_id} with role {self._agent_role} "
                f"is not allowed to access secret {secret_id}"
            )
        
        cache_key = f"{secret_id}:{version or 'latest'}"
        
        # Check cache first (unless bypassing)
        if not bypass_cache:
            with self._cache_lock:
                if cache_key in self._cache:
                    cached = self._cache[cache_key]
                    if not cached.is_expired:
                        self._audit(
                            "secret_access",
                            secret_id,
                            "read",
                            "success",
                            version=cached.metadata.version,
                            context={**(context or {}), "cache_hit": True}
                        )
                        return cached.value
        
        # Fetch from backend
        try:
            value, metadata = self._provider.get_secret(secret_id, version)
            
            # Cache the result
            ttl = cache_ttl or self._default_cache_ttl
            cached_secret = CachedSecret(
                value=value,
                metadata=metadata,
                cached_at=datetime.now(timezone.utc),
                ttl_seconds=ttl
            )
            
            with self._cache_lock:
                self._cache[cache_key] = cached_secret
            
            self._audit(
                "secret_access",
                secret_id,
                "read",
                "success",
                version=metadata.version,
                context={**(context or {}), "cache_hit": False}
            )
            
            return value
            
        except Exception as e:
            self._audit(
                "secret_access",
                secret_id,
                "read",
                "failure",
                context=context,
                error=str(e)
            )
            raise
            
    def scoped_secret(
        self,
        secret_id: str,
        context: Optional[dict] = None
    ) -> "ScopedSecretContext":
        """
        Get a secret with automatic cleanup via context manager.
        
        This implements just-in-time secret injection. The secret is
        fetched when entering the context and cleared from memory
        when exiting.
        
        Example:
            >>> with manager.scoped_secret("api/key") as key:
            ...     make_api_call(key)
            >>> # key is now cleared from memory
        """
        return ScopedSecretContext(self, secret_id, context)
        
    def invalidate_cache(self, secret_id: Optional[str] = None) -> None:
        """
        Invalidate cached secrets.
        
        Args:
            secret_id: If provided, invalidate only this secret.
                      If None, invalidate all cached secrets.
        """
        with self._cache_lock:
            if secret_id:
                keys_to_remove = [
                    k for k in self._cache.keys()
                    if k.startswith(f"{secret_id}:")
                ]
                for key in keys_to_remove:
                    del self._cache[key]
            else:
                self._cache.clear()
                
    def register_rotation_callback(
        self,
        secret_id: str,
        callback: Callable[[str, str], None]
    ) -> None:
        """
        Register a callback to be invoked when a secret is rotated.
        
        Args:
            secret_id: The secret to monitor.
            callback: Function to call with (secret_id, new_version).
        """
        if secret_id not in self._rotation_callbacks:
            self._rotation_callbacks[secret_id] = []
        self._rotation_callbacks[secret_id].append(callback)
        
    def force_rotation(
        self,
        secret_id: str,
        context: Optional[dict] = None
    ) -> str:
        """
        Force immediate rotation of a secret.
        
        Args:
            secret_id: The secret to rotate.
            context: Additional context for audit logging.
            
        Returns:
            The new secret value.
        """
        if not self._is_secret_allowed(secret_id):
            self._audit(
                "secret_rotation",
                secret_id,
                "rotate",
                "denied",
                context=context,
                error="Access denied by scope policy"
            )
            raise SecretAccessDeniedError(
                f"Agent {self._agent_id} cannot rotate secret {secret_id}"
            )
        
        try:
            new_value, metadata = self._provider.rotate_secret(secret_id)
            
            # Invalidate cache
            self.invalidate_cache(secret_id)
            
            # Notify callbacks
            for callback in self._rotation_callbacks.get(secret_id, []):
                try:
                    callback(secret_id, metadata.version)
                except Exception as e:
                    logger.error(f"Rotation callback failed: {e}")
            
            self._audit(
                "secret_rotation",
                secret_id,
                "rotate",
                "success",
                version=metadata.version,
                context=context
            )
            
            return new_value
            
        except Exception as e:
            self._audit(
                "secret_rotation",
                secret_id,
                "rotate",
                "failure",
                context=context,
                error=str(e)
            )
            raise
            
    def emergency_revoke(
        self,
        secret_id: str,
        version: Optional[str] = None,
        context: Optional[dict] = None
    ) -> None:
        """
        Emergency revocation of a secret.
        
        This immediately invalidates the secret. Use with caution
        as it may disrupt running operations.
        
        Args:
            secret_id: The secret to revoke.
            version: Optional specific version to revoke.
            context: Additional context for audit logging.
        """
        self._audit(
            "secret_revocation",
            secret_id,
            "revoke",
            "initiated",
            version=version,
            context={**(context or {}), "emergency": True}
        )
        
        try:
            self._provider.revoke_secret(secret_id, version)
            
            # Invalidate all cached versions
            self.invalidate_cache(secret_id)
            
            self._audit(
                "secret_revocation",
                secret_id,
                "revoke",
                "success",
                version=version,
                context=context
            )
            
        except Exception as e:
            self._audit(
                "secret_revocation",
                secret_id,
                "revoke",
                "failure",
                version=version,
                context=context,
                error=str(e)
            )
            raise
            
    def _start_rotation_monitor(self) -> None:
        """Start the background rotation monitoring thread."""
        self._rotation_monitor_thread = threading.Thread(
            target=self._rotation_monitor_loop,
            daemon=True,
            name=f"SecretRotationMonitor-{self._agent_id}"
        )
        self._rotation_monitor_thread.start()
        
    def _rotation_monitor_loop(self) -> None:
        """Background loop that checks for needed rotations."""
        while not self._shutdown_event.is_set():
            try:
                self._check_rotation_due()
            except Exception as e:
                logger.error(f"Rotation monitor error: {e}")
            
            self._shutdown_event.wait(self._rotation_check_interval)
            
    def _check_rotation_due(self) -> None:
        """Check all monitored secrets for rotation needs."""
        with self._cache_lock:
            for cache_key, cached in list(self._cache.items()):
                if cached.metadata.rotation_due:
                    if datetime.now(timezone.utc) >= cached.metadata.rotation_due:
                        secret_id = cached.metadata.secret_id
                        logger.info(f"Secret {secret_id} is due for rotation")
                        # Trigger rotation callbacks
                        for callback in self._rotation_callbacks.get(secret_id, []):
                            try:
                                callback(secret_id, "rotation_due")
                            except Exception as e:
                                logger.error(f"Rotation callback failed: {e}")
                                
    def shutdown(self) -> None:
        """Gracefully shut down the secret manager."""
        self._shutdown_event.set()
        if self._rotation_monitor_thread:
            self._rotation_monitor_thread.join(timeout=5)
        
        # Clear all cached secrets from memory
        with self._cache_lock:
            for cached in self._cache.values():
                # Overwrite secret value before clearing.
                # NOTE: Python string immutability means this is BEST-EFFORT
                # illustrative; use bytearray for true memory wipe.
                cached.value = "0" * len(cached.value)
            self._cache.clear()


class ScopedSecretContext:
    """
    Context manager for just-in-time secret injection.
    
    This ensures secrets are fetched only when needed and cleared
    from memory as soon as they are no longer required.
    """
    
    def __init__(
        self,
        manager: SecretManager,
        secret_id: str,
        context: Optional[dict] = None
    ):
        self._manager = manager
        self._secret_id = secret_id
        self._context = context
        self._value: Optional[str] = None
        
    def __enter__(self) -> str:
        """Fetch the secret on context entry."""
        self._value = self._manager.get_secret(
            self._secret_id,
            bypass_cache=True,  # Always fetch fresh for JIT
            context={**(self._context or {}), "jit_injection": True}
        )
        return self._value
        
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clear the secret from memory on context exit."""
        if self._value:
            # Overwrite the string in memory
            # Note: Python strings are immutable, so this creates a new string
            # For true secure deletion, use a SecureString class with ctypes
            self._value = "0" * len(self._value)
            self._value = None
        return False


class EnvironmentSecretProvider(SecretBackendProvider):
    """
    Environment variable-based secret provider.

    WARNING: This provider is intended for local development only.
    Never use environment variables for secrets in production.
    See twelve-factor app methodology for config vs secrets distinction.
    """
    
    def __init__(self, prefix: str = "SECRET_"):
        self._prefix = prefix
        
    def get_secret(self, secret_id: str, version: Optional[str] = None) -> tuple[str, SecretMetadata]:
        """Retrieve a secret from environment variables."""
        import os
        
        # Convert secret_id to environment variable name
        env_name = self._prefix + secret_id.upper().replace("/", "_").replace("-", "_")
        
        value = os.environ.get(env_name)
        if value is None:
            raise SecretNotFoundError(
                f"Environment variable {env_name} not found"
            )
        
        metadata = SecretMetadata(
            secret_id=secret_id,
            version="env",
            created_at=datetime.now(timezone.utc),
            expires_at=None,
            rotation_due=None
        )
        
        return value, metadata
        
    def rotate_secret(self, secret_id: str) -> tuple[str, SecretMetadata]:
        """Environment secrets cannot be rotated programmatically."""
        raise NotImplementedError(
            "Environment variable secrets cannot be rotated. "
            "Use a proper secret manager in production."
        )
        
    def revoke_secret(self, secret_id: str, version: Optional[str] = None) -> None:
        """Environment secrets cannot be revoked programmatically."""
        raise NotImplementedError(
            "Environment variable secrets cannot be revoked. "
            "Use a proper secret manager in production."
        )

# ============================================================================
# Block 6 (chapter listing #6)
# ============================================================================

"""
Examples of using the SecretManager in production agent systems.
"""

from typing import Optional
import logging

logging.basicConfig(level=logging.INFO)


def example_basic_usage():
    """Basic secret retrieval and caching."""
    
    # Initialize the secret manager
    manager = SecretManager(
        agent_id="research-agent-prod-001",
        agent_role="research",
        backend=SecretBackend.AWS_SECRETS_MANAGER,
        backend_config={"region_name": "us-east-1"},
        allowed_secret_patterns=[
            "research/*",      # All research secrets
            "shared/search-*"  # Shared search API keys
        ],
        default_cache_ttl=300  # 5 minutes
    )
    
    # Get a secret (will be cached)
    api_key = manager.get_secret(
        "research/openai-api-key",
        context={"task": "document_analysis"}
    )
    
    # Subsequent calls use cache
    api_key_2 = manager.get_secret("research/openai-api-key")
    
    # Force fresh fetch
    api_key_fresh = manager.get_secret(
        "research/openai-api-key",
        bypass_cache=True
    )
    
    # Clean up
    manager.shutdown()


def example_jit_injection():
    """Just-in-time secret injection for sensitive operations."""
    
    manager = SecretManager(
        agent_id="payment-agent-prod-001",
        agent_role="finance",
        backend=SecretBackend.HASHICORP_VAULT,
        backend_config={
            "vault_addr": "https://vault.example.com",
            "role_id": "payment-agent-role",
            "secret_id": "secret-id-from-secure-source",
            "namespace": "production"
        },
        allowed_secret_patterns=["finance/payment-*"]
    )
    
    def process_payment(amount: float, recipient: str):
        """Process a payment using JIT secret injection."""
        
        # Secret is fetched here and cleared after the block
        with manager.scoped_secret("finance/payment-gateway-key") as api_key:
            # api_key is only in memory during this block
            result = call_payment_api(api_key, amount, recipient)
            
        # api_key is now cleared from memory
        return result
    
    def call_payment_api(key: str, amount: float, recipient: str) -> dict:
        """Simulated payment API call."""
        return {"status": "success", "transaction_id": "txn_123"}
    
    # Process payment with automatic secret cleanup
    result = process_payment(100.00, "vendor@example.com")
    
    manager.shutdown()


def example_rotation_handling():
    """Handling automatic secret rotation."""
    
    manager = SecretManager(
        agent_id="api-gateway-agent-001",
        agent_role="gateway",
        backend=SecretBackend.AWS_SECRETS_MANAGER,
        backend_config={"region_name": "us-east-1"},
        allowed_secret_patterns=["gateway/*"],
        rotation_check_interval=300  # Check every 5 minutes
    )
    
    # Define what to do when a secret is rotated
    def on_api_key_rotated(secret_id: str, new_version: str):
        """Handle API key rotation."""
        logging.info(f"Secret {secret_id} rotated to version {new_version}")
        
        # Invalidate any cached connections using the old key
        invalidate_api_connections(secret_id)
        
        # Pre-warm cache with new secret
        manager.get_secret(secret_id, bypass_cache=True)
    
    def invalidate_api_connections(secret_id: str):
        """Invalidate connections using rotated secret."""
        pass  # Implementation depends on your connection pooling
    
    # Register the callback
    manager.register_rotation_callback(
        "gateway/external-api-key",
        on_api_key_rotated
    )
    
    # Normal operation - rotation is handled in background
    while True:
        api_key = manager.get_secret("gateway/external-api-key")
        # Use the key...
        break  # For example purposes
    
    manager.shutdown()


def example_multi_tenant_isolation():
    """Demonstrate secret isolation for multi-tenant agents."""
    
    class TenantAwareSecretManager:
        """
        Wrapper that ensures tenant isolation for secret access.
        
        Each tenant can only access secrets within their namespace.
        """
        
        def __init__(
            self,
            tenant_id: str,
            base_manager: SecretManager
        ):
            self._tenant_id = tenant_id
            self._manager = base_manager
            
        def get_secret(self, secret_name: str, **kwargs) -> str:
            """Get a tenant-scoped secret."""
            # Prefix all secret IDs with tenant namespace
            tenant_secret_id = f"tenants/{self._tenant_id}/{secret_name}"
            return self._manager.get_secret(tenant_secret_id, **kwargs)
    
    # Create base manager with tenant wildcard access
    base_manager = SecretManager(
        agent_id="multi-tenant-agent-001",
        agent_role="customer_service",
        backend=SecretBackend.HASHICORP_VAULT,
        backend_config={
            "vault_addr": "https://vault.example.com",
            "role_id": "multi-tenant-role",
            "secret_id": "secret-from-secure-source"
        },
        # Pattern allows access to any tenant's secrets
        # Access control is enforced by TenantAwareSecretManager
        allowed_secret_patterns=["tenants/*"]
    )
    
    # Create tenant-specific managers
    acme_secrets = TenantAwareSecretManager("acme-corp", base_manager)
    globex_secrets = TenantAwareSecretManager("globex-inc", base_manager)
    
    # Each tenant can only access their own secrets
    acme_api_key = acme_secrets.get_secret("api-key")  # tenants/acme-corp/api-key
    globex_api_key = globex_secrets.get_secret("api-key")  # tenants/globex-inc/api-key
    
    base_manager.shutdown()


def example_emergency_revocation():
    """Demonstrate emergency secret revocation procedure."""
    
    manager = SecretManager(
        agent_id="security-admin-001",
        agent_role="security_admin",
        backend=SecretBackend.HASHICORP_VAULT,
        backend_config={
            "vault_addr": "https://vault.example.com",
            "role_id": "security-admin-role",
            "secret_id": "admin-secret-id"
        },
        allowed_secret_patterns=["*"]  # Admin has full access
    )
    
    def handle_security_incident(
        compromised_secret_id: str,
        incident_id: str
    ):
        """Handle a security incident requiring secret revocation."""
        
        context = {
            "incident_id": incident_id,
            "reason": "potential_compromise",
            "initiated_by": "security_team"
        }
        
        # Step 1: Revoke the compromised secret immediately
        logging.warning(
            f"SECURITY: Revoking compromised secret {compromised_secret_id}"
        )
        manager.emergency_revoke(
            compromised_secret_id,
            context=context
        )
        
        # Step 2: Force rotation to generate new credentials
        logging.info(f"Generating new credentials for {compromised_secret_id}")
        new_value = manager.force_rotation(
            compromised_secret_id,
            context=context
        )
        
        # Step 3: Notify dependent systems
        notify_dependent_systems(compromised_secret_id, incident_id)
        
        return new_value
    
    def notify_dependent_systems(secret_id: str, incident_id: str):
        """Notify systems that depend on the rotated secret."""
        logging.info(
            f"Notifying dependent systems of secret rotation "
            f"for incident {incident_id}"
        )
    
    # Simulate handling an incident
    # handle_security_incident("api/external-service-key", "INC-2024-001")
    
    manager.shutdown()

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

class CustomerServiceAgent:
    def __init__(self, client_id: str):
        self.config = load_config(f"/app/config/{client_id}.json")
        self.crm_api_key = self.config["crm_api_key"]
        self.email_api_key = self.config["email_api_key"]
        self.slack_webhook = self.config["slack_webhook"]

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

def create_client_agent(client_id: str) -> CustomerServiceAgent:
    """Create a customer service agent for a specific client."""
    
    # Get client-specific Vault configuration
    vault_config = get_vault_config_for_client(client_id)
    
    secret_manager = SecretManager(
        agent_id=f"cs-agent-{client_id}-{uuid.uuid4().hex[:8]}",
        agent_role="customer_service",
        backend=SecretBackend.HASHICORP_VAULT,
        backend_config={
            "vault_addr": vault_config.vault_addr,
            "role_id": vault_config.role_id,
            "secret_id": vault_config.secret_id,
            "namespace": f"clients/{client_id}"  # Client-specific namespace
        },
        # Agent can only access this client's secrets
        allowed_secret_patterns=[f"{client_id}/*"],
        default_cache_ttl=300
    )
    
    return CustomerServiceAgent(client_id, secret_manager)

# ============================================================================
# Block 9 (chapter listing #9)
# ============================================================================

import os
import uuid  # noqa: F401  (used elsewhere in this module's examples)

# Module identifier embedded with audit events; bump on platform releases.
__version__ = "1.0.0"


def send_to_siem(endpoint: str, event: dict) -> None:
    """Sync stub; replace with your SIEM client.

    If you wrap an async client, use ``asyncio.run()`` at the boundary or
    convert ``SIEMAuditLogger.log`` itself to ``async``. Earlier drafts of
    this stub were declared ``async`` with no ``await`` site in the sync
    ``log`` caller, which silently dropped every audit event as an
    un-awaited coroutine.

    TODO: wire to your SIEM transport (HTTPS POST, syslog, Kafka topic, ...).
    """
    return None


class SIEMAuditLogger(AuditLogger):
    """Audit logger that sends events to the SIEM system."""
    
    def __init__(self, siem_endpoint: str, client_id: str):
        self._endpoint = siem_endpoint
        self._client_id = client_id
        
    def log(self, event: AuditEvent) -> None:
        """Send audit event to SIEM."""
        enriched_event = {
            **event.__dict__,
            "client_id": self._client_id,
            "environment": os.environ.get("ENVIRONMENT", "unknown"),
            "platform_version": __version__
        }
        
        # Sync send to SIEM (see send_to_siem docstring for async wrapping)
        send_to_siem(self._endpoint, enriched_event)

# ============================================================================
# Block 10 (chapter listing #10)
# ============================================================================

def setup_rotation_schedule(
    client_id: str,
    manager: SecretManager,
    rotation_days: int = 30
):
    """Configure automatic rotation for client secrets."""
    
    secrets_to_rotate = [
        f"{client_id}/crm-api-key",
        f"{client_id}/email-api-key"
    ]
    
    for secret_id in secrets_to_rotate:
        manager.register_rotation_callback(
            secret_id,
            lambda sid, ver: notify_client_security_team(
                client_id, sid, ver
            )
        )
