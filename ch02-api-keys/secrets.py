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

_block_2_listing_example = {
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
"""Illustrative audit-event shape; not used at runtime, retained as
documentation alongside the listing."""

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
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Optional, Protocol
import http.client
import importlib.util as _importlib_util
import queue
import sys as _sys
import sysconfig as _sysconfig
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _optional import optional_import  # noqa: E402

# botocore is an optional provider SDK; guard it so the module imports
# cleanly without AWS installed. Bind the exceptions namespace directly;
# this file's name makes indirect `botocore.exceptions` paths easy to
# misbind in tests and minimal environments.
botocore_exceptions = optional_import(
    "botocore.exceptions", stub_exception_names=("ClientError",)
)
import hashlib
import json
import logging
import random
import threading
import time
from urllib.parse import urlparse
import weakref

# Use the shared optional-import helper so the stub exception classes
# inherit from RetryableError (matching the other guarded SDKs in this
# repo) and so this file does not redefine the fallback pattern inline.
hvac = optional_import(
    "hvac",
    stub_exception_names=("VaultError", "Forbidden", "InvalidPath"),
)


def _real_exceptions(*candidates: Any) -> tuple:
    """Filter ``candidates`` to those that are genuine exception classes.

    Test environments may stub provider SDKs with ``MagicMock`` rather than
    real modules, in which case attribute lookups (e.g.
    ``hvac.exceptions.VaultError``) yield mock instances that cannot appear
    in an ``except`` tuple. Filtering through this helper keeps the narrowed
    handlers safe under both real and stubbed imports.
    """
    return tuple(
        c for c in candidates
        if isinstance(c, type) and issubclass(c, BaseException)
    )


def _load_stdlib_secrets():
    """Load stdlib secrets without resolving to this chapter's secrets.py."""

    stdlib_secrets_path = _Path(_sysconfig.get_path("stdlib")) / "secrets.py"
    spec = _importlib_util.spec_from_file_location(
        "_book2_stdlib_secrets",
        stdlib_secrets_path,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load stdlib secrets from {stdlib_secrets_path}")

    module = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_stdlib_secrets = _load_stdlib_secrets()

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
    # ``is_binary`` is True when the backend returned non-UTF-8 bytes (e.g.,
    # a DER certificate or raw key material). In that case ``secret_value``
    # is a base64-encoded string that the caller must decode before use.
    is_binary: bool = False


@dataclass
class CachedSecret:
    """A secret with caching metadata."""
    value: str
    metadata: SecretMetadata
    cached_at: datetime
    ttl_seconds: int

    def __post_init__(self) -> None:
        # Coerce naive datetimes to UTC so ``is_expired`` does not raise
        # TypeError when subtracting against ``datetime.now(timezone.utc)``.
        if self.cached_at.tzinfo is None:
            self.cached_at = self.cached_at.replace(tzinfo=timezone.utc)

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
    def log(self, event: AuditEvent) -> Any:
        """Log an audit event."""
        pass


AUDIT_REDACTED = "[REDACTED]"
MAX_AUDIT_CONTEXT_DEPTH = 4
MAX_AUDIT_CONTEXT_ITEMS = 50
MAX_AUDIT_CONTEXT_STRING_CHARS = 500
SENSITIVE_AUDIT_CONTEXT_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "prompt",
    "completion",
    "raw",
    "payload",
    "body",
    "content",
    "document",
    "cookie",
)


def _is_sensitive_audit_context_key(key: Any) -> bool:
    key_text = str(key).lower()
    return any(marker in key_text for marker in SENSITIVE_AUDIT_CONTEXT_MARKERS)


def _sanitize_audit_context(value: Any, depth: int = 0) -> Any:
    """Redact sensitive audit context while preserving useful metadata."""
    if depth >= MAX_AUDIT_CONTEXT_DEPTH:
        return "[TRUNCATED]"

    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_AUDIT_CONTEXT_ITEMS:
                sanitized["__truncated__"] = (
                    f"{len(value) - MAX_AUDIT_CONTEXT_ITEMS} omitted"
                )
                break
            key_text = str(key)
            if _is_sensitive_audit_context_key(key_text):
                sanitized[key_text] = AUDIT_REDACTED
            else:
                sanitized[key_text] = _sanitize_audit_context(item, depth + 1)
        return sanitized

    if isinstance(value, (list, tuple)):
        sanitized_items = [
            _sanitize_audit_context(item, depth + 1)
            for item in value[:MAX_AUDIT_CONTEXT_ITEMS]
        ]
        if len(value) > MAX_AUDIT_CONTEXT_ITEMS:
            sanitized_items.append(
                f"[{len(value) - MAX_AUDIT_CONTEXT_ITEMS} omitted]"
            )
        return sanitized_items

    if isinstance(value, str) and len(value) > MAX_AUDIT_CONTEXT_STRING_CHARS:
        return value[:MAX_AUDIT_CONTEXT_STRING_CHARS] + "...[TRUNCATED]"

    return value


class StructuredAuditLogger(AuditLogger):
    """
    Structured audit logger that outputs JSON-formatted events.
    
    This logger formats security-relevant metadata; it must not receive
    secret values or sensitive payloads in event context. Tamper evidence
    requires shipping these events to an append-only or Chapter 4-style
    tamper-evident audit store.
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
            "context": _sanitize_audit_context(event.context),
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
        Request backend-specific revocation or deletion.

        Revocation semantics are intentionally provider-specific: Vault KV v2
        can destroy a stored version or delete metadata, AWS Secrets Manager can
        remove staging labels or schedule secret deletion, and the environment
        provider cannot revoke. None of these operations can invalidate copies
        already fetched by other processes or credentials already accepted by a
        downstream service.
        
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


class SecretRetryExhaustedError(Exception):
    """Raised when a retry budget is exhausted without success.

    Distinct from the underlying transport error so callers can tell
    "we gave up after N attempts" apart from "this is a fatal error
    that should not be retried" (e.g. a Forbidden response).
    """
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
        mount_point: str = "secret",
        max_retries: int = 2,
        retry_base_delay: float = 0.25,
        retry_max_delay: float = 2.0,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
    ):
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if retry_base_delay <= 0 or retry_max_delay <= 0:
            raise ValueError("retry delays must be positive")
        if connect_timeout <= 0 or read_timeout <= 0:
            raise ValueError("timeouts must be positive")

        self._vault_addr = vault_addr
        self._role_id = role_id
        self._secret_id = secret_id
        self._namespace = namespace
        self._mount_point = mount_point
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay
        self._retry_max_delay = retry_max_delay
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
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
                # freeze the calling agent; defaults of 5s connect / 10s read
                # fit typical WAN deployments. Raise via constructor for
                # high-latency network paths and tune alongside the retry
                # policy below.
                client = hvac.Client(
                    url=self._vault_addr,
                    namespace=self._namespace,
                    timeout=(self._connect_timeout, self._read_timeout),
                )
                
                # Authenticate with AppRole
                auth_response = self._with_retry(
                    "vault approle login",
                    lambda: client.auth.approle.login(
                        role_id=self._role_id,
                        secret_id=self._secret_id
                    )
                )
                
                # Track token expiry for renewal
                # Note: lease_duration behavior may vary by Vault version (tested with Vault 1.12+)
                ttl = int(auth_response['auth']['lease_duration'])
                renewal_margin = min(60, max(1, ttl // 10))
                refresh_after = max(1, ttl - renewal_margin)
                self._token_expiry = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=refresh_after)
                )
                self._client = client
                
            return self._client
    
    def _is_token_expired(self) -> bool:
        """Check if the current token is expired or about to expire."""
        if self._token_expiry is None:
            return True
        return datetime.now(timezone.utc) >= self._token_expiry

    def _retry_delay(self, attempt: int) -> float:
        """Calculate exponential backoff with full jitter."""
        cap = min(
            self._retry_max_delay,
            self._retry_base_delay * (2 ** (attempt - 1))
        )
        return random.uniform(0, cap)

    def _is_retryable_vault_error(self, error: Exception) -> bool:
        """Return True for transient Vault failures worth retrying."""
        status_code = getattr(error, "status_code", None)
        if status_code is None:
            response = getattr(error, "response", None)
            status_code = getattr(response, "status_code", None)
        if status_code is None:
            return True
        return status_code in {429, 500, 502, 503, 504}

    def _with_retry(self, operation_name: str, operation: Callable[[], Any]) -> Any:
        """Run a Vault operation with bounded retries and jitter."""
        attempts = self._max_retries + 1
        for attempt in range(1, attempts + 1):
            try:
                return operation()
            except (hvac.exceptions.Forbidden, hvac.exceptions.InvalidPath):
                raise
            except hvac.exceptions.VaultError as e:
                if attempt == attempts or not self._is_retryable_vault_error(e):
                    raise
                delay = self._retry_delay(attempt)
                logger.warning(
                    "%s failed on attempt %s/%s; retrying in %.2fs: %s",
                    operation_name,
                    attempt,
                    attempts,
                    delay,
                    e,
                )
                time.sleep(delay)
        # Loop fell through without returning or raising. The retry budget
        # is exhausted; surface that explicitly so callers do not silently
        # receive ``None`` from an apparently successful call.
        raise SecretRetryExhaustedError(
            f"Retry budget exhausted after {self._max_retries} attempts"
        )

    def get_secret(self, secret_id: str, version: Optional[str] = None) -> tuple[str, SecretMetadata]:
        """Retrieve a secret from Vault."""
        client = self._get_client()
        
        try:
            # Read from KV v2 secrets engine
            response = self._with_retry(
                "vault read secret",
                lambda: client.secrets.kv.v2.read_secret_version(
                    path=secret_id,
                    version=int(version) if version else None,
                    mount_point=self._mount_point
                )
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
            current = self._with_retry(
                "vault read secret for rotation",
                lambda: client.secrets.kv.v2.read_secret_version(
                    path=secret_id,
                    mount_point=self._mount_point
                )
            )
            tags = current['data']['data'].get('tags', {})
        except hvac.exceptions.InvalidPath:
            tags = {}
        except hvac.exceptions.VaultError as e:
            logger.warning(
                f"Could not preserve tags during rotation of {secret_id}: {e}"
            )
            tags = {}

        # Generate new secret value with the stdlib module loaded under a
        # private alias so this file cannot shadow it on sys.path.
        new_value = _stdlib_secrets.token_urlsafe(32)
        
        # Write new version
        self._with_retry(
            "vault write rotated secret",
            lambda: client.secrets.kv.v2.create_or_update_secret(
                path=secret_id,
                secret={'value': new_value, 'tags': tags},
                mount_point=self._mount_point
            )
        )
        
        # Retrieve updated metadata
        return self.get_secret(secret_id)
    
    def revoke_secret(self, secret_id: str, version: Optional[str] = None) -> None:
        """Destroy a Vault KV v2 version or delete stored secret metadata."""
        client = self._get_client()
        
        if version:
            # Destroy specific version
            self._with_retry(
                "vault destroy secret version",
                lambda: client.secrets.kv.v2.destroy_secret_versions(
                    path=secret_id,
                    versions=[int(version)],
                    mount_point=self._mount_point
                )
            )
        else:
            # Delete all versions (metadata remains)
            self._with_retry(
                "vault delete secret metadata and versions",
                lambda: client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=secret_id,
                    mount_point=self._mount_point
                )
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
        aws_secret_access_key: Optional[str] = None,
        deletion_recovery_window_days: int = 7
    ):
        if not 7 <= deletion_recovery_window_days <= 30:
            raise ValueError("deletion_recovery_window_days must be 7-30")
        self._region_name = region_name
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._deletion_recovery_window_days = deletion_recovery_window_days
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
            is_binary = False
            if 'SecretString' in response:
                secret_value = response['SecretString']
            else:
                import base64
                # Binary secrets may not be valid UTF-8 (DER certificates,
                # raw key material). Decoding with ``errors='replace'``
                # silently corrupts byte payloads with U+FFFD; instead, try
                # strict UTF-8 first and fall back to base64 so callers get
                # a deterministic round-trippable string. ``is_binary`` on
                # the metadata signals which path produced the value.
                raw_bytes = base64.b64decode(response['SecretBinary'])
                try:
                    secret_value = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    secret_value = base64.b64encode(raw_bytes).decode("ascii")
                    is_binary = True

            # Get additional metadata
            describe_response = client.describe_secret(SecretId=secret_id)

            metadata = SecretMetadata(
                secret_id=secret_id,
                version=response['VersionId'],
                created_at=response['CreatedDate'],
                expires_at=None,
                rotation_due=describe_response.get('NextRotationDate'),
                tags={t['Key']: t['Value'] for t in describe_response.get('Tags', [])},
                is_binary=is_binary,
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
            rotation_response = client.rotate_secret(SecretId=secret_id)
            pending_version_id = rotation_response.get("VersionId")
            
            # Wait for rotation to complete with exponential backoff + jitter
            # so a flaky describe_secret endpoint does not get hammered by a
            # tight 1-second poll loop. Total budget is roughly the same
            # (~30s worst case) but the backoff distributes load.
            max_attempts = 8
            base_delay = 0.5
            cap = 8.0
            for attempt in range(max_attempts):
                response = client.describe_secret(SecretId=secret_id)
                version_stages = response.get("VersionIdsToStages", {})
                if pending_version_id:
                    pending_stages = set(
                        version_stages.get(pending_version_id, [])
                    )
                    if (
                        "AWSCURRENT" in pending_stages
                        and "AWSPENDING" not in pending_stages
                    ):
                        break
                elif not any(
                    "AWSPENDING" in stages
                    for stages in version_stages.values()
                ):
                    break
                # Exponential backoff: 0.5, 1, 2, 4, 8, 8, 8, 8 seconds
                # with full jitter per the AWS exponential-backoff guidance.
                delay = min(cap, base_delay * (2 ** attempt))
                logger.debug(
                    f"rotation poll attempt={attempt} sleeping={delay:.2f}s"
                )
                time.sleep(random.uniform(0, delay))
            else:
                raise SecretRotationError(
                    f"Rotation timeout for secret {secret_id}"
                )
            
            return self.get_secret(secret_id)

        except botocore_exceptions.ClientError as e:
            raise SecretRotationError(f"Failed to rotate {secret_id}: {e}") from e
            
    def revoke_secret(self, secret_id: str, version: Optional[str] = None) -> None:
        """Remove an AWS version label or schedule recoverable deletion."""
        client = self._get_client()
        
        if version:
            # AWS doesn't support deleting specific versions directly
            # Remove AWSCURRENT from the compromised version to stop normal
            # default reads without deleting the entire secret record.
            client.update_secret_version_stage(
                SecretId=secret_id,
                VersionStage='AWSCURRENT',
                RemoveFromVersionId=version
            )
        else:
            # Schedule recoverable deletion. Do not use force deletion for the
            # normal recovery path; rotate the credential or remove staging
            # labels when the emergency objective is to stop future reads.
            client.delete_secret(
                SecretId=secret_id,
                RecoveryWindowInDays=self._deletion_recovery_window_days
            )

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

class SecretManager:
    """
    Unified secret management for agentic AI systems.
    
    This class provides a high-level interface for secret management with:
    - Multi-backend support for Vault and AWS, with Azure as an extension point
    - Automatic caching with TTL
    - Lazy background rotation monitoring for registered callbacks
    - Comprehensive audit logging
    - Scope-based access control
    
    Example:
        >>> with SecretManager(
        ...     agent_id="research-agent-1",
        ...     agent_role="research",
        ...     backend=SecretBackend.AWS_SECRETS_MANAGER,
        ...     backend_config={"region_name": "us-east-1"}
        ... ) as manager:
        ...     # Get a secret with automatic caching
        ...     api_key = manager.get_secret("openai/api-key")
        ...
        ...     # Use context manager for JIT injection
        ...     with manager.scoped_secret("sensitive/payment-key") as key:
        ...         process_payment(key)
        ...     # Manager-held references are dropped after context exit
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
        rotation_check_interval: Optional[int] = 3600,
        require_audit_success: bool = False
    ):
        """
        Initialize the SecretManager.
        
        Args:
            agent_id: Unique identifier for this agent instance.
            agent_role: Role of this agent (used for access control).
            backend: Which secret backend to use.
            backend_config: Backend-specific configuration.
            allowed_secret_patterns: Glob patterns for secrets this agent can access.
                Defaults to deny-all; pass explicit patterns for every agent.
            default_cache_ttl: Default cache TTL in seconds.
            audit_logger: Custom audit logger implementation.
            rotation_check_interval: How often to check for rotation needs (seconds).
                Set to None to disable the background monitor. The monitor starts
                lazily when the first rotation callback is registered.
            require_audit_success: If true, successful reads fail closed when the
                audit logger reports that the event could not be accepted.
        """
        if rotation_check_interval is not None and rotation_check_interval <= 0:
            raise ValueError("rotation_check_interval must be positive or None")

        self._agent_id = agent_id
        self._agent_role = agent_role
        self._allowed_patterns = list(allowed_secret_patterns or [])
        self._default_cache_ttl = default_cache_ttl
        self._audit_logger = audit_logger or StructuredAuditLogger()
        self._require_audit_success = require_audit_success
        self._rotation_check_interval = rotation_check_interval
        provider_config = dict(backend_config)
        if backend == SecretBackend.ENVIRONMENT:
            self._validate_environment_backend(provider_config)
        
        # Initialize backend provider
        self._provider = self._create_provider(backend, provider_config)
        
        # Secret cache (bounded to avoid unbounded growth in long-running agents)
        from cachetools import TTLCache
        self._cache: TTLCache = TTLCache(maxsize=1000, ttl=default_cache_ttl)
        self._cache_lock = threading.Lock()
        
        # Rotation monitoring
        self._rotation_callbacks: dict[str, list[Callable[[str, str], None]]] = {}
        self._rotation_monitor_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._closed = False
        
        # The monitor starts only after a callback is registered, avoiding one
        # daemon thread per short-lived manager that never uses rotation events.

    def __enter__(self) -> "SecretManager":
        """Enter a managed lifecycle for the secret manager."""
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Close the manager and drop cached references on context exit."""
        self.close()

    def _validate_environment_backend(self, config: dict[str, Any]) -> None:
        """Reject the development-only environment backend in production."""
        import os

        environment = os.environ.get("ENVIRONMENT", "").strip().lower()
        development_override = (
            config.pop("allow_environment_backend_in_production", False) is True
        )
        if environment not in {"production", "prod"} or development_override:
            return

        error = (
            "Environment secret backend is development-only; set "
            "allow_environment_backend_in_production=True only for an explicit "
            "development override."
        )
        context = {
            "backend": SecretBackend.ENVIRONMENT.value,
            "environment": environment,
            "development_override": False,
        }
        self._audit(
            "secret_backend_configuration",
            "backend/environment",
            "configure",
            "denied",
            context=context,
            error=error,
        )
        logger.warning(
            "Denied environment secret backend while ENVIRONMENT=%s",
            environment,
            extra=context,
        )
        raise SecretAccessDeniedError(error)
        
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
            # Extension point for readers who need an Azure Key Vault provider.
            raise NotImplementedError(
                "Azure Key Vault provider is an extension point in this chapter"
            )
        elif backend == SecretBackend.ENVIRONMENT:
            return EnvironmentSecretProvider(**config)
        else:
            raise ValueError(f"Unknown backend: {backend}")

    def _ensure_open(self) -> None:
        """Raise if this manager has already been closed."""
        if self._closed:
            raise RuntimeError("SecretManager is closed")
            
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
    ) -> Any:
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
        return self._audit_logger.log(event)

    def _audit_delivery_accepted(self, result: Any) -> bool:
        """Return true when the audit logger accepted the event for delivery."""
        if result is None:
            return True
        if getattr(result, "error", None):
            return False
        if getattr(result, "queued", False):
            return True
        return bool(getattr(result, "delivered", False))

    def _require_successful_audit(self, result: Any) -> None:
        """Fail closed if policy requires an accepted audit event."""
        if (
            self._require_audit_success
            and not self._audit_delivery_accepted(result)
        ):
            raise SecretAccessDeniedError(
                "Secret audit delivery failed; refusing to return secret"
            )
        
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
            bypass_cache: If True, skip cache reads and writes.
            cache_ttl: Override the default cache TTL for this secret.
            context: Additional context for audit logging.
            
        Returns:
            The secret value as a string.
            
        Raises:
            SecretAccessDeniedError: If this agent cannot access the secret.
            SecretNotFoundError: If the secret does not exist.
        """
        self._ensure_open()

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
        
        cache_key = f"{secret_id}:{version or 'default'}"
        
        # Check cache first (unless bypassing)
        if not bypass_cache:
            with self._cache_lock:
                if cache_key in self._cache:
                    cached = self._cache[cache_key]
                    if not cached.is_expired:
                        audit_result = self._audit(
                            "secret_access",
                            secret_id,
                            "read",
                            "success",
                            version=cached.metadata.version,
                            context={**(context or {}), "cache_hit": True}
                        )
                        self._require_successful_audit(audit_result)
                        return cached.value
        
        # Fetch from backend
        try:
            value, metadata = self._provider.get_secret(secret_id, version)
            
            audit_result = self._audit(
                "secret_access",
                secret_id,
                "read",
                "success",
                version=metadata.version,
                context={**(context or {}), "cache_hit": False}
            )
            self._require_successful_audit(audit_result)

            # Cache only after required audit delivery succeeds. JIT and
            # explicit fresh-fetch callers should not leave a manager-held
            # cached reference behind.
            if not bypass_cache:
                ttl = cache_ttl or self._default_cache_ttl
                cached_secret = CachedSecret(
                    value=value,
                    metadata=metadata,
                    cached_at=datetime.now(timezone.utc),
                    ttl_seconds=ttl
                )

                with self._cache_lock:
                    self._cache[cache_key] = cached_secret

            return value

        except _real_exceptions(
            SecretNotFoundError,
            SecretAccessDeniedError,
            SecretRetryExhaustedError,
            hvac.exceptions.VaultError,
            botocore_exceptions.ClientError,
        ) as e:
            self._audit(
                "secret_access",
                secret_id,
                "read",
                "failure",
                context=context,
                error=str(e)
            )
            raise
        except Exception as e:  # noqa: BLE001 -- fail-safe boundary
            logger.exception("Unexpected secret access error")
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
        Get a secret with scoped manager-held references.
        
        This implements just-in-time secret injection. The secret is
        fetched when entering the context and the context manager's
        reference is dropped when exiting. Python string zeroization
        cannot be proven from application code.
        
        Example:
            >>> with manager.scoped_secret("api/key") as key:
            ...     make_api_call(key)
            >>> # manager-held reference has been dropped
        """
        self._ensure_open()
        return ScopedSecretContext(self, secret_id, context)
        
    def invalidate_cache(self, secret_id: Optional[str] = None) -> None:
        """
        Invalidate cached secrets.
        
        Args:
            secret_id: If provided, invalidate only this secret.
                      If None, invalidate all cached secrets.
        """
        self._ensure_open()
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
        with self._lifecycle_lock:
            self._ensure_open()
            if secret_id not in self._rotation_callbacks:
                self._rotation_callbacks[secret_id] = []
            self._rotation_callbacks[secret_id].append(callback)

        self._start_rotation_monitor()
        
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
        self._ensure_open()
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

        except _real_exceptions(
            SecretRotationError,
            SecretNotFoundError,
            SecretAccessDeniedError,
            hvac.exceptions.VaultError,
            botocore_exceptions.ClientError,
        ) as e:
            self._audit(
                "secret_rotation",
                secret_id,
                "rotate",
                "failure",
                context=context,
                error=str(e)
            )
            raise
        except Exception as e:  # noqa: BLE001 -- fail-safe boundary
            logger.exception("Unexpected secret rotation error")
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
        
        This requests the backend's revocation operation and invalidates this
        manager's cache. It does not guarantee immediate invalidation of copies
        already fetched by other agents, open connections, or static credentials
        that must be disabled in the downstream service.
        
        Args:
            secret_id: The secret to revoke.
            version: Optional specific version to revoke.
            context: Additional context for audit logging.
        """
        self._ensure_open()
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

        except _real_exceptions(
            SecretNotFoundError,
            SecretAccessDeniedError,
            hvac.exceptions.VaultError,
            botocore_exceptions.ClientError,
        ) as e:
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
        except Exception as e:  # noqa: BLE001 -- fail-safe boundary
            logger.exception("Unexpected secret revocation error")
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
        """Start the background rotation monitor if configured and needed."""
        if self._rotation_check_interval is None:
            return

        with self._lifecycle_lock:
            if self._closed or not self._rotation_callbacks:
                return
            if (
                self._rotation_monitor_thread
                and self._rotation_monitor_thread.is_alive()
            ):
                return

            self._shutdown_event.clear()
            self._rotation_monitor_thread = threading.Thread(
                target=self._rotation_monitor_loop,
                daemon=True,
                name=f"SecretRotationMonitor-{self._agent_id}"
            )
            self._rotation_monitor_thread.start()
        
    def _rotation_monitor_loop(self) -> None:
        """Background loop that checks for needed rotations."""
        if self._rotation_check_interval is None:
            return

        while not self._shutdown_event.is_set():
            try:
                self._check_rotation_due()
            except Exception as e:  # noqa: BLE001 -- monitor loop must not die
                logger.exception("Rotation monitor error: %s", e)
            
            self._shutdown_event.wait(self._rotation_check_interval)
            
    def _check_rotation_due(self) -> None:
        """Check all monitored secrets for rotation needs."""
        due_callbacks: list[tuple[str, Callable[[str, str], None]]] = []

        with self._cache_lock:
            now = datetime.now(timezone.utc)
            for cache_key, cached in list(self._cache.items()):
                if cached.metadata.rotation_due:
                    if now >= cached.metadata.rotation_due:
                        secret_id = cached.metadata.secret_id
                        logger.info(f"Secret {secret_id} is due for rotation")

                        # Copy callbacks while holding the cache lock, then
                        # invoke them after release so callbacks can fetch
                        # fresh secrets without deadlocking this manager.
                        for callback in self._rotation_callbacks.get(secret_id, []):
                            due_callbacks.append((secret_id, callback))

        for secret_id, callback in due_callbacks:
            try:
                callback(secret_id, "rotation_due")
            except Exception as e:
                logger.error(f"Rotation callback failed: {e}")

    def close(self) -> None:
        """Close the secret manager, stop monitoring, and drop cached secrets."""
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._shutdown_event.set()
            monitor_thread = self._rotation_monitor_thread

        if (
            monitor_thread
            and monitor_thread.is_alive()
            and monitor_thread is not threading.current_thread()
        ):
            monitor_thread.join(timeout=5)
        
        # Drop cached secret references held by this manager.
        with self._cache_lock:
            for cached in self._cache.values():
                # Rebinding only removes this CachedSecret's reference to the
                # original str. Python string zeroization cannot be proven.
                cached.value = "0" * len(cached.value)
            self._cache.clear()

        audit_close = getattr(self._audit_logger, "close", None)
        if callable(audit_close):
            audit_close()

    def shutdown(self) -> None:
        """Backward-compatible alias for close()."""
        self.close()


class ScopedSecretContext:
    """
    Context manager for just-in-time secret injection.
    
    This helps secrets be fetched only when needed and keeps the
    manager-held reference scoped to the context block. It does not
    prove zeroization of Python string objects.
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
        """Drop the manager-held secret reference on context exit."""
        if self._value:
            # Rebinding creates a new string and then drops this reference.
            # It does not prove the original bytes were zeroized by CPython.
            self._value = "0" * len(self._value)
            self._value = None
        return False


class EnvironmentSecretProvider(SecretBackendProvider):
    """
    Environment variable-based secret provider.

    WARNING: This provider is intended for local development only.
    Avoid long-lived plaintext environment variables for production secrets.
    If your platform injects secrets through the process environment, keep
    scope narrow, rotate aggressively, and account for residual exposure in
    process dumps, inherited environments, logs, and compromised hosts.
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
        
        # Secret is fetched here and the manager-held reference is dropped
        # after the block.
        with manager.scoped_secret("finance/payment-gateway-key") as api_key:
            # api_key is intentionally referenced only during this block.
            result = call_payment_api(api_key, amount, recipient)
            
        # The scoped manager no longer holds api_key.
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
        
        # Pre-warm cache with new secret after invalidating stale entries
        manager.get_secret(secret_id)
    
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
        Wrapper that helps enforce tenant isolation for secret access.
        
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
    def __init__(self, client_id: str, secret_manager: SecretManager):
        self.client_id = client_id
        self.secret_manager = secret_manager
        self.config = load_config(f"/app/config/{client_id}.json")
        self.crm_secret_id = self.config["crm_secret_id"]
        self.email_secret_id = self.config["email_secret_id"]
        self.slack_webhook_secret_id = self.config["slack_webhook_secret_id"]
        self.crm_base_url = self.config["crm_base_url"]
        self.support_email = self.config["support_email"]

    def handle_ticket(self, ticket: dict[str, Any]) -> dict[str, Any]:
        """Handle one ticket with secrets fetched only at use time."""
        context = {
            "client_id": self.client_id,
            "ticket_id": str(ticket["id"])
        }

        with self.secret_manager.scoped_secret(
            self.crm_secret_id,
            context={**context, "purpose": "crm_lookup"}
        ) as crm_api_key:
            customer = fetch_customer_record(
                self.crm_base_url,
                crm_api_key,
                ticket["customer_id"]
            )

        with self.secret_manager.scoped_secret(
            self.email_secret_id,
            context={**context, "purpose": "email_reply"}
        ) as email_api_key:
            send_customer_email(
                self.support_email,
                email_api_key,
                ticket,
                customer
            )

        if ticket.get("notify_slack"):
            with self.secret_manager.scoped_secret(
                self.slack_webhook_secret_id,
                context={**context, "purpose": "slack_notification"}
            ) as slack_webhook:
                post_slack_notification(slack_webhook, ticket)

        return {"ticket_id": ticket["id"], "customer": customer}

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

# Module identifier embedded with audit events. Resolved from the
# installed package metadata (pyproject.toml) so a redeploy bumps this
# automatically; falls back to a sentinel for direct-from-source runs
# where the package isn't pip-installed.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version
    __version__ = _pkg_version("agentic-ai-production")
except (PackageNotFoundError, ImportError):  # pragma: no cover
    __version__ = "0.0.0+unknown"


@dataclass(frozen=True)
class SIEMDeliveryResult:
    """Outcome returned by the SIEM delivery path."""
    delivered: bool
    attempts: int
    status_code: Optional[int] = None
    error: Optional[str] = None
    queued: bool = False
    buffered: bool = False
    queue_depth: int = 0
    dropped_queue_full_total: int = 0
    dropped_failed_events_total: int = 0
    circuit_open: bool = False


@dataclass(frozen=True)
class SIEMAuditMetrics:
    """Snapshot of SIEM audit queue, delivery, and breaker state."""
    queued_events: int
    queue_capacity: int
    buffered_failed_events: int
    enqueued_total: int
    delivered_total: int
    failed_delivery_total: int
    dropped_queue_full_total: int
    dropped_failed_events_total: int
    circuit_open: bool
    circuit_open_total: int


MAX_BACKOFF_SECONDS = 30.0


class SIEMSender(Protocol):
    """Callable transport used by SIEM delivery; inject one in tests."""
    def __call__(
        self,
        endpoint: str,
        event: dict[str, Any],
        connect_timeout: float,
        read_timeout: float,
    ) -> int:
        """Send one event and return an HTTP-like status code."""
        ...


def _http_json_sender(
    endpoint: str,
    event: dict[str, Any],
    connect_timeout: float,
    read_timeout: float,
) -> int:
    """Send one audit event as HTTPS JSON using bounded socket timeouts."""
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("siem_endpoint must be an https:// URL")

    body = json.dumps(event, default=str).encode("utf-8")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection = http.client.HTTPSConnection(
        parsed.netloc,
        timeout=connect_timeout,
    )
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        if connection.sock is not None:
            connection.sock.settimeout(read_timeout)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def send_to_siem(
    endpoint: str,
    event: dict[str, Any],
    *,
    sender: Optional[SIEMSender] = None,
    connect_timeout: float = 2.0,
    read_timeout: float = 5.0,
    max_retries: int = 2,
    backoff_seconds: float = 0.25,
) -> SIEMDeliveryResult:
    """Deliver one audit event to a SIEM endpoint.

    The default sender performs an HTTPS POST with explicit connect/read
    timeouts. Tests should pass ``sender=...`` so no network is used.
    """
    if max_retries < 0:
        raise ValueError("max_retries must be >= 0")

    transport = sender or _http_json_sender
    attempts = max_retries + 1
    last_error: Optional[str] = None
    last_status: Optional[int] = None

    for attempt in range(1, attempts + 1):
        try:
            status_code = transport(
                endpoint,
                event,
                connect_timeout,
                read_timeout,
            )
            last_status = status_code
            if 200 <= status_code < 300:
                return SIEMDeliveryResult(
                    delivered=True,
                    attempts=attempt,
                    status_code=status_code,
                )
            # 4xx client errors (other than 408 Request Timeout and 429
            # Too Many Requests) will fail every retry attempt the same
            # way, so we short-circuit and surface the failure without
            # burning the retry budget.
            if 400 <= status_code < 500 and status_code not in (408, 429):
                last_error = (
                    f"SIEM endpoint returned HTTP {status_code} "
                    "(non-retryable client error)"
                )
                return SIEMDeliveryResult(
                    delivered=False,
                    attempts=attempt,
                    status_code=status_code,
                    error=last_error,
                )
            last_error = f"SIEM endpoint returned HTTP {status_code}"
        except Exception as exc:
            last_error = str(exc)

        if attempt < attempts:
            delay = min(MAX_BACKOFF_SECONDS, backoff_seconds * (2 ** attempt))
            time.sleep(random.uniform(0, delay))

    return SIEMDeliveryResult(
        delivered=False,
        attempts=attempts,
        status_code=last_status,
        error=last_error,
    )


class SIEMAuditLogger(AuditLogger):
    """Audit logger that queues events and delivers them off the secret path."""
    
    def __init__(
        self,
        siem_endpoint: str,
        client_id: str,
        *,
        sender: Optional[SIEMSender] = None,
        connect_timeout: float = 2.0,
        read_timeout: float = 5.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.25,
        delivery_queue_size: int = 1000,
        failure_buffer_size: int = 100,
        circuit_failure_threshold: int = 3,
        circuit_reset_seconds: float = 30.0,
    ):
        if delivery_queue_size < 1:
            raise ValueError("delivery_queue_size must be >= 1")
        if failure_buffer_size < 1:
            raise ValueError("failure_buffer_size must be >= 1")
        if circuit_failure_threshold < 1:
            raise ValueError("circuit_failure_threshold must be >= 1")
        if circuit_reset_seconds < 0:
            raise ValueError("circuit_reset_seconds must be >= 0")

        self._endpoint = siem_endpoint
        self._client_id = client_id
        self._sender = sender
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._delivery_queue: queue.Queue = queue.Queue(
            maxsize=delivery_queue_size
        )
        self._failed_events: deque[dict[str, Any]] = deque(
            maxlen=failure_buffer_size
        )
        self._failed_events_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._enqueued_total = 0
        self._delivered_total = 0
        self._failed_delivery_total = 0
        self._dropped_queue_full_total = 0
        self._dropped_failed_events_total = 0
        self._consecutive_failures = 0
        self._circuit_failure_threshold = circuit_failure_threshold
        self._circuit_reset_seconds = circuit_reset_seconds
        self._circuit_open_until = 0.0
        self._circuit_open_total = 0
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name=f"siem-audit-{client_id}",
            daemon=True,
        )
        self._worker_thread.start()
        
    @property
    def failed_events(self) -> tuple[dict[str, Any], ...]:
        """Bounded in-memory DLQ for events that could not be delivered."""
        with self._failed_events_lock:
            return tuple(self._failed_events)

    @property
    def dropped_failed_events_total(self) -> int:
        """Number of failed audit events evicted before redelivery."""
        with self._failed_events_lock:
            return self._dropped_failed_events_total

    @property
    def metrics(self) -> SIEMAuditMetrics:
        """Return a point-in-time snapshot for monitoring/backpressure alerts."""
        with self._metrics_lock:
            enqueued_total = self._enqueued_total
            delivered_total = self._delivered_total
            failed_delivery_total = self._failed_delivery_total
            dropped_queue_full_total = self._dropped_queue_full_total
            circuit_open = self._is_circuit_open_locked()
            circuit_open_total = self._circuit_open_total

        with self._failed_events_lock:
            buffered_failed_events = len(self._failed_events)
            dropped_failed_events_total = self._dropped_failed_events_total

        return SIEMAuditMetrics(
            queued_events=self._delivery_queue.qsize(),
            queue_capacity=self._delivery_queue.maxsize,
            buffered_failed_events=buffered_failed_events,
            enqueued_total=enqueued_total,
            delivered_total=delivered_total,
            failed_delivery_total=failed_delivery_total,
            dropped_queue_full_total=dropped_queue_full_total,
            dropped_failed_events_total=dropped_failed_events_total,
            circuit_open=circuit_open,
            circuit_open_total=circuit_open_total,
        )

    def _is_circuit_open_locked(self) -> bool:
        """Check breaker state while holding _metrics_lock."""
        return time.monotonic() < self._circuit_open_until

    def _circuit_open(self) -> bool:
        """Check breaker state."""
        with self._metrics_lock:
            return self._is_circuit_open_locked()

    def _circuit_wait_seconds(self) -> float:
        """Return seconds until the breaker allows another send attempt."""
        with self._metrics_lock:
            return max(0.0, self._circuit_open_until - time.monotonic())

    def _wait_for_circuit(self) -> bool:
        """Wait until half-open, returning False if shutdown interrupts."""
        while True:
            wait_seconds = self._circuit_wait_seconds()
            if wait_seconds <= 0:
                return True
            if self._shutdown_event.wait(min(wait_seconds, 0.1)):
                return False

    def _record_delivery_success(self) -> None:
        """Update metrics after a successful background delivery."""
        with self._metrics_lock:
            self._delivered_total += 1
            self._consecutive_failures = 0
            self._circuit_open_until = 0.0

    def _record_delivery_failure(self) -> bool:
        """Update metrics after a failed delivery and maybe open the breaker."""
        with self._metrics_lock:
            self._failed_delivery_total += 1
            self._consecutive_failures += 1
            if self._consecutive_failures < self._circuit_failure_threshold:
                return False

            self._consecutive_failures = 0
            self._circuit_open_until = (
                time.monotonic() + self._circuit_reset_seconds
            )
            self._circuit_open_total += 1
            return True

    def _buffer_failed_event(
        self,
        event: dict[str, Any],
        result: SIEMDeliveryResult
    ) -> None:
        """Buffer a failed delivery and make bounded-buffer loss explicit."""
        with self._failed_events_lock:
            if len(self._failed_events) == self._failed_events.maxlen:
                evicted = self._failed_events.popleft()
                evicted_event = evicted.get("event", {})
                self._dropped_failed_events_total += 1
                logger.error(
                    (
                        "SIEM failed-event buffer full; dropping oldest "
                        "event metadata"
                    ),
                    extra={
                        "client_id": self._client_id,
                        "evicted_event_type": evicted_event.get("event_type"),
                        "evicted_secret_id": evicted_event.get("secret_id"),
                        "evicted_operation": evicted_event.get("operation"),
                        "evicted_result": evicted_event.get("result"),
                        "evicted_timestamp": evicted_event.get("timestamp"),
                        "evicted_attempts": evicted.get("attempts"),
                        "evicted_status_code": evicted.get("status_code"),
                        "evicted_error": evicted.get("error"),
                        "dropped_failed_events_total": (
                            self._dropped_failed_events_total
                        ),
                    },
                )

            self._failed_events.append(
                {
                    "event": event,
                    "error": result.error,
                    "attempts": result.attempts,
                    "status_code": result.status_code,
                }
            )

    def _dropped_failed_total(self) -> int:
        """Return failed-buffer drop count."""
        with self._failed_events_lock:
            return self._dropped_failed_events_total

    def _buffer_undrained_queue(self, error: str) -> int:
        """Move queued events into the failed-event buffer during close."""
        buffered_count = 0
        while True:
            try:
                event = self._delivery_queue.get_nowait()
            except queue.Empty:
                break

            result = SIEMDeliveryResult(
                delivered=False,
                attempts=0,
                error=error,
                buffered=True,
                queue_depth=self._delivery_queue.qsize(),
                dropped_failed_events_total=self._dropped_failed_total(),
                circuit_open=self._circuit_open(),
            )
            self._buffer_failed_event(event, result)
            self._delivery_queue.task_done()
            buffered_count += 1

        return buffered_count

    def _worker_loop(self) -> None:
        """Deliver queued audit events outside the secret access path."""
        while not self._shutdown_event.is_set() or not self._delivery_queue.empty():
            try:
                event = self._delivery_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                self._deliver_event(event)
            except Exception as exc:  # pragma: no cover - defensive guard
                result = SIEMDeliveryResult(
                    delivered=False,
                    attempts=0,
                    error=f"SIEM worker error: {exc}",
                    buffered=True,
                    dropped_failed_events_total=self._dropped_failed_total(),
                    circuit_open=self._circuit_open(),
                )
                self._buffer_failed_event(event, result)
                logger.exception(
                    "SIEM audit worker failed; event buffered",
                    extra={
                        "client_id": self._client_id,
                        "secret_id": event.get("secret_id"),
                    },
                )
            finally:
                self._delivery_queue.task_done()

    def _deliver_event(self, event: dict[str, Any]) -> None:
        """Send one queued event or buffer it if delivery is unavailable."""
        if not self._wait_for_circuit():
            result = SIEMDeliveryResult(
                delivered=False,
                attempts=0,
                error="SIEM circuit breaker open during shutdown",
                buffered=True,
                dropped_failed_events_total=self._dropped_failed_total(),
                circuit_open=True,
            )
            self._buffer_failed_event(event, result)
            return

        result = send_to_siem(
            self._endpoint,
            event,
            sender=self._sender,
            connect_timeout=self._connect_timeout,
            read_timeout=self._read_timeout,
            max_retries=self._max_retries,
            backoff_seconds=self._backoff_seconds,
        )
        if result.delivered:
            self._record_delivery_success()
            return

        self._buffer_failed_event(event, result)
        circuit_opened = self._record_delivery_failure()
        logger.warning(
            "SIEM audit delivery failed; event buffered for retry",
            extra={
                "client_id": self._client_id,
                "secret_id": event.get("secret_id"),
                "attempts": result.attempts,
                "status_code": result.status_code,
                "error": result.error,
                "dropped_failed_events_total": (
                    self._dropped_failed_total()
                ),
                "circuit_open": self._circuit_open(),
            },
        )
        if circuit_opened:
            logger.error(
                "SIEM circuit breaker opened after delivery failures",
                extra={
                    "client_id": self._client_id,
                    "circuit_reset_seconds": self._circuit_reset_seconds,
                    "failed_delivery_total": (
                        self.metrics.failed_delivery_total
                    ),
                    "circuit_open_total": self.metrics.circuit_open_total,
                },
            )

    def drain_failed_events(
        self,
        max_events: Optional[int] = None
    ) -> list[SIEMDeliveryResult]:
        """
        Retry buffered SIEM events, removing only successful deliveries.

        Stops after the first failed redelivery so callers can schedule this
        method with external backoff instead of hammering an unhealthy SIEM.
        """
        if max_events is not None and max_events < 1:
            raise ValueError("max_events must be >= 1")

        with self._failed_events_lock:
            events_to_attempt = len(self._failed_events)
        if max_events is not None:
            events_to_attempt = min(events_to_attempt, max_events)

        results: list[SIEMDeliveryResult] = []
        for _ in range(events_to_attempt):
            if self._circuit_open():
                result = SIEMDeliveryResult(
                    delivered=False,
                    attempts=0,
                    error="SIEM circuit breaker open",
                    buffered=True,
                    dropped_failed_events_total=self._dropped_failed_total(),
                    circuit_open=True,
                )
                results.append(result)
                break

            with self._failed_events_lock:
                if not self._failed_events:
                    break
                buffered_event = self._failed_events[0]
            event = buffered_event["event"]
            result = send_to_siem(
                self._endpoint,
                event,
                sender=self._sender,
                connect_timeout=self._connect_timeout,
                read_timeout=self._read_timeout,
                max_retries=self._max_retries,
                backoff_seconds=self._backoff_seconds,
            )
            if result.delivered:
                with self._failed_events_lock:
                    if (
                        self._failed_events
                        and self._failed_events[0] is buffered_event
                    ):
                        self._failed_events.popleft()
                    elif buffered_event in self._failed_events:
                        self._failed_events.remove(buffered_event)
                self._record_delivery_success()
                results.append(result)
                continue

            with self._failed_events_lock:
                buffered_event["error"] = result.error
                buffered_event["attempts"] = (
                    buffered_event.get("attempts", 0) + result.attempts
                )
                buffered_event["status_code"] = result.status_code
                dropped_failed_events_total = self._dropped_failed_events_total
            self._record_delivery_failure()
            retained_result = SIEMDeliveryResult(
                delivered=False,
                attempts=result.attempts,
                status_code=result.status_code,
                error=result.error,
                buffered=True,
                dropped_failed_events_total=dropped_failed_events_total,
                circuit_open=self._circuit_open(),
            )
            results.append(retained_result)
            logger.warning(
                "SIEM audit redelivery failed; leaving event buffered",
                extra={
                    "client_id": self._client_id,
                    "secret_id": event.get("secret_id"),
                    "attempts": result.attempts,
                    "status_code": result.status_code,
                    "error": result.error,
                    "dropped_failed_events_total": (
                        dropped_failed_events_total
                    ),
                    "circuit_open": self._circuit_open(),
                },
            )
            break

        return results

    def log(self, event: AuditEvent) -> SIEMDeliveryResult:
        """Queue an audit event without performing network I/O inline."""
        enriched_event = {
            **event.__dict__,
            "client_id": self._client_id,
            "environment": os.environ.get("ENVIRONMENT", "unknown"),
            "platform_version": __version__
        }

        if self._shutdown_event.is_set():
            return SIEMDeliveryResult(
                delivered=False,
                attempts=0,
                error="SIEM audit logger is closed",
                queue_depth=self._delivery_queue.qsize(),
                dropped_queue_full_total=(
                    self.metrics.dropped_queue_full_total
                ),
                dropped_failed_events_total=self._dropped_failed_total(),
                circuit_open=self._circuit_open(),
            )
        
        try:
            self._delivery_queue.put_nowait(enriched_event)
        except queue.Full:
            with self._metrics_lock:
                self._dropped_queue_full_total += 1
                dropped_queue_full_total = self._dropped_queue_full_total
            logger.error(
                "SIEM audit queue full; dropping event metadata",
                extra={
                    "client_id": self._client_id,
                    "secret_id": event.secret_id,
                    "operation": event.operation,
                    "result": event.result,
                    "queue_depth": self._delivery_queue.qsize(),
                    "dropped_queue_full_total": dropped_queue_full_total,
                    "circuit_open": self._circuit_open(),
                },
            )
            return SIEMDeliveryResult(
                delivered=False,
                attempts=0,
                error="SIEM audit delivery queue full",
                queue_depth=self._delivery_queue.qsize(),
                dropped_queue_full_total=dropped_queue_full_total,
                dropped_failed_events_total=self._dropped_failed_total(),
                circuit_open=self._circuit_open(),
            )

        with self._metrics_lock:
            self._enqueued_total += 1
            dropped_queue_full_total = self._dropped_queue_full_total

        return SIEMDeliveryResult(
            delivered=False,
            attempts=0,
            queued=True,
            queue_depth=self._delivery_queue.qsize(),
            dropped_queue_full_total=dropped_queue_full_total,
            dropped_failed_events_total=self._dropped_failed_total(),
            circuit_open=self._circuit_open(),
        )

    def flush(self, timeout: Optional[float] = None) -> bool:
        """Wait for the delivery queue to drain; return False on timeout."""
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be >= 0")

        deadline = None if timeout is None else time.monotonic() + timeout
        with self._delivery_queue.all_tasks_done:
            while self._delivery_queue.unfinished_tasks:
                if deadline is None:
                    self._delivery_queue.all_tasks_done.wait()
                    continue

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._delivery_queue.all_tasks_done.wait(remaining)
        return True

    def close(self, timeout: float = 5.0) -> bool:
        """
        Flush queued audit events and stop the worker.

        Returns ``False`` if the queue could not drain or the worker could not
        stop before the timeout. Any events still waiting in the delivery queue
        after a flush timeout or a worker-join timeout are moved into the
        failed-event buffer so callers can retry them with
        ``drain_failed_events()`` instead of losing them on process exit.
        """
        if timeout < 0:
            raise ValueError("timeout must be >= 0")

        if self._worker_thread is threading.current_thread():
            self._shutdown_event.set()
            return False

        drained = self.flush(timeout=timeout)
        buffered_count = 0
        if not drained:
            self._shutdown_event.set()
            buffered_count += self._buffer_undrained_queue(
                "SIEM audit logger closed before delivery queue drained"
            )
            logger.error(
                "SIEM audit close timed out; queued events buffered",
                extra={
                    "client_id": self._client_id,
                    "buffered_queued_events": buffered_count,
                    "queue_depth": self._delivery_queue.qsize(),
                    "dropped_failed_events_total": (
                        self._dropped_failed_total()
                    ),
                },
            )
        else:
            self._shutdown_event.set()

        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout if drained else 0)

        stopped = not self._worker_thread.is_alive()
        if not stopped:
            # Always drain any remaining events to the DLQ on join-timeout,
            # whether or not the queue drained cleanly earlier. Events sitting
            # behind a wedged worker would otherwise be silently lost when the
            # caller drops its reference to this logger.
            buffered_count += self._buffer_undrained_queue(
                "SIEM audit worker did not exit before close timeout"
            )
            logger.warning(
                "SIEM audit worker did not stop before close timeout; "
                "remaining queue contents buffered to DLQ.",
                extra={
                    "client_id": self._client_id,
                    "queue_drained": drained,
                    "buffered_queued_events": buffered_count,
                    "queue_depth": self._delivery_queue.qsize(),
                },
            )

        return drained and stopped

    def shutdown(self) -> bool:
        """Backward-compatible alias for close()."""
        return self.close()

    def __enter__(self) -> "SIEMAuditLogger":
        """Use this logger as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Ensure the background worker is asked to stop."""
        self.close()

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
