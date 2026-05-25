"""
Enterprise Identity and Authentication

Code listings from Chapter 01, Book 2:
"Agentic AI in Production: Ship, Scale, and Govern Autonomous Systems"
by Dr. Vijay Raghavan

This file faithfully reproduces every code listing from the chapter, in book
order, with section banners showing the block number. Most listings are
runnable Python that builds incrementally; some are illustrative fragments
(log output, file trees, Dockerfile snippets, JSON examples) preserved as
docstrings so this file always remains valid Python.

To use a particular class or function, copy it into your own project and
provide the surrounding context (imports, dependencies) as needed.

Production Setup Checklist
--------------------------
1. Replace ``INTERNAL_NETWORK`` (Block 3) with the network ACL or VPC
   subnet list your environment treats as trusted. The block is a
   pedagogical foil for what NOT to do under zero-trust; keep the
   empty set in copy-paste deployments so the perimeter branch is
   never taken.
2. Wire ``audit_log`` (Block 3) to your SIEM sink (Splunk, Datadog,
   CloudWatch Logs, etc.). The placeholder is a fail-loud
   ``_RequiredDependency`` so a forgotten wiring raises rather than
   silently dropping audit events.
3. Replace ``database`` (Block 3) with your real DB driver. Same
   fail-loud behavior; a misconfigured deployment will not silently
   no-op queries.
4. Provision real signing material for ``CertificateAuthority`` and
   the JWT signer (Block 5+); the in-process key generation here is
   for local examples only.

The pedagogical examples in Block 3 illustrate what NOT to do under a
perimeter-security mindset, then show the zero-trust replacement. They
intentionally use fail-loud placeholders so a copy-paste deployment
fails fast rather than silently no-oping.
"""

# Module-level imports needed by listings that appear before Block 5's
# import section (e.g., the @dataclass decorator on DelegationToken in
# Block 4 evaluates its `datetime` annotations at class-creation time,
# and CertificateAuthority calls `logger.warning` inside Block 5).
import hashlib
import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


# ============================================================================
# Block 1 (chapter listing #1)
# ============================================================================

# What the logs look like WITHOUT identity infrastructure.
# Assigned to a private name so static analyzers do not flag a bare
# expression; the dict is illustrative, not used at runtime.
_example_log_without_identity = {
    "timestamp": "2024-03-15T03:14:22Z",
    "event": "trade_executed",
    "symbol": "AAPL",
    "quantity": 50000,
    "agent": "trading-agent"  # Which one? There are 12 instances.
}

# What the logs look like WITH identity infrastructure.
# Same illustrative-only treatment: bound to a private name to keep
# the module importable and lint-clean.
_example_log_with_identity = {
    "timestamp": "2024-03-15T03:14:22Z",
    "event": "trade_executed",
    "symbol": "AAPL",
    "quantity": 50000,
    "agent_id": "agent_7f3a2b1c9d4e",
    "certificate_serial": "4a:7b:9c:2d:1e:8f",
    "permissions_at_execution": ["orders:execute", "data:read"],
    "delegation_chain": {
        "human_approver": "alice@acme.com",
        "delegation_id": "del_9x8y7z",
        "granted_at": "2024-03-14T09:00:00Z"
    }
}

# ============================================================================
# Block 2 (chapter listing #2)
# ============================================================================

# WITHOUT identity: Investigation dead-ends
def investigate_incident_without_identity(trade_id):
    trade = get_trade(trade_id)
    # trade.agent = "trading-agent"
    # Q: Which instance? Unknown.
    # Q: What permissions? Check deployment config... which version?
    # Q: Who approved? Search Slack history...
    # Q: Was credential compromised? No way to know.
    return "INVESTIGATION STALLED"

# WITH identity: Complete traceability
async def investigate_incident_with_identity(trade_id, identity_service):
    trade = get_trade(trade_id)

    # Get the exact agent identity
    identity = await identity_service.get_identity(trade.agent_id)

    # Get full audit trail
    events = await identity_service.get_audit_log(
        agent_id=trade.agent_id,
        since=trade.timestamp - timedelta(hours=24)
    )

    return {
        "agent": identity.name,
        "certificate_valid": identity.is_valid(),
        "permissions_at_time": identity.permissions,
        "provisioned_by": identity.metadata.get("approver"),
        "delegation_chain": events.filter(type="delegation"),
        "credential_rotations": events.filter(type="key_rotated")
    }

# ============================================================================
# Block 3 (chapter listing #3)
# ============================================================================

# Placeholder bindings for the pedagogical examples below. See the
# Production Setup Checklist at the top of this module.
#
# - INTERNAL_NETWORK (checklist #1) intentionally stays a real empty
#   set: the `in` operator must work for the perimeter-security
#   counter-example, and an empty set makes the trust branch explicit
#   instead of silently taking it in a copy-paste deployment.
# - `database` (checklist #3) and `audit_log` (checklist #2) are
#   replaced with fail-loud RequiredDependency placeholders; any call
#   raises a clear error rather than silently no-oping.
import os as _os_early
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _optional import _RequiredDependency  # noqa: E402

INTERNAL_NETWORK: set[str] = set()  # TODO[1]: see checklist
database = _RequiredDependency(  # TODO[3]: see checklist
    "database",
    "Replace with your real DB driver (psycopg, sqlalchemy, ...).",
)
audit_log = _RequiredDependency(  # TODO[2]: see checklist
    "audit_log",
    "Wire to your SIEM sink (Splunk, Datadog, CloudWatch Logs, ...).",
)


# Module-level trip-wire: refuse to be a silent no-op in production.
# The empty INTERNAL_NETWORK above is a pedagogical foil (every IP fails
# the `in` check), but a copy-paste deployment that imports this module
# with AGENT_ENV=production must populate it before use.
def _check_internal_network() -> None:
    if _os_early.environ.get("AGENT_ENV") == "production" and not INTERNAL_NETWORK:
        raise RuntimeError(
            "INTERNAL_NETWORK is empty in production. "
            "Populate it with the CIDR ranges of your internal network "
            "before importing this module. See production-setup-checklist."
        )


_check_internal_network()


def _stable_query_hash(query: str | bytes) -> str:
    """Return a deterministic SHA-256 fingerprint for audit query fields."""
    if isinstance(query, bytes):
        query_bytes = query
    else:
        query_bytes = query.encode("utf-8")
    return hashlib.sha256(query_bytes).hexdigest()


# Traditional perimeter security (what NOT to do)
def handle_database_request_insecure(request):
    # Agent is "inside" our network, so trust it
    if request.source_ip in INTERNAL_NETWORK:
        return database.execute(request.query)
    return "Access denied"

# Zero-trust approach
async def handle_database_request_zero_trust(request, identity_service):
    # 1. VERIFY EXPLICITLY: Validate the agent's identity
    try:
        payload = await identity_service.validate_token(
            request.agent_token,
            required_scope=PermissionScope.DATA_READ
        )
        identity = await identity_service.get_identity(payload["sub"])
        if not identity:
            raise ValueError("agent identity not found")
    except ValueError:
        audit_log.record("database_access_denied", reason="invalid_token")
        return "Access denied: invalid credentials"
    except PermissionError:
        audit_log.record("database_access_denied", reason="insufficient_data_scope")
        return "Access denied: missing data:read permission"

    # 2. LEAST PRIVILEGE: Check specific permission for this resource
    if "customers" in request.query and not identity.has_permission("data:customers:read"):
        audit_log.record("database_access_denied", reason="insufficient_scope")
        return "Access denied: missing customers:read permission"

    # 3. ASSUME BREACH: Log everything, even successful requests
    audit_log.record(
        "database_query_executed",
        agent_id=identity.agent_id,
        query_hash=_stable_query_hash(request.query),
        tables_accessed=["customers"],
        certificate_serial=identity.certificate_serial
    )

    return database.execute(request.query)

# ============================================================================
# Block 4 (chapter listing #4)
# ============================================================================

@dataclass
class DelegationToken:
    """Token representing human-to-agent delegation."""
    
    delegation_id: str
    human_subject: str          # Human's OIDC subject claim
    human_email: str            # Human's email for audit
    agent_id: str               # Receiving agent
    delegated_scopes: list[str] # What the agent can do
    issued_at: datetime
    expires_at: datetime
    constraints: dict           # Additional restrictions
    
    def to_jwt(self, signing_key, key_id: str = "delegation_signing") -> str:
        """Encode as an RS256-signed JWT using the issuer's private key."""
        payload = {
            "type": "delegation",
            "del_id": self.delegation_id,
            "human_sub": self.human_subject,
            "human_email": self.human_email,
            "agent_id": self.agent_id,
            "scopes": self.delegated_scopes,
            "iat": int(self.issued_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
            "constraints": self.constraints
        }
        return jwt.encode(
            payload,
            signing_key,
            algorithm="RS256",
            headers={"kid": key_id}
        )

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

"""
Enterprise Agent Identity Service
==================================
Reference implementation of agent identity management.

This service provides:
1. Cryptographic identity provisioning with X.509 certificates
2. Token-based authentication with JWT
3. Human-agent delegation via OIDC
4. Key rotation and credential lifecycle
5. Comprehensive audit logging

Security considerations:
- All private keys stored in HSM/KMS (simulated here)
- Tokens are short-lived with explicit revocation
- Every operation is audited
- Permissions follow least-privilege

Code Navigation (search by symbol; line numbers drift as the file
evolves, so we anchor to class names instead):
- Permission Model: see PermissionScope, IdentityStatus,
  AuditEventType below.
- Data Models: see AgentIdentity, Credential, DelegationRecord,
  AuditEvent below.
- Storage Layer: see IdentityStore and KeyVault below.
- Certificate Authority: see CertificateAuthority below.
- Main Service: see AgentIdentityService below.
"""

import asyncio
import contextlib
import hashlib
import heapq
import hmac
import json
import os
import random
import secrets
import threading
import uuid
import warnings
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Optional

import jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtensionOID



class PermissionScope(str, Enum):
    """Standard permission scopes for agents.
    
    Follows resource:action pattern for clarity.
    """
    # Data permissions
    DATA_READ = "data:read"
    DATA_WRITE = "data:write"
    DATA_DELETE = "data:delete"
    
    # Tool permissions
    TOOLS_INVOKE = "tools:invoke"
    TOOLS_ADMIN = "tools:admin"
    
    # Agent permissions
    AGENTS_INVOKE = "agents:invoke"
    AGENTS_CREATE = "agents:create"
    AGENTS_MANAGE = "agents:manage"
    
    # Session permissions
    SESSIONS_CREATE = "sessions:create"
    SESSIONS_MANAGE = "sessions:manage"
    
    # Secret permissions
    SECRETS_READ = "secrets:read"
    SECRETS_WRITE = "secrets:write"
    
    # Administrative
    ADMIN_FULL = "admin:*"


Permission = PermissionScope | str


def permission_value(permission: Permission) -> str:
    """Return the wire-format string for standard and custom scopes."""
    if isinstance(permission, PermissionScope):
        return permission.value
    return permission


_DELEGATION_AUTHZ_CLAIMS = (
    "delegable_scopes",
    "permissions",
    "scp",
    "scope",
)


def _scope_claim_values(claim_value: Any) -> set[str]:
    """Normalize common OIDC/OAuth scope claim shapes into a string set."""
    if claim_value is None:
        return set()
    if isinstance(claim_value, str):
        return {scope for scope in claim_value.split() if scope}
    if isinstance(claim_value, (list, tuple, set)):
        return {
            permission_value(scope) if isinstance(scope, PermissionScope) else str(scope)
            for scope in claim_value
        }
    return set()


def _delegable_scope_claims(human_oidc_token: dict) -> set[str]:
    """Collect scopes this human token is allowed to delegate."""
    allowed: set[str] = set()
    for claim_name in _DELEGATION_AUTHZ_CLAIMS:
        allowed.update(_scope_claim_values(human_oidc_token.get(claim_name)))
    return allowed


def _scope_allowed_by_claims(scope: str, allowed_scopes: set[str]) -> bool:
    """Return true if OIDC claims authorize delegating this exact scope."""
    return (
        permission_value(PermissionScope.ADMIN_FULL) in allowed_scopes
        or scope in allowed_scopes
    )


def _datetime_utc(value: datetime) -> datetime:
    """Normalize certificate datetimes to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _certificate_validity_window_utc(
    cert: x509.Certificate
) -> tuple[datetime, datetime]:
    """Return certificate validity bounds as timezone-aware UTC datetimes."""
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before
    if not_after is None:
        not_after = cert.not_valid_after
    return _datetime_utc(not_before), _datetime_utc(not_after)


_MIN_TOKEN_HASH_SECRET_BYTES = 32
_TEST_ENVIRONMENTS = {"test", "testing", "pytest"}
_PRODUCTION_ENVIRONMENTS = {"production", "prod"}
_LOCAL_KEY_VAULT_ENVIRONMENTS = {
    "development",
    "dev",
    "demo",
    "local",
    *_TEST_ENVIRONMENTS,
}
_DISALLOWED_SECRET_MARKERS = (
    "demo",
    "test",
    "example",
    "sample",
    "changeme",
    "change_me",
    "change-me",
    "password",
)


def _current_environment() -> str:
    return os.environ.get("ENVIRONMENT", "production").lower()


def _is_test_environment(environment: str) -> bool:
    return environment.lower() in _TEST_ENVIRONMENTS


def _is_production_environment(environment: str) -> bool:
    return environment.lower() in _PRODUCTION_ENVIRONMENTS


def _is_local_key_vault_environment(environment: str) -> bool:
    return environment.lower() in _LOCAL_KEY_VAULT_ENVIRONMENTS


def _is_production_key_provider(key_provider: Any) -> bool:
    return bool(getattr(key_provider, "is_production_key_provider", False))


def _validate_key_provider_environment(
    key_provider: Any,
    environment: str
) -> None:
    """Fail closed when a demo key provider is wired into deployable envs."""
    if _is_production_key_provider(key_provider):
        return

    if _is_local_key_vault_environment(environment):
        return

    if getattr(key_provider, "is_in_memory_demo_provider", False):
        raise RuntimeError(
            "In-memory KeyVault is for explicit development/demo/test use only. "
            "Set ENVIRONMENT=development, demo, or test for local examples, "
            "or provide a KMS/HSM-backed key provider marked "
            "is_production_key_provider=True."
        )

    if _is_production_environment(environment):
        raise RuntimeError(
            "ENVIRONMENT=production/prod requires a KMS/HSM-backed key "
            "provider marked is_production_key_provider=True."
        )


def _validate_token_hash_secret(secret: str, environment: str) -> str:
    """Reject credential-hash HMAC secrets that are too weak."""
    secret_bytes = secret.encode("utf-8")
    if len(secret_bytes) < _MIN_TOKEN_HASH_SECRET_BYTES:
        raise RuntimeError(
            "TOKEN_HASH_SECRET must be at least 32 bytes (256 bits)."
        )

    lower_secret = secret.lower()
    has_demo_marker = any(
        marker in lower_secret for marker in _DISALLOWED_SECRET_MARKERS
    )
    if has_demo_marker and not _is_test_environment(environment):
        raise RuntimeError(
            "TOKEN_HASH_SECRET must not contain demo/test/example markers outside "
            "test runs."
        )

    return secret


class IdentityStatus(str, Enum):
    """Lifecycle status of an agent identity."""
    PENDING = "pending"      # Created but not yet activated
    ACTIVE = "active"        # Normal operating state
    SUSPENDED = "suspended"  # Temporarily disabled
    REVOKED = "revoked"      # Permanently disabled
    EXPIRED = "expired"      # Past expiration date


class AuditEventType(str, Enum):
    """Types of auditable events."""
    # Identity lifecycle
    IDENTITY_CREATED = "identity.created"
    IDENTITY_ACTIVATED = "identity.activated"
    IDENTITY_SUSPENDED = "identity.suspended"
    IDENTITY_REVOKED = "identity.revoked"
    IDENTITY_EXPIRED = "identity.expired"
    
    # Credential operations
    CERTIFICATE_ISSUED = "certificate.issued"
    CERTIFICATE_RENEWED = "certificate.renewed"
    CERTIFICATE_REVOKED = "certificate.revoked"
    TOKEN_ISSUED = "token.issued"
    TOKEN_REVOKED = "token.revoked"
    TOKEN_VALIDATED = "token.validated"
    TOKEN_REJECTED = "token.rejected"
    
    # Permission changes
    PERMISSION_GRANTED = "permission.granted"
    PERMISSION_REVOKED = "permission.revoked"
    
    # Delegation
    DELEGATION_CREATED = "delegation.created"
    DELEGATION_USED = "delegation.used"
    DELEGATION_REVOKED = "delegation.revoked"
    DELEGATION_REJECTED = "delegation.rejected"
    
    # Key management
    KEY_ROTATED = "key.rotated"
    KEY_COMPROMISED = "key.compromised"

    # Trade execution
    TRADE_EXECUTED = "trade.executed"
    TRADE_REJECTED = "trade.rejected"



@dataclass
class AgentIdentity:
    """
    Core identity record for an agent.
    
    Each agent has exactly one identity that tracks:
    - Unique identifier
    - Cryptographic credentials (public key / certificate)
    - Permissions
    - Lifecycle state
    - Ownership and metadata
    """
    agent_id: str
    name: str
    description: str
    owner_team: str
    owner_email: str
    permissions: list[Permission]
    status: IdentityStatus
    certificate_pem: Optional[str]
    certificate_serial: Optional[str]
    created_at: datetime
    activated_at: Optional[datetime]
    expires_at: datetime
    last_used_at: Optional[datetime]
    suspended_at: Optional[datetime]
    revoked_at: Optional[datetime]
    revocation_reason: Optional[str]
    metadata: dict = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if identity can currently be used."""
        if self.status != IdentityStatus.ACTIVE:
            return False
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        return True
    
    def has_permission(self, scope: Permission) -> bool:
        """Check if identity has a specific permission."""
        permission_values = {permission_value(p) for p in self.permissions}
        if permission_value(PermissionScope.ADMIN_FULL) in permission_values:
            return True
        return permission_value(scope) in permission_values
    
    def has_any_permission(self, scopes: list[Permission]) -> bool:
        """Check if identity has any of the specified permissions."""
        return any(self.has_permission(s) for s in scopes)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for storage/transmission."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "description": self.description,
            "owner_team": self.owner_team,
            "owner_email": self.owner_email,
            "permissions": [permission_value(p) for p in self.permissions],
            "status": self.status.value,
            "certificate_pem": self.certificate_pem,
            "certificate_serial": self.certificate_serial,
            "created_at": self.created_at.isoformat(),
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "expires_at": self.expires_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "suspended_at": self.suspended_at.isoformat() if self.suspended_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
            "metadata": self.metadata
        }


@dataclass
class Credential:
    """Record of an issued credential (token)."""
    credential_id: str
    agent_id: str
    credential_type: str  # "jwt", "api_key", etc.
    token_hash: str       # Hash of actual token (never store raw)
    scopes: list[str]
    issued_at: datetime
    expires_at: datetime
    issued_by: str        # Who/what issued this credential
    is_revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    
    def is_valid(self) -> bool:
        """Check if credential is currently valid."""
        if self.is_revoked:
            return False
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        return True


@dataclass
class DelegationRecord:
    """Record of human-to-agent delegation."""
    delegation_id: str
    human_subject: str
    human_email: str
    human_name: str
    agent_id: str
    delegated_scopes: list[str]
    constraints: dict
    created_at: datetime
    expires_at: datetime
    used_count: int = 0
    max_uses: Optional[int] = None
    is_revoked: bool = False
    revoked_at: Optional[datetime] = None


@dataclass
class AuditEvent:
    """Immutable audit log entry."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    agent_id: Optional[str]
    actor_id: str           # Who performed the action
    actor_type: str         # "human", "agent", "system"
    resource_type: str      # What was affected
    resource_id: str
    action: str
    outcome: str            # "success", "failure", "denied"
    details: dict
    client_ip: Optional[str]
    user_agent: Optional[str]
    correlation_id: Optional[str]  # Links related events
    
    def to_dict(self) -> dict:
        """Serialize for storage."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "outcome": self.outcome,
            "details": self.details,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "correlation_id": self.correlation_id
        }


# Storage Layer (Production: Replace with Database)

class IdentityStore:
    """
    Storage for identity data.
    
    In production, replace with:
    - PostgreSQL for identity records
    - Redis for credential validation cache
    - Elasticsearch for audit log queries
    """
    is_durable_production_store = False
    
    def __init__(
        self,
        audit_log_capacity: int = 10_000,
        max_credential_records: int = 50_000,
        revoked_credential_retention_hours: int = 24,
        max_revoked_cert_records: int = 50_000,
        revoked_cert_retention_hours: int = 24,
        max_delegation_records: int = 50_000,
        terminal_delegation_retention_hours: int = 24
    ):
        if max_revoked_cert_records < 1:
            raise ValueError("max_revoked_cert_records must be positive")
        if revoked_cert_retention_hours <= 0:
            raise ValueError("revoked_cert_retention_hours must be positive")
        # Identity records are bounded by agent population. Credential and
        # delegation records are operational logs, so this teaching store
        # prunes terminal records and caps live entries below.
        self._identities: dict[str, AgentIdentity] = {}
        self._credentials: dict[str, Credential] = {}
        self._credentials_by_agent: dict[str, set[str]] = {}
        self._credential_expiry_heap: list[tuple[datetime, str]] = []
        self._max_credential_records = max_credential_records
        self._revoked_credential_retention = timedelta(
            hours=revoked_credential_retention_hours
        )
        self._delegations: dict[str, DelegationRecord] = {}
        self._delegation_expiry_heap: list[tuple[datetime, str]] = []
        self._max_delegation_records = max_delegation_records
        self._terminal_delegation_retention = timedelta(
            hours=terminal_delegation_retention_hours
        )
        # Audit log is *not* naturally bounded -- every action appends an event.
        # Use a bounded deque so the process cannot leak memory indefinitely.
        # For long-running production deployments, replace this in-memory ring
        # buffer with a durable sink (Kafka, Loki, CloudTrail, etc.) so that
        # events evicted from the deque are still retained for compliance.
        self._audit_log: deque[AuditEvent] = deque(maxlen=audit_log_capacity)
        # Eviction counter: increments each time a full deque drops its oldest
        # event on append. Exposed via the audit_events_dropped property so
        # operators can spot silent compliance-log loss. We re-emit a WARN
        # periodically so a single early log line is not the only signal of
        # sustained sink saturation: see log_audit_event for the cadence.
        self._audit_events_dropped: int = 0
        # Re-warn every N evictions; the first eviction is always logged
        # (counter == 1 satisfies % threshold == 1), then we emit every
        # 1000 evictions so a wedged sink remains visible in operator logs.
        self._eviction_warn_threshold: int = 1000
        self._revoked_certs: dict[str, datetime] = {}  # serial -> retain-until
        self._revoked_cert_expiry_heap: list[tuple[datetime, str]] = []
        self._max_revoked_cert_records = max_revoked_cert_records
        self._revoked_cert_retention = timedelta(hours=revoked_cert_retention_hours)
        self._identity_activity_lock = asyncio.Lock()
        self._delegation_lock = asyncio.Lock()

    def _credential_removable_at(self, credential: Credential) -> datetime:
        """Return when an in-memory credential record can be pruned."""
        if credential.is_revoked:
            revoked_at = credential.revoked_at or credential.expires_at
            return min(
                credential.expires_at,
                revoked_at + self._revoked_credential_retention
            )
        return credential.expires_at

    def _delete_credential(self, credential_id: str) -> None:
        """Remove a credential and its secondary index entry."""
        credential = self._credentials.pop(credential_id, None)
        if not credential:
            return

        agent_credentials = self._credentials_by_agent.get(credential.agent_id)
        if not agent_credentials:
            return

        agent_credentials.discard(credential_id)
        if not agent_credentials:
            del self._credentials_by_agent[credential.agent_id]

    def _cleanup_revoked_certs(self, now: Optional[datetime] = None) -> None:
        """Prune expired certificate revocations and enforce a hard cap."""
        now = now or datetime.now(timezone.utc)

        while self._revoked_cert_expiry_heap:
            expires_at, cert_serial = self._revoked_cert_expiry_heap[0]
            current_expiry = self._revoked_certs.get(cert_serial)
            if current_expiry is None or current_expiry != expires_at:
                heapq.heappop(self._revoked_cert_expiry_heap)
                continue
            if expires_at > now:
                break

            heapq.heappop(self._revoked_cert_expiry_heap)
            del self._revoked_certs[cert_serial]

        while len(self._revoked_certs) > self._max_revoked_cert_records:
            if not self._revoked_cert_expiry_heap:
                break
            expires_at, cert_serial = heapq.heappop(
                self._revoked_cert_expiry_heap
            )
            if self._revoked_certs.get(cert_serial) == expires_at:
                del self._revoked_certs[cert_serial]

    def _cleanup_credentials(self, now: Optional[datetime] = None) -> None:
        """
        Bound the teaching store by pruning expired/revoked credentials.

        JWT expiry still protects expired tokens cryptographically. If the
        record cap is reached, this store drops the soonest-removable records
        and validation fails closed because missing credentials are rejected.
        """
        now = now or datetime.now(timezone.utc)

        while self._credential_expiry_heap:
            removable_at, credential_id = self._credential_expiry_heap[0]
            credential = self._credentials.get(credential_id)
            if credential is None:
                heapq.heappop(self._credential_expiry_heap)
                continue
            if self._credential_removable_at(credential) != removable_at:
                heapq.heappop(self._credential_expiry_heap)
                continue
            if removable_at > now:
                break

            heapq.heappop(self._credential_expiry_heap)
            self._delete_credential(credential_id)

        while len(self._credentials) > self._max_credential_records:
            if not self._credential_expiry_heap:
                break
            removable_at, credential_id = heapq.heappop(
                self._credential_expiry_heap
            )
            credential = self._credentials.get(credential_id)
            if credential is None:
                continue
            if self._credential_removable_at(credential) != removable_at:
                continue
            self._delete_credential(credential_id)

    def _delegation_used_up(self, delegation: DelegationRecord) -> bool:
        """Return true when a delegation can never be consumed again."""
        return (
            delegation.max_uses is not None
            and delegation.used_count >= delegation.max_uses
        )

    def _delegation_removable_at(
        self,
        delegation: DelegationRecord
    ) -> datetime:
        """Return when a terminal delegation can be pruned."""
        if self._delegation_used_up(delegation):
            return datetime.min.replace(tzinfo=timezone.utc)
        if delegation.is_revoked:
            revoked_at = delegation.revoked_at or delegation.expires_at
            return min(
                delegation.expires_at,
                revoked_at + self._terminal_delegation_retention
            )
        return delegation.expires_at

    def _delete_delegation(self, delegation_id: str) -> None:
        """Remove a delegation record from the teaching store."""
        self._delegations.pop(delegation_id, None)

    def _cleanup_delegations(self, now: Optional[datetime] = None) -> None:
        """
        Bound delegation memory by pruning expired, revoked, and used-up rows.

        If the cap is still exceeded after terminal cleanup, this store drops
        the nearest-removable delegation and validation fails closed because
        missing delegation records are rejected.
        """
        now = now or datetime.now(timezone.utc)

        while self._delegation_expiry_heap:
            removable_at, delegation_id = self._delegation_expiry_heap[0]
            delegation = self._delegations.get(delegation_id)
            if delegation is None:
                heapq.heappop(self._delegation_expiry_heap)
                continue
            if self._delegation_removable_at(delegation) != removable_at:
                heapq.heappop(self._delegation_expiry_heap)
                continue
            if removable_at > now:
                break

            heapq.heappop(self._delegation_expiry_heap)
            self._delete_delegation(delegation_id)

        while len(self._delegations) > self._max_delegation_records:
            if not self._delegation_expiry_heap:
                break
            removable_at, delegation_id = heapq.heappop(
                self._delegation_expiry_heap
            )
            delegation = self._delegations.get(delegation_id)
            if delegation is None:
                continue
            if self._delegation_removable_at(delegation) != removable_at:
                continue
            self._delete_delegation(delegation_id)
    
    async def create_identity(self, identity: AgentIdentity) -> None:
        """Store a new identity."""
        if identity.agent_id in self._identities:
            raise ValueError(f"Identity already exists: {identity.agent_id}")
        self._identities[identity.agent_id] = identity
    
    async def get_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        """Retrieve an identity by ID."""
        return self._identities.get(agent_id)
    
    async def update_identity(self, identity: AgentIdentity) -> None:
        """Update an existing identity."""
        if identity.agent_id not in self._identities:
            raise ValueError(f"Identity not found: {identity.agent_id}")
        self._identities[identity.agent_id] = identity

    async def record_identity_activity(
        self,
        agent_id: str,
        seen_at: datetime,
        min_interval: timedelta
    ) -> bool:
        """
        Persist last_used_at at most once per interval.

        Production stores should implement this as an atomic conditional
        UPDATE, for example:
        WHERE agent_id = :agent_id
          AND (last_used_at IS NULL OR last_used_at < :threshold)
        """
        async with self._identity_activity_lock:
            identity = self._identities.get(agent_id)
            if not identity:
                return False

            previous_seen_at = identity.last_used_at
            if previous_seen_at and seen_at - previous_seen_at < min_interval:
                return False

            identity.last_used_at = seen_at
            self._identities[agent_id] = identity
            return True
    
    async def list_identities(
        self,
        owner_team: Optional[str] = None,
        status: Optional[IdentityStatus] = None,
        limit: int = 100,
        offset: int = 0
    ) -> list[AgentIdentity]:
        """List identities with optional filters."""
        results = list(self._identities.values())
        
        if owner_team:
            results = [i for i in results if i.owner_team == owner_team]
        if status:
            results = [i for i in results if i.status == status]
        
        return results[offset:offset + limit]
    
    async def store_credential(self, credential: Credential) -> None:
        """Store a credential record."""
        previous = self._credentials.get(credential.credential_id)
        if previous and previous.agent_id != credential.agent_id:
            previous_agent_credentials = self._credentials_by_agent.get(
                previous.agent_id
            )
            if previous_agent_credentials:
                previous_agent_credentials.discard(credential.credential_id)

        self._credentials[credential.credential_id] = credential
        self._credentials_by_agent.setdefault(credential.agent_id, set()).add(
            credential.credential_id
        )
        heapq.heappush(
            self._credential_expiry_heap,
            (self._credential_removable_at(credential), credential.credential_id)
        )
        self._cleanup_credentials()
    
    async def get_credential(self, credential_id: str) -> Optional[Credential]:
        """Retrieve a credential by ID."""
        self._cleanup_credentials()
        return self._credentials.get(credential_id)
    
    async def get_credentials_for_agent(self, agent_id: str) -> list[Credential]:
        """Get all credentials for an agent."""
        self._cleanup_credentials()
        credential_ids = list(self._credentials_by_agent.get(agent_id, set()))
        credentials: list[Credential] = []

        for credential_id in credential_ids:
            credential = self._credentials.get(credential_id)
            if credential is None:
                agent_credentials = self._credentials_by_agent.get(agent_id)
                if agent_credentials:
                    agent_credentials.discard(credential_id)
                    if not agent_credentials:
                        del self._credentials_by_agent[agent_id]
                continue
            credentials.append(credential)

        return credentials
    
    async def store_delegation(self, delegation: DelegationRecord) -> None:
        """Store a delegation record."""
        async with self._delegation_lock:
            self._cleanup_delegations()
            self._delegations[delegation.delegation_id] = delegation
            heapq.heappush(
                self._delegation_expiry_heap,
                (
                    self._delegation_removable_at(delegation),
                    delegation.delegation_id
                )
            )
            self._cleanup_delegations()
    
    async def get_delegation(self, delegation_id: str) -> Optional[DelegationRecord]:
        """Retrieve a delegation by ID."""
        async with self._delegation_lock:
            self._cleanup_delegations()
            return self._delegations.get(delegation_id)

    async def consume_delegation_use(
        self,
        delegation_id: str
    ) -> DelegationRecord:
        """
        Atomically consume one allowed delegation use.

        Production stores should make this a single conditional update:
        increment used_count only where used_count < max_uses, or where
        max_uses is NULL.
        """
        async with self._delegation_lock:
            self._cleanup_delegations()
            delegation = self._delegations.get(delegation_id)
            if not delegation:
                raise ValueError("Delegation record not found")

            if delegation.is_revoked:
                raise ValueError("Delegation has been revoked")

            if datetime.now(timezone.utc) > delegation.expires_at:
                raise ValueError("Delegation has expired")

            if (
                delegation.max_uses is not None
                and delegation.used_count >= delegation.max_uses
            ):
                raise ValueError("Delegation has exceeded maximum uses")

            delegation.used_count += 1
            if self._delegation_used_up(delegation):
                self._delete_delegation(delegation_id)
            else:
                self._delegations[delegation_id] = delegation
                heapq.heappush(
                    self._delegation_expiry_heap,
                    (
                        self._delegation_removable_at(delegation),
                        delegation_id
                    )
                )
            return delegation
    
    async def add_to_crl(
        self,
        cert_serial: str,
        expires_at: Optional[datetime] = None
    ) -> None:
        """Add certificate to revocation list."""
        now = datetime.now(timezone.utc)
        retain_until = expires_at or (now + self._revoked_cert_retention)
        retain_until = max(retain_until, now + self._revoked_cert_retention)
        self._revoked_certs[cert_serial] = retain_until
        heapq.heappush(self._revoked_cert_expiry_heap, (retain_until, cert_serial))
        self._cleanup_revoked_certs(now)
    
    async def is_cert_revoked(self, cert_serial: str) -> bool:
        """Check if certificate is revoked."""
        self._cleanup_revoked_certs()
        return cert_serial in self._revoked_certs
    
    async def log_audit_event(self, event: AuditEvent) -> None:
        """Append to audit log (immutable)."""
        if (
            self._audit_log.maxlen is not None
            and len(self._audit_log) == self._audit_log.maxlen
        ):
            self._audit_events_dropped += 1
            # Re-emit periodically: the first eviction fires immediately
            # (counter == 1) and we then re-warn every _eviction_warn_threshold
            # evictions so a sustained sink outage stays visible instead of
            # being silenced by a single boot-time WARN.
            if (
                self._audit_events_dropped
                % self._eviction_warn_threshold
            ) == 1:
                logger.warning(
                    "IdentityStore audit log evicting old events "
                    "(maxlen=%d, total evicted: %d); investigate sink "
                    "saturation and configure a durable sink to retain "
                    "compliance history.",
                    self._audit_log.maxlen,
                    self._audit_events_dropped,
                )
        self._audit_log.append(event)

    @property
    def audit_events_dropped(self) -> int:
        """Number of audit events silently evicted by deque overflow."""
        return self._audit_events_dropped
    
    async def query_audit_log(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: Optional[int] = None
    ) -> list[AuditEvent]:
        """Query audit log with filters."""
        # Materialize the deque snapshot to a list so callers can either keep
        # the historical tail-query behavior or page from the start.
        results: list[AuditEvent] = list(self._audit_log)

        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if actor_id:
            results = [e for e in results if e.actor_id == actor_id]
        if since:
            results = [e for e in results if e.timestamp >= since]
        if until:
            results = [e for e in results if e.timestamp <= until]

        if offset is not None:
            return results[offset:offset + limit]

        return results[-limit:]


class KeyVault:
    """
    Development/demo key storage.

    In production, replace with:
    - AWS KMS
    - Azure Key Vault
    - HashiCorp Vault
    - Hardware Security Module (HSM)

    PRODUCTION DANGER: This is an in-memory key store. Private keys are
    stored unencrypted in the process's heap and disappear on restart.
    Use only for development, tests, or worked examples. Production
    deployments MUST replace this with an HSM- or KMS-backed
    KeyManagementService implementation (see the chapter's "Key
    Management" section).
    """

    is_in_memory_demo_provider = True
    is_production_key_provider = False

    def __init__(self):
        self._keys: dict[str, bytes] = {}
        self._metadata: dict[str, dict] = {}
        # Trip-wire: refuse to instantiate an in-memory vault under
        # AGENT_ENV=production. Placed at the end of __init__ so
        # subclasses that mark themselves production-grade can call
        # super().__init__() without tripping this guard prematurely.
        if (
            self.is_in_memory_demo_provider
            and not self.is_production_key_provider
            and os.environ.get("AGENT_ENV") == "production"
        ):
            raise RuntimeError(
                "In-memory KeyVault refused in production. "
                "Provide an HSM- or KMS-backed implementation; this class is "
                "for development and testing only. "
                "See production-setup-checklist."
            )

    def _assert_environment_allowed(self) -> None:
        _validate_key_provider_environment(self, _current_environment())
    
    async def generate_key_pair(
        self,
        key_id: str,
        key_size: int = 2048,
        metadata: Optional[dict] = None
    ) -> rsa.RSAPublicKey:
        """Generate and store a new RSA key pair, return the public key.

        These keypairs sign X.509 agent certificates and service-issued JWTs.
        Production multi-service deployments commonly expose the JWT public
        key through JWKS while keeping the private key in KMS/HSM custody.
        """
        self._assert_environment_allowed()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Store private key (in production, this stays in HSM)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self._keys[key_id] = pem
        self._metadata[key_id] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_size": key_size,
            **(metadata or {})
        }
        
        return private_key.public_key()
    
    async def get_private_key(self, key_id: str) -> Optional[rsa.RSAPrivateKey]:
        """Retrieve private key for signing."""
        self._assert_environment_allowed()
        pem = self._keys.get(key_id)
        if not pem:
            return None
        return serialization.load_pem_private_key(pem, password=None)

    async def get_public_key(self, key_id: str) -> Optional[rsa.RSAPublicKey]:
        """Retrieve public key for verification."""
        private_key = await self.get_private_key(key_id)
        if not private_key:
            return None
        return private_key.public_key()
    
    async def sign(
        self,
        key_id: str,
        data: bytes
    ) -> bytes:
        """Sign data with stored private key."""
        private_key = await self.get_private_key(key_id)
        if not private_key:
            raise ValueError(f"Key not found: {key_id}")
        
        return private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    
    async def delete_key(self, key_id: str) -> None:
        """Securely delete a key."""
        self._assert_environment_allowed()
        if key_id in self._keys:
            # In production, ensure secure deletion
            del self._keys[key_id]
            del self._metadata[key_id]
    
    async def rotate_key(
        self,
        old_key_id: str,
        new_key_id: str
    ) -> rsa.RSAPublicKey:
        """Rotate to a new key, keeping old for verification period."""
        metadata = self._metadata.get(old_key_id, {})
        metadata["rotated_from"] = old_key_id
        metadata["rotated_at"] = datetime.now(timezone.utc).isoformat()
        
        return await self.generate_key_pair(new_key_id, metadata=metadata)



class CertificateAuthority:
    """
    Internal Certificate Authority for agent certificates.
    
    Provides:
    - Certificate issuance with custom extensions
    - Certificate validation
    - Revocation checking
    """
    
    # PEN OID arc for agent identity attributes. The 99999 arc below is a
    # documented placeholder (the IANA Private Enterprise Numbers space under
    # 1.3.6.1.4.1); deployers MUST replace it with their registered PEN
    # obtained from https://pen.iana.org/pen/PenApplication.page. Pass a
    # different arc to __init__ to override at runtime. See ITU-T X.660 for
    # OID structure.
    AGENT_ID_OID_ARC: ClassVar[str] = "1.3.6.1.4.1.99999.1"

    # Default OIDs derived from the placeholder arc. Instance attributes set
    # in __init__ override these when a custom arc is supplied.
    AGENT_ID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
    AGENT_PERMISSIONS_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.2")
    AGENT_OWNER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.3")

    def __init__(
        self,
        key_vault: KeyVault,
        store: IdentityStore,
        ca_key_id: str = "ca_intermediate",
        agent_id_oid_arc: Optional[str] = None,
    ):
        self.key_vault = key_vault
        self.store = store
        self.ca_key_id = ca_key_id
        self._ca_cert: Optional[x509.Certificate] = None

        # Resolve OID arc (per-instance) and derive the three agent OIDs.
        # When agent_id_oid_arc is None, fall back to the class-level
        # placeholder so existing call sites keep working unchanged.
        self.agent_id_oid_arc = agent_id_oid_arc or self.AGENT_ID_OID_ARC
        self.AGENT_ID_OID = x509.ObjectIdentifier(
            f"{self.agent_id_oid_arc}.1"
        )
        self.AGENT_PERMISSIONS_OID = x509.ObjectIdentifier(
            f"{self.agent_id_oid_arc}.2"
        )
        self.AGENT_OWNER_OID = x509.ObjectIdentifier(
            f"{self.agent_id_oid_arc}.3"
        )
    
    async def initialize(
        self,
        ca_common_name: str = "Agent Intermediate CA",
        ca_organization: str = "Enterprise Agent Platform",
        validity_days: int = 730  # 2 years
    ) -> x509.Certificate:
        """Initialize the CA with a self-signed certificate (for demo).
        
        In production, this would be signed by your root CA.
        """
        # Generate CA key pair
        public_key = await self.key_vault.generate_key_pair(
            self.ca_key_id,
            key_size=4096,
            metadata={"purpose": "ca_signing"}
        )
        
        private_key = await self.key_vault.get_private_key(self.ca_key_id)
        
        # Build CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_organization),
        ])
        
        now = datetime.now(timezone.utc)
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        self._ca_cert = cert
        return cert
    
    async def issue_agent_certificate(
        self,
        identity: AgentIdentity,
        validity_days: int = 90
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Issue a certificate for an agent."""
        if not self._ca_cert:
            raise RuntimeError("CA not initialized")
        
        # Generate agent's key pair
        agent_key_id = f"{identity.agent_id}/cert_key"
        public_key = await self.key_vault.generate_key_pair(
            agent_key_id,
            key_size=2048,
            metadata={"agent_id": identity.agent_id}
        )
        
        private_key = await self.key_vault.get_private_key(agent_key_id)
        ca_private_key = await self.key_vault.get_private_key(self.ca_key_id)
        
        # Build certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, identity.name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, identity.owner_team),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Agents"),
        ])
        
        now = datetime.now(timezone.utc)
        serial = x509.random_serial_number()
        
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False
            )
        )
        
        # Add custom agent extensions
        # Note: In production, use proper ASN.1 encoding for extensions
        agent_extensions = json.dumps({
            "agent_id": identity.agent_id,
            "permissions": [permission_value(p) for p in identity.permissions],
            "owner_team": identity.owner_team,
            "owner_email": identity.owner_email
        }).encode()
        
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                self.AGENT_ID_OID,
                agent_extensions
            ),
            critical=False
        )
        
        cert = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
        
        return cert, private_key
    
    async def verify_certificate(
        self,
        cert_pem: str
    ) -> tuple[bool, Optional[str], Optional[dict]]:
        """
        Verify a certificate.
        
        Returns:
            (is_valid, error_message, extracted_data)
        """
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(),
                default_backend()
            )
            
            # Check expiration
            now = datetime.now(timezone.utc)
            not_before, not_after = _certificate_validity_window_utc(cert)
            if now < not_before or now > not_after:
                return False, "Certificate expired or not yet valid", None
            
            # Check revocation
            serial_hex = format(cert.serial_number, 'x')
            if await self.store.is_cert_revoked(serial_hex):
                return False, "Certificate has been revoked", None
            
            # Verify signature (simplified - in production, verify full chain)
            if not self._ca_cert:
                return False, "CA not initialized or trusted CA not loaded", None
            if cert.issuer != self._ca_cert.subject:
                return False, "Certificate issuer does not match trusted CA", None
            try:
                self._ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            except InvalidSignature:
                logger.exception("Certificate signature invalid")
                return False, "Certificate signature verification failed", None
            except (ValueError, TypeError) as e:
                logger.exception("Certificate signature check failed: %s", e)
                return False, "Certificate signature verification failed", None

            # Extract agent data from extensions
            agent_data = None
            for ext in cert.extensions:
                if ext.oid == self.AGENT_ID_OID:
                    agent_data = json.loads(ext.value.value.decode())
                    break

            return True, None, agent_data

        except (ValueError, TypeError) as e:
            logger.exception("Certificate parsing failed: %s", e)
            return False, f"Parsing failed: {e!r}", None
        except Exception as e:  # noqa: BLE001 -- fail-safe boundary
            logger.exception("Unexpected certificate verification error")
            return False, f"Unexpected error: {e!r}", None
    
    async def revoke_certificate(
        self,
        cert_serial: str,
        expires_at: Optional[datetime] = None
    ) -> None:
        """Add certificate to revocation list."""
        await self.store.add_to_crl(cert_serial, expires_at=expires_at)

# ============================================================================
# Block 6 (chapter listing #6)
# ============================================================================

class AgentIdentityService:
    """
    Complete identity service for agent systems.
    
    Orchestrates:
    - Identity provisioning and lifecycle
    - Certificate management
    - Token issuance and validation
    - Human-agent delegation
    - Audit logging
    """
    
    def __init__(
        self,
        store: IdentityStore,
        key_vault: KeyVault,
        ca: CertificateAuthority,
        jwt_signing_key_id: str = "jwt_signing",
        token_ttl_hours: int = 24,
        delegation_ttl_hours: int = 8,
        last_used_update_interval: timedelta = timedelta(minutes=5)
    ):
        self.store = store
        self.key_vault = key_vault
        self.ca = ca
        self.jwt_signing_key_id = jwt_signing_key_id
        self.token_ttl_hours = token_ttl_hours
        self.delegation_ttl_hours = delegation_ttl_hours
        self.last_used_update_interval = last_used_update_interval
        self._credential_hash_secret: Optional[bytes] = None
        self._jwt_public_key: Optional[rsa.RSAPublicKey] = None
        # Audit reliability: bounded retry plus in-memory DLQ so a transient
        # store failure cannot abort the identity operation that triggered it.
        self._audit_max_retries: int = 3
        self._audit_dlq: deque[tuple[AuditEvent, Exception]] = deque(
            maxlen=1000
        )
        self._audit_dlq_evicted: int = 0
        self._audit_dlq_eviction_warned: bool = False

    @property
    def audit_dlq_size(self) -> int:
        """Number of audit events currently parked in the DLQ."""
        return len(self._audit_dlq)

    @property
    def audit_dlq_evicted_count(self) -> int:
        """Count of DLQ entries evicted due to maxlen overflow."""
        return self._audit_dlq_evicted

    async def initialize(self) -> None:
        """Initialize the identity service."""
        # JWTs are signed with the vault-backed RSA key below. This separate
        # secret only keys the credential-table HMAC so the table never stores
        # raw bearer tokens or bare SHA-256 hashes of them.
        environment = _current_environment()
        hash_secret = os.environ.get("TOKEN_HASH_SECRET")
        if not hash_secret:
            if _is_production_environment(environment):
                raise RuntimeError(
                    "TOKEN_HASH_SECRET must be set in production; a "
                    "per-process fallback would break credential hash "
                    "comparison across replicas."
                )
            hash_secret = secrets.token_urlsafe(32)
            warnings.warn(
                "Using generated local token hash secret (ENVIRONMENT="
                + environment
                + "). Set TOKEN_HASH_SECRET before going to production."
            )
        validated_hash_secret = _validate_token_hash_secret(
            hash_secret,
            environment
        )
        _validate_key_provider_environment(self.key_vault, environment)
        if (
            _is_production_environment(environment)
            and not getattr(self.store, "is_durable_production_store", False)
        ):
            raise RuntimeError(
                "Production identity service requires a durable identity store; "
                "the in-memory IdentityStore is for development and tests only."
            )
        self._credential_hash_secret = validated_hash_secret.encode("utf-8")

        # Initialize CA
        await self.ca.initialize()

        # Generate JWT signing key. The private key stays behind KeyVault;
        # services verify tokens with this public key (or a JWKS wrapper around
        # it in a multi-service deployment).
        self._jwt_public_key = await self.key_vault.generate_key_pair(
            self.jwt_signing_key_id,
            metadata={"purpose": "jwt_signing", "algorithm": "RS256"}
        )

    def _require_credential_hash_secret(self) -> bytes:
        """Return the HMAC key used for credential-table token hashes."""
        if self._credential_hash_secret is None:
            raise RuntimeError("AgentIdentityService.initialize() was not called")
        return self._credential_hash_secret

    async def _jwt_private_key(self) -> rsa.RSAPrivateKey:
        """Load the vault-held JWT signing key."""
        private_key = await self.key_vault.get_private_key(
            self.jwt_signing_key_id
        )
        if private_key is None:
            raise RuntimeError(
                f"JWT signing key not found: {self.jwt_signing_key_id}"
            )
        return private_key

    async def _jwt_verification_key(self) -> rsa.RSAPublicKey:
        """Return the public key used to verify service-issued JWTs."""
        if self._jwt_public_key is None:
            self._jwt_public_key = await self.key_vault.get_public_key(
                self.jwt_signing_key_id
            )
        if self._jwt_public_key is None:
            raise RuntimeError(
                f"JWT verification key not found: {self.jwt_signing_key_id}"
            )
        return self._jwt_public_key

    async def _encode_service_jwt(self, payload: dict) -> str:
        """Sign a service JWT with the vault-backed RS256 key."""
        return jwt.encode(
            payload,
            await self._jwt_private_key(),
            algorithm="RS256",
            headers={"kid": self.jwt_signing_key_id}
        )

    async def _decode_service_jwt(
        self,
        token: str,
        *,
        verify_exp: bool = True
    ) -> dict:
        """Decode a service JWT with the RS256 verification key."""
        return jwt.decode(
            token,
            await self._jwt_verification_key(),
            algorithms=["RS256"],
            audience="agent-platform",
            issuer="agent-identity-service",
            options={"verify_exp": verify_exp}
        )
    
    # -------------------------------------------------------
    # Identity Lifecycle
    # -------------------------------------------------------
    async def create_identity(
        self,
        name: str,
        description: str,
        owner_team: str,
        owner_email: str,
        permissions: list[Permission],
        validity_days: int = 90,
        metadata: Optional[dict] = None,
        actor: str = "system",
        correlation_id: Optional[str] = None
    ) -> tuple[AgentIdentity, str]:
        """
        Create a new agent identity.
        
        Returns:
            (identity, initial_token)
        """
        agent_id = f"agent_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        
        # Create identity record
        identity = AgentIdentity(
            agent_id=agent_id,
            name=name,
            description=description,
            owner_team=owner_team,
            owner_email=owner_email,
            permissions=permissions,
            status=IdentityStatus.PENDING,
            certificate_pem=None,
            certificate_serial=None,
            created_at=now,
            activated_at=None,
            expires_at=now + timedelta(days=validity_days),
            last_used_at=None,
            suspended_at=None,
            revoked_at=None,
            revocation_reason=None,
            metadata=metadata or {}
        )
        
        stored_identity = False
        cert_serial: Optional[str] = None
        try:
            # Stage the certificate before persisting the identity so a
            # certificate/key-generation failure cannot leave an unusable
            # PENDING row behind.
            cert, _ = await self.ca.issue_agent_certificate(
                identity,
                validity_days=validity_days
            )
            cert_serial = format(cert.serial_number, 'x')

            identity.certificate_pem = cert.public_bytes(
                serialization.Encoding.PEM
            ).decode()
            identity.certificate_serial = cert_serial
            identity.status = IdentityStatus.ACTIVE
            identity.activated_at = now

            await self.store.create_identity(identity)
            stored_identity = True

            # Issue initial token only after the active identity is durable.
            token = await self._issue_token(identity, actor)

            await self._audit(
                event_type=AuditEventType.IDENTITY_CREATED,
                agent_id=agent_id,
                actor_id=actor,
                actor_type="system" if actor == "system" else "human",
                resource_type="identity",
                resource_id=agent_id,
                action="create",
                outcome="success",
                details={
                    "name": name,
                    "owner_team": owner_team,
                    "permissions": [permission_value(p) for p in permissions],
                    "validity_days": validity_days
                },
                correlation_id=correlation_id
            )

            return identity, token
        except Exception:
            # Compensate any local signing material created before the failure.
            if cert_serial:
                with contextlib.suppress(Exception):
                    await self.ca.revoke_certificate(
                        cert_serial,
                        expires_at=identity.expires_at
                    )
            with contextlib.suppress(Exception):
                await self.key_vault.delete_key(f"{agent_id}/cert_key")

            if stored_identity:
                identity.status = IdentityStatus.SUSPENDED
                identity.suspended_at = datetime.now(timezone.utc)
                identity.revocation_reason = (
                    "identity provisioning failed before initial credential "
                    "activation completed"
                )
                identity.certificate_pem = None
                identity.certificate_serial = None
                with contextlib.suppress(Exception):
                    await self.store.update_identity(identity)
            raise
    
    async def get_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        """Retrieve an agent identity."""
        return await self.store.get_identity(agent_id)
    
    async def suspend_identity(
        self,
        agent_id: str,
        reason: str,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> AgentIdentity:
        """Temporarily suspend an agent identity."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if identity.status == IdentityStatus.REVOKED:
            raise ValueError("Cannot suspend revoked identity")
        
        identity.status = IdentityStatus.SUSPENDED
        identity.suspended_at = datetime.now(timezone.utc)
        
        await self.store.update_identity(identity)
        
        # Revoke all active credentials
        await self._revoke_all_credentials(agent_id, actor)
        
        await self._audit(
            event_type=AuditEventType.IDENTITY_SUSPENDED,
            agent_id=agent_id,
            actor_id=actor,
            actor_type="human",
            resource_type="identity",
            resource_id=agent_id,
            action="suspend",
            outcome="success",
            details={"reason": reason},
            correlation_id=correlation_id
        )
        
        return identity
    
    async def reactivate_identity(
        self,
        agent_id: str,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> AgentIdentity:
        """Reactivate a suspended identity."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if identity.status != IdentityStatus.SUSPENDED:
            raise ValueError(f"Identity is not suspended: {identity.status.value}")
        
        identity.status = IdentityStatus.ACTIVE
        identity.suspended_at = None
        
        await self.store.update_identity(identity)
        
        await self._audit(
            event_type=AuditEventType.IDENTITY_ACTIVATED,
            agent_id=agent_id,
            actor_id=actor,
            actor_type="human",
            resource_type="identity",
            resource_id=agent_id,
            action="reactivate",
            outcome="success",
            details={},
            correlation_id=correlation_id
        )
        
        return identity
    
    async def revoke_identity(
        self,
        agent_id: str,
        reason: str,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> AgentIdentity:
        """Permanently revoke an agent identity."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        now = datetime.now(timezone.utc)
        identity.status = IdentityStatus.REVOKED
        identity.revoked_at = now
        identity.revocation_reason = reason
        
        await self.store.update_identity(identity)
        
        # Revoke certificate
        if identity.certificate_serial:
            await self.ca.revoke_certificate(
                identity.certificate_serial,
                expires_at=identity.expires_at
            )
        
        # Revoke all credentials
        await self._revoke_all_credentials(agent_id, actor)
        
        # Delete private key
        await self.key_vault.delete_key(f"{agent_id}/cert_key")
        
        await self._audit(
            event_type=AuditEventType.IDENTITY_REVOKED,
            agent_id=agent_id,
            actor_id=actor,
            actor_type="human",
            resource_type="identity",
            resource_id=agent_id,
            action="revoke",
            outcome="success",
            details={"reason": reason},
            correlation_id=correlation_id
        )
        
        return identity
    
    # -------------------------------------------------------
    # Token Management
    # -------------------------------------------------------
    async def issue_token(
        self,
        agent_id: str,
        scopes: Optional[list[Permission]] = None,
        ttl_hours: Optional[int] = None,
        actor: str = "system",
        correlation_id: Optional[str] = None
    ) -> str:
        """Issue a new authentication token for an agent."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if not identity.is_valid():
            raise ValueError(f"Identity is not valid: {identity.status.value}")
        
        # Validate requested scopes
        effective_scopes = scopes or identity.permissions
        for scope in effective_scopes:
            if not identity.has_permission(scope):
                raise PermissionError(
                    f"Agent does not have permission: {permission_value(scope)}"
                )
        
        token = await self._issue_token(
            identity,
            actor,
            effective_scopes,
            ttl_hours or self.token_ttl_hours
        )
        
        return token
    
    async def _issue_token(
        self,
        identity: AgentIdentity,
        actor: str,
        scopes: Optional[list[Permission]] = None,
        ttl_hours: Optional[int] = None
    ) -> str:
        """Internal token issuance."""
        now = datetime.now(timezone.utc)
        ttl = ttl_hours or self.token_ttl_hours
        expires_at = now + timedelta(hours=ttl)
        
        token_id = str(uuid.uuid4())
        
        payload = {
            "sub": identity.agent_id,
            "name": identity.name,
            "owner": identity.owner_team,
            "scopes": [permission_value(s) for s in (scopes or identity.permissions)],
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": token_id,
            "iss": "agent-identity-service",
            "aud": "agent-platform"
        }
        
        # Agent-issued JWTs are signed with the vault-backed RS256 key.
        # Verifiers need only the public key, which can be distributed through
        # JWKS in a multi-service deployment.
        token = await self._encode_service_jwt(payload)

        # Store credential record. Use HMAC instead of a bare SHA-256 so that a
        # leak of the credential table alone does not let an attacker
        # precompute hashes of stolen tokens.
        credential = Credential(
            credential_id=token_id,
            agent_id=identity.agent_id,
            credential_type="jwt",
            token_hash=hmac.new(
                self._require_credential_hash_secret(),
                token.encode(),
                hashlib.sha256,
            ).hexdigest(),
            scopes=[permission_value(s) for s in (scopes or identity.permissions)],
            issued_at=now,
            expires_at=expires_at,
            issued_by=actor
        )
        await self.store.store_credential(credential)
        
        await self._audit(
            event_type=AuditEventType.TOKEN_ISSUED,
            agent_id=identity.agent_id,
            actor_id=actor,
            actor_type="system" if actor == "system" else "human",
            resource_type="credential",
            resource_id=token_id,
            action="issue",
            outcome="success",
            details={
                "scopes": [permission_value(s) for s in (scopes or identity.permissions)],
                "ttl_hours": ttl
            }
        )
        
        return token
    
    async def validate_token(
        self,
        token: str,
        required_scope: Optional[Permission] = None
    ) -> dict:
        """
        Validate an authentication token.
        
        Returns the decoded payload if valid.
        Raises ValueError if invalid.
        """
        try:
            payload = await self._decode_service_jwt(token)
        except jwt.ExpiredSignatureError:
            await self._audit(
                event_type=AuditEventType.TOKEN_REJECTED,
                agent_id=None,
                actor_id="unknown",
                actor_type="agent",
                resource_type="token",
                resource_id="unknown",
                action="validate",
                outcome="failure",
                details={"reason": "expired"}
            )
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            await self._audit(
                event_type=AuditEventType.TOKEN_REJECTED,
                agent_id=None,
                actor_id="unknown",
                actor_type="agent",
                resource_type="token",
                resource_id="unknown",
                action="validate",
                outcome="failure",
                details={"reason": str(e)}
            )
            raise ValueError(f"Invalid token: {e}") from e
        
        # Check credential not revoked
        credential = await self.store.get_credential(payload["jti"])
        if not credential or credential.is_revoked:
            await self._audit(
                event_type=AuditEventType.TOKEN_REJECTED,
                agent_id=payload.get("sub"),
                actor_id=payload.get("sub", "unknown"),
                actor_type="agent",
                resource_type="token",
                resource_id=payload.get("jti", "unknown"),
                action="validate",
                outcome="failure",
                details={"reason": "credential_revoked"}
            )
            raise ValueError("Credential has been revoked")
        
        # Check identity still valid
        identity = await self.store.get_identity(payload["sub"])
        if not identity or not identity.is_valid():
            await self._audit(
                event_type=AuditEventType.TOKEN_REJECTED,
                agent_id=payload["sub"],
                actor_id=payload["sub"],
                actor_type="agent",
                resource_type="token",
                resource_id=payload["jti"],
                action="validate",
                outcome="failure",
                details={"reason": "identity_invalid"}
            )
            raise ValueError("Agent identity is no longer valid")
        
        # Check required scope
        if required_scope:
            token_scopes = set(payload["scopes"])
            required_scope_value = permission_value(required_scope)
            if required_scope_value not in token_scopes:
                if permission_value(PermissionScope.ADMIN_FULL) not in token_scopes:
                    await self._audit(
                        event_type=AuditEventType.TOKEN_REJECTED,
                        agent_id=payload["sub"],
                        actor_id=payload["sub"],
                        actor_type="agent",
                        resource_type="token",
                        resource_id=payload["jti"],
                        action="validate",
                        outcome="denied",
                        details={
                            "reason": "insufficient_scope",
                            "required": required_scope_value,
                            "available": payload["scopes"]
                        }
                    )
                    raise PermissionError(
                        f"Token does not have required scope: {required_scope_value}"
                    )
        
        # Record coarse activity without turning every token validation into
        # a persisted identity-row write.
        last_used_persisted = await self.store.record_identity_activity(
            payload["sub"],
            datetime.now(timezone.utc),
            self.last_used_update_interval
        )
        
        await self._audit(
            event_type=AuditEventType.TOKEN_VALIDATED,
            agent_id=payload["sub"],
            actor_id=payload["sub"],
            actor_type="agent",
            resource_type="token",
            resource_id=payload["jti"],
            action="validate",
            outcome="success",
            details={"last_used_at_persisted": last_used_persisted}
        )
        
        return payload
    
    async def revoke_token(
        self,
        credential_id: str,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> None:
        """Revoke a specific token."""
        credential = await self.store.get_credential(credential_id)
        if not credential:
            raise ValueError(f"Credential not found: {credential_id}")
        
        credential.is_revoked = True
        credential.revoked_at = datetime.now(timezone.utc)
        credential.revoked_by = actor
        
        await self.store.store_credential(credential)
        
        await self._audit(
            event_type=AuditEventType.TOKEN_REVOKED,
            agent_id=credential.agent_id,
            actor_id=actor,
            actor_type="human",
            resource_type="credential",
            resource_id=credential_id,
            action="revoke",
            outcome="success",
            details={},
            correlation_id=correlation_id
        )
    
    async def _revoke_all_credentials(
        self,
        agent_id: str,
        actor: str,
        exclude_credential_ids: Optional[set[str]] = None
    ) -> int:
        """Revoke all credentials for an agent."""
        exclude_credential_ids = exclude_credential_ids or set()
        credentials = await self.store.get_credentials_for_agent(agent_id)
        count = 0
        
        for cred in credentials:
            if cred.credential_id in exclude_credential_ids:
                continue
            if not cred.is_revoked:
                cred.is_revoked = True
                cred.revoked_at = datetime.now(timezone.utc)
                cred.revoked_by = actor
                await self.store.store_credential(cred)
                count += 1
        
        return count
    
    # -------------------------------------------------------
    # Key Rotation
    # -------------------------------------------------------
    async def rotate_agent_credentials(
        self,
        agent_id: str,
        actor: str,
        correlation_id: Optional[str] = None,
        allow_suspended: bool = False
    ) -> str:
        """
        Rotate all credentials for an agent.
        
        This:
        1. Revokes all existing tokens
        2. Issues a new certificate
        3. Issues a new token

        Emergency workflows may set allow_suspended=True after suspending the
        identity. The new credential is issued but remains unusable until the
        identity is manually reactivated because validate_token still checks
        the identity lifecycle state.
        
        Returns the new token.
        """
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if not identity.is_valid():
            suspended_emergency = (
                allow_suspended
                and identity.status == IdentityStatus.SUSPENDED
                and datetime.now(timezone.utc) <= identity.expires_at
            )
            if not suspended_emergency:
                raise ValueError(f"Identity is not valid: {identity.status.value}")
        
        old_serial = identity.certificate_serial
        new_identity = replace(identity)
        new_cert_serial: Optional[str] = None

        try:
            # Stage and persist replacement certificate before touching old
            # credentials. If anything fails before the new token is durable,
            # existing tokens remain valid and the agent is not stranded.
            cert, _ = await self.ca.issue_agent_certificate(new_identity)
            new_cert_serial = format(cert.serial_number, 'x')

            new_identity.certificate_pem = cert.public_bytes(
                serialization.Encoding.PEM
            ).decode()
            new_identity.certificate_serial = new_cert_serial

            await self.store.update_identity(new_identity)

            new_token = await self._issue_token(new_identity, actor)
            new_payload = await self._decode_service_jwt(new_token)
            new_credential_id = new_payload["jti"]
        except Exception:
            if new_cert_serial:
                with contextlib.suppress(Exception):
                    await self.ca.revoke_certificate(
                        new_cert_serial,
                        expires_at=identity.expires_at
                    )
            with contextlib.suppress(Exception):
                await self.key_vault.delete_key(f"{agent_id}/cert_key")
            with contextlib.suppress(Exception):
                await self.store.update_identity(identity)
            raise

        # Revoke old credentials only after the replacement token exists.
        revoked_count = await self._revoke_all_credentials(
            agent_id,
            actor,
            exclude_credential_ids={new_credential_id}
        )

        # Revoke old certificate
        if old_serial:
            await self.ca.revoke_certificate(
                old_serial,
                expires_at=new_identity.expires_at
            )
        
        await self._audit(
            event_type=AuditEventType.KEY_ROTATED,
            agent_id=agent_id,
            actor_id=actor,
            actor_type="human" if actor != "system" else "system",
            resource_type="credentials",
            resource_id=agent_id,
            action="rotate",
            outcome="success",
            details={
                "credentials_revoked": revoked_count,
                "old_cert_serial": old_serial,
                "new_cert_serial": new_identity.certificate_serial,
                "allow_suspended": allow_suspended
            },
            correlation_id=correlation_id
        )
        
        return new_token
    
    # -------------------------------------------------------
    # Human-Agent Delegation
    # -------------------------------------------------------
    async def _audit_delegation_rejection(
        self,
        *,
        agent_id: Optional[str],
        actor_id: str,
        actor_type: str,
        resource_id: str,
        action: str,
        reason: str,
        details: Optional[dict] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """Audit a denied delegation create or validate request."""
        await self._audit(
            event_type=AuditEventType.DELEGATION_REJECTED,
            agent_id=agent_id,
            actor_id=actor_id,
            actor_type=actor_type,
            resource_type="delegation",
            resource_id=resource_id,
            action=action,
            outcome="denied",
            details={
                "reason": reason,
                **(details or {})
            },
            correlation_id=correlation_id
        )

    async def _decode_delegation_without_expiry(
        self,
        delegation_token: str
    ) -> dict:
        """Best-effort decode of an otherwise valid expired delegation JWT."""
        try:
            return await self._decode_service_jwt(
                delegation_token,
                verify_exp=False
            )
        except jwt.InvalidTokenError:
            return {}

    async def create_delegation(
        self,
        human_oidc_token: dict,  # Decoded OIDC token
        agent_id: str,
        scopes: list[Permission],
        constraints: Optional[dict] = None,
        ttl_hours: Optional[int] = None,
        max_uses: Optional[int] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Create a delegation from a human to an agent.
        
        The human's OIDC token must contain:
        - sub: unique subject identifier
        - email: email address
        - name: display name
        
        Returns a delegation token the agent can use.
        """
        human_subject = human_oidc_token.get("sub")
        human_email = human_oidc_token.get("email", "unknown")
        requested_scopes = [permission_value(scope) for scope in scopes]

        if not human_subject:
            await self._audit_delegation_rejection(
                agent_id=agent_id,
                actor_id="unknown",
                actor_type="human",
                resource_id="pending",
                action="create",
                reason="missing_human_subject",
                details={
                    "human_email": human_email,
                    "requested_scopes": requested_scopes
                },
                correlation_id=correlation_id
            )
            raise ValueError("Human OIDC token missing required sub claim")

        if not requested_scopes:
            await self._audit_delegation_rejection(
                agent_id=agent_id,
                actor_id=human_subject,
                actor_type="human",
                resource_id="pending",
                action="create",
                reason="empty_scope_request",
                details={"human_email": human_email},
                correlation_id=correlation_id
            )
            raise ValueError("Delegation must include at least one scope")

        # Validate agent exists and is active
        identity = await self.store.get_identity(agent_id)
        if not identity or not identity.is_valid():
            await self._audit_delegation_rejection(
                agent_id=agent_id,
                actor_id=human_subject,
                actor_type="human",
                resource_id="pending",
                action="create",
                reason="agent_invalid",
                details={
                    "human_email": human_email,
                    "requested_scopes": requested_scopes
                },
                correlation_id=correlation_id
            )
            raise ValueError(f"Agent not valid for delegation: {agent_id}")

        allowed_scopes = _delegable_scope_claims(human_oidc_token)
        unauthorized_scopes = [
            scope for scope in requested_scopes
            if not _scope_allowed_by_claims(scope, allowed_scopes)
        ]
        if unauthorized_scopes:
            await self._audit_delegation_rejection(
                agent_id=agent_id,
                actor_id=human_subject,
                actor_type="human",
                resource_id="pending",
                action="create",
                reason="human_scope_not_delegable",
                details={
                    "human_email": human_email,
                    "requested_scopes": requested_scopes,
                    "allowed_scopes": sorted(allowed_scopes),
                    "missing_scopes": unauthorized_scopes,
                    "policy": "requested scopes must appear in delegable OIDC claims"
                },
                correlation_id=correlation_id
            )
            raise PermissionError(
                "Human is not authorized to delegate scope(s): "
                + ", ".join(unauthorized_scopes)
            )

        agent_missing_scopes = [
            scope for scope in requested_scopes
            if not identity.has_permission(scope)
        ]
        if agent_missing_scopes:
            await self._audit_delegation_rejection(
                agent_id=agent_id,
                actor_id=human_subject,
                actor_type="human",
                resource_id="pending",
                action="create",
                reason="agent_scope_not_permitted",
                details={
                    "human_email": human_email,
                    "requested_scopes": requested_scopes,
                    "missing_scopes": agent_missing_scopes,
                    "agent_permissions": [
                        permission_value(permission)
                        for permission in identity.permissions
                    ]
                },
                correlation_id=correlation_id
            )
            raise PermissionError(
                "Agent identity does not permit delegated scope(s): "
                + ", ".join(agent_missing_scopes)
            )
        
        now = datetime.now(timezone.utc)
        ttl = ttl_hours or self.delegation_ttl_hours
        expires_at = now + timedelta(hours=ttl)
        
        delegation_id = str(uuid.uuid4())
        
        # Create delegation record
        delegation = DelegationRecord(
            delegation_id=delegation_id,
            human_subject=human_subject,
            human_email=human_email,
            human_name=human_oidc_token.get("name", "Unknown"),
            agent_id=agent_id,
            delegated_scopes=requested_scopes,
            constraints=constraints or {},
            created_at=now,
            expires_at=expires_at,
            max_uses=max_uses
        )
        
        await self.store.store_delegation(delegation)
        
        # Create delegation token with the same vault-backed RS256 signer used
        # for agent tokens.
        payload = {
            "type": "delegation",
            "del_id": delegation_id,
            "human_sub": human_subject,
            "human_email": human_email,
            "agent_id": agent_id,
            "scopes": requested_scopes,
            "constraints": constraints or {},
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": "agent-identity-service",
            "aud": "agent-platform"
        }
        
        delegation_token = await self._encode_service_jwt(payload)
        
        await self._audit(
            event_type=AuditEventType.DELEGATION_CREATED,
            agent_id=agent_id,
            actor_id=human_subject,
            actor_type="human",
            resource_type="delegation",
            resource_id=delegation_id,
            action="create",
            outcome="success",
            details={
                "human_email": human_email,
                "scopes": requested_scopes,
                "ttl_hours": ttl,
                "max_uses": max_uses
            },
            correlation_id=correlation_id
        )
        
        return delegation_token
    
    async def validate_delegation(
        self,
        delegation_token: str,
        required_scope: Optional[Permission] = None
    ) -> dict:
        """Validate a delegation token."""
        payload: dict = {}
        try:
            payload = await self._decode_service_jwt(delegation_token)
        except jwt.ExpiredSignatureError as e:
            payload = await self._decode_delegation_without_expiry(
                delegation_token
            )
            await self._audit_delegation_rejection(
                agent_id=payload.get("agent_id"),
                actor_id=payload.get("agent_id", "unknown"),
                actor_type="agent",
                resource_id=payload.get("del_id", "unknown"),
                action="validate",
                reason="expired",
                details={
                    "human_sub": payload.get("human_sub"),
                    "required_scope": (
                        permission_value(required_scope)
                        if required_scope else None
                    )
                }
            )
            raise ValueError("Delegation has expired") from e
        except jwt.InvalidTokenError as e:
            await self._audit_delegation_rejection(
                agent_id=None,
                actor_id="unknown",
                actor_type="agent",
                resource_id="unknown",
                action="validate",
                reason="invalid",
                details={"error": str(e)}
            )
            raise ValueError(f"Invalid delegation: {e}") from e
        
        if payload.get("type") != "delegation":
            await self._audit_delegation_rejection(
                agent_id=payload.get("agent_id"),
                actor_id=payload.get("agent_id", "unknown"),
                actor_type="agent",
                resource_id=payload.get("del_id", "unknown"),
                action="validate",
                reason="invalid",
                details={"token_type": payload.get("type")}
            )
            raise ValueError("Not a delegation token")

        delegation_id = payload.get("del_id")
        if not delegation_id:
            await self._audit_delegation_rejection(
                agent_id=payload.get("agent_id"),
                actor_id=payload.get("agent_id", "unknown"),
                actor_type="agent",
                resource_id="unknown",
                action="validate",
                reason="invalid",
                details={"missing_claim": "del_id"}
            )
            raise ValueError("Delegation token missing delegation id")
        
        # Check delegation record
        delegation = await self.store.get_delegation(delegation_id)
        if not delegation:
            await self._audit_delegation_rejection(
                agent_id=payload.get("agent_id"),
                actor_id=payload.get("agent_id", "unknown"),
                actor_type="agent",
                resource_id=delegation_id,
                action="validate",
                reason="missing",
                details={"human_sub": payload.get("human_sub")}
            )
            raise ValueError("Delegation record not found")
        
        if delegation.is_revoked:
            await self._audit_delegation_rejection(
                agent_id=delegation.agent_id,
                actor_id=payload.get("agent_id", delegation.agent_id),
                actor_type="agent",
                resource_id=delegation_id,
                action="validate",
                reason="revoked",
                details={"human_sub": delegation.human_subject}
            )
            raise ValueError("Delegation has been revoked")

        if datetime.now(timezone.utc) > delegation.expires_at:
            await self._audit_delegation_rejection(
                agent_id=delegation.agent_id,
                actor_id=payload.get("agent_id", delegation.agent_id),
                actor_type="agent",
                resource_id=delegation_id,
                action="validate",
                reason="expired",
                details={"human_sub": delegation.human_subject}
            )
            raise ValueError("Delegation has expired")
        
        # Check required scope
        if required_scope:
            required_scope_value = permission_value(required_scope)
            token_scopes = set(payload.get("scopes") or [])
            record_scopes = set(delegation.delegated_scopes)
            effective_scopes = token_scopes.intersection(record_scopes)
            has_required_scope = (
                required_scope_value in effective_scopes
                or permission_value(PermissionScope.ADMIN_FULL) in effective_scopes
            )
        else:
            required_scope_value = None
            effective_scopes = set(payload.get("scopes") or []).intersection(
                delegation.delegated_scopes
            )
            has_required_scope = True

        if not has_required_scope:
            await self._audit_delegation_rejection(
                agent_id=delegation.agent_id,
                actor_id=payload.get("agent_id", delegation.agent_id),
                actor_type="agent",
                resource_id=delegation_id,
                action="validate",
                reason="insufficient_scope",
                details={
                    "human_sub": delegation.human_subject,
                    "required": required_scope_value,
                    "available": sorted(effective_scopes)
                }
            )
            raise PermissionError(
                f"Delegation does not include scope: {required_scope_value}"
            )
        
        # Atomically increment use count only after scope validation passes.
        try:
            delegation = await self.store.consume_delegation_use(delegation_id)
        except ValueError as e:
            message = str(e)
            if "revoked" in message:
                reason = "revoked"
            elif "expired" in message:
                reason = "expired"
            elif "maximum uses" in message:
                reason = "max_uses_exceeded"
            else:
                reason = "missing"
            await self._audit_delegation_rejection(
                agent_id=payload.get("agent_id"),
                actor_id=payload.get("agent_id", "unknown"),
                actor_type="agent",
                resource_id=delegation_id,
                action="validate",
                reason=reason,
                details={"human_sub": payload.get("human_sub")}
            )
            raise
        
        await self._audit(
            event_type=AuditEventType.DELEGATION_USED,
            agent_id=payload["agent_id"],
            actor_id=payload["agent_id"],
            actor_type="agent",
            resource_type="delegation",
            resource_id=payload["del_id"],
            action="use",
            outcome="success",
            details={
                "human_sub": payload["human_sub"],
                "use_count": delegation.used_count
            }
        )
        
        return payload
    
    # -------------------------------------------------------
    # Permission Management
    # -------------------------------------------------------
    async def grant_permission(
        self,
        agent_id: str,
        permission: Permission,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> AgentIdentity:
        """Grant additional permission to an agent."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if not identity.has_permission(permission):
            identity.permissions.append(permission)
            await self.store.update_identity(identity)
            
            await self._audit(
                event_type=AuditEventType.PERMISSION_GRANTED,
                agent_id=agent_id,
                actor_id=actor,
                actor_type="human",
                resource_type="permission",
                resource_id=permission_value(permission),
                action="grant",
                outcome="success",
                details={"permission": permission_value(permission)},
                correlation_id=correlation_id
            )
        
        return identity
    
    async def revoke_permission(
        self,
        agent_id: str,
        permission: Permission,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> AgentIdentity:
        """Revoke a permission from an agent."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        permission_to_remove = next(
            (
                existing for existing in identity.permissions
                if permission_value(existing) == permission_value(permission)
            ),
            None
        )
        if permission_to_remove is not None:
            identity.permissions.remove(permission_to_remove)
            await self.store.update_identity(identity)
            
            await self._audit(
                event_type=AuditEventType.PERMISSION_REVOKED,
                agent_id=agent_id,
                actor_id=actor,
                actor_type="human",
                resource_type="permission",
                resource_id=permission_value(permission),
                action="revoke",
                outcome="success",
                details={"permission": permission_value(permission)},
                correlation_id=correlation_id
            )
        
        return identity
    
    # -------------------------------------------------------
    # Audit
    # -------------------------------------------------------
    async def _audit(
        self,
        event_type: AuditEventType,
        agent_id: Optional[str],
        actor_id: str,
        actor_type: str,
        resource_type: str,
        resource_id: str,
        action: str,
        outcome: str,
        details: dict,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """Record an audit event."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            agent_id=agent_id,
            actor_id=actor_id,
            actor_type=actor_type,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            outcome=outcome,
            details=details,
            client_ip=client_ip,
            user_agent=user_agent,
            correlation_id=correlation_id
        )
        # Bounded retry plus DLQ. Audit failure must not abort the operation
        # that produced it; we surface the loss to operators via a critical
        # log and an in-memory dead-letter queue they can drain.
        for attempt in range(self._audit_max_retries):
            try:
                await self.store.log_audit_event(event)
                return
            except Exception as exc:
                if attempt == self._audit_max_retries - 1:
                    if len(self._audit_dlq) >= (self._audit_dlq.maxlen or 0):
                        self._audit_dlq_evicted += 1
                        if not self._audit_dlq_eviction_warned:
                            logger.warning(
                                "audit DLQ at capacity (maxlen=%d); oldest "
                                "entries are being evicted. Investigate "
                                "audit pipeline health.",
                                self._audit_dlq.maxlen,
                            )
                            self._audit_dlq_eviction_warned = True
                    self._audit_dlq.append((event, exc))
                    logger.critical(
                        "Audit event failed after %d retries; pushed to "
                        "DLQ. Operator action required.",
                        self._audit_max_retries,
                        exc_info=exc,
                    )
                else:
                    # Full jitter on exponential backoff: synchronized
                    # transient failures (e.g., audit store outage) would
                    # otherwise produce a thundering-herd retry storm.
                    # Base scaled to ride out typical 1-2s audit-store
                    # blips: 0.25s, 0.5s, 1.0s (capped at 2.0s). Worst-case
                    # total across 3 attempts is ~3.5s with jitter, which
                    # stays acceptable for an inline audit hop.
                    base = 0.25 * (2 ** attempt)
                    backoff = min(2.0, base)
                    await asyncio.sleep(random.uniform(0, backoff))

    async def get_audit_log(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: Optional[int] = None
    ) -> list[AuditEvent]:
        """Query the audit log."""
        return await self.store.query_audit_log(
            agent_id=agent_id,
            event_type=event_type,
            actor_id=actor_id,
            since=since,
            until=until,
            limit=limit,
            offset=offset
        )



class AgentAuthenticator:
    """
    Middleware for authenticating agent requests.
    
    Use in API endpoints to validate identity before processing.
    """
    
    def __init__(self, identity_service: AgentIdentityService):
        self.identity_service = identity_service
    
    async def authenticate(self, token: str) -> AgentIdentity:
        """
        Authenticate a request.
        
        Returns the agent's identity if valid.
        Raises ValueError if authentication fails.
        """
        payload = await self.identity_service.validate_token(token)
        identity = await self.identity_service.get_identity(payload["sub"])
        if not identity:
            raise ValueError("Agent identity not found")
        return identity
    
    async def authorize(
        self,
        token: str,
        required_scope: Permission
    ) -> AgentIdentity:
        """
        Authenticate and authorize for a specific scope.
        
        Returns identity if authorized.
        Raises PermissionError if scope not present.
        """
        payload = await self.identity_service.validate_token(
            token,
            required_scope=required_scope
        )
        identity = await self.identity_service.get_identity(payload["sub"])
        if not identity:
            raise ValueError("Agent identity not found")
        return identity
    
    async def authenticate_with_delegation(
        self,
        agent_token: str,
        delegation_token: str,
        required_scope: Optional[Permission] = None
    ) -> tuple[AgentIdentity, dict]:
        """
        Authenticate agent and validate human delegation.
        
        Returns (agent_identity, delegation_payload).
        """
        # First authenticate the agent
        identity = await self.authenticate(agent_token)
        
        # Then validate the delegation
        delegation = await self.identity_service.validate_delegation(
            delegation_token,
            required_scope=required_scope
        )
        
        # Verify delegation is for this agent
        if delegation["agent_id"] != identity.agent_id:
            raise PermissionError("Delegation is for a different agent")
        
        return identity, delegation



async def main():
    """Demonstrate the identity service.

    Sets ENVIRONMENT=development and AGENT_ENV=development if not already
    set so the production trip-wires (in-memory KeyVault refusal, empty
    INTERNAL_NETWORK abort) do not fire in this pedagogical context.
    Real deployments must set ENVIRONMENT/AGENT_ENV explicitly via the
    deployment configuration so production behavior is the default and
    the development overrides are never silently inherited.
    """
    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ.setdefault("AGENT_ENV", "development")

    print("=" * 70)
    print("Enterprise Agent Identity Service - Demo")
    print("=" * 70)

    # Initialize components
    store = IdentityStore()
    key_vault = KeyVault()
    ca = CertificateAuthority(key_vault, store)
    
    service = AgentIdentityService(store, key_vault, ca)
    await service.initialize()
    
    auth = AgentAuthenticator(service)
    
    # 1. Create an agent identity
    print("\n1. Creating agent identity...")
    identity, token = await service.create_identity(
        name="procurement-agent",
        description="Handles purchase order processing",
        owner_team="supply-chain",
        owner_email="supply-chain@example.com",
        permissions=[
            PermissionScope.DATA_READ,
            PermissionScope.DATA_WRITE,
            PermissionScope.TOOLS_INVOKE
        ],
        metadata={"environment": "production", "version": "1.0"}
    )
    print(f"   Agent ID: {identity.agent_id}")
    print(f"   Status: {identity.status.value}")
    print(f"   Certificate serial: {identity.certificate_serial}")
    
    # 2. Authenticate with token
    print("\n2. Authenticating with token...")
    validated_identity = await auth.authenticate(token)
    print(f"   Authenticated: {validated_identity.name}")
    
    # 3. Authorize for specific scope
    print("\n3. Authorizing for scopes...")
    try:
        await auth.authorize(token, PermissionScope.DATA_READ)
        print("   Authorized for data:read")
    except PermissionError as e:
        print(f"   Denied: {e}")
    
    try:
        await auth.authorize(token, PermissionScope.SECRETS_READ)
        print("   Authorized for secrets:read")
    except PermissionError as e:
        print(f"   Denied: {e}")
    
    # 4. Grant additional permission
    print("\n4. Granting secrets:read permission...")
    identity = await service.grant_permission(
        identity.agent_id,
        PermissionScope.SECRETS_READ,
        actor="admin@example.com"
    )
    print(f"   Permissions: {[permission_value(p) for p in identity.permissions]}")
    
    # 5. Create human delegation
    print("\n5. Creating human-to-agent delegation...")
    mock_oidc_token = {
        "sub": "user_12345",
        "email": "alice@example.com",
        "name": "Alice Smith",
        "delegable_scopes": [PermissionScope.DATA_WRITE.value]
    }
    delegation_token = await service.create_delegation(
        human_oidc_token=mock_oidc_token,
        agent_id=identity.agent_id,
        scopes=[PermissionScope.DATA_WRITE],
        constraints={"max_amount": 10000},
        max_uses=5
    )
    print(f"   Delegation created for: {mock_oidc_token['email']}")
    
    # 6. Use delegation
    print("\n6. Agent using delegation...")
    _, delegation_payload = await auth.authenticate_with_delegation(
        token,
        delegation_token
    )
    print(f"   Acting on behalf of: {delegation_payload['human_email']}")
    print(f"   Delegated scopes: {delegation_payload['scopes']}")
    
    # 7. Rotate credentials
    print("\n7. Rotating credentials...")
    new_token = await service.rotate_agent_credentials(
        identity.agent_id,
        actor="security-rotation@example.com"
    )
    print("   Credentials rotated")
    
    # Verify old token is invalid
    try:
        await auth.authenticate(token)
        print("   Old token still valid (unexpected!)")
    except ValueError as e:
        print(f"   Old token rejected: {e}")
    
    # 8. Query audit log
    print("\n8. Audit Log (last 10 events):")
    events = await service.get_audit_log(agent_id=identity.agent_id, limit=10)
    for event in events:
        print(f"   [{event.timestamp.isoformat()[:19]}] "
              f"{event.event_type.value} - {event.outcome}")
    
    # 9. Suspend and reactivate
    print("\n9. Suspend and reactivate...")
    await service.suspend_identity(
        identity.agent_id,
        reason="Scheduled maintenance",
        actor="admin@example.com"
    )
    print("   Identity suspended")
    
    identity = await service.reactivate_identity(
        identity.agent_id,
        actor="admin@example.com"
    )
    print(f"   Identity reactivated: {identity.status.value}")
    
    # 10. Final statistics
    print("\n10. Final Statistics:")
    all_events = await service.get_audit_log(limit=1000)
    print(f"    Total audit events: {len(all_events)}")
    print(f"    Identity status: {identity.status.value}")
    print(f"    Last used: {identity.last_used_at}")


if __name__ == "__main__":
    asyncio.run(main())

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

class ScheduledRotation:
    """Rotate credentials on a schedule."""
    
    def __init__(
        self,
        identity_service: AgentIdentityService,
        rotation_interval_days: int = 30
    ):
        self.identity_service = identity_service
        self.rotation_interval = timedelta(days=rotation_interval_days)
    
    async def check_and_rotate(self) -> list[str]:
        """Check all identities and rotate those due."""
        rotated = []
        page_size = 100
        offset = 0
        now = datetime.now(timezone.utc)

        while True:
            identities = await self.identity_service.store.list_identities(
                status=IdentityStatus.ACTIVE,
                limit=page_size,
                offset=offset
            )
            if not identities:
                break

            for identity in identities:
                # Check certificate age
                if identity.activated_at:
                    cert_age = now - identity.activated_at
                    if cert_age > self.rotation_interval:
                        await self.identity_service.rotate_agent_credentials(
                            identity.agent_id,
                            actor="scheduled-rotation"
                        )
                        rotated.append(identity.agent_id)

            if len(identities) < page_size:
                break
            offset += page_size
        
        return rotated

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

class EmergencyRotation:
    """Handle emergency credential rotation."""
    
    def __init__(self, identity_service: AgentIdentityService):
        self.identity_service = identity_service
    
    async def rotate_compromised(
        self,
        agent_id: str,
        incident_id: str,
        actor: str
    ) -> str:
        """
        Emergency rotation for potentially compromised agent.
        
        This:
        1. Immediately suspends the agent and revokes current credentials
        2. Rotates credentials through an explicit emergency path
        3. Keeps the new credential unusable until manual reactivation
        """
        # Suspend immediately
        await self.identity_service.suspend_identity(
            agent_id,
            reason=f"Emergency rotation - incident {incident_id}",
            actor=actor,
            correlation_id=incident_id
        )
        
        # Rotate credentials
        new_token = await self.identity_service.rotate_agent_credentials(
            agent_id,
            actor=actor,
            correlation_id=incident_id,
            allow_suspended=True
        )
        
        # Log for incident response
        await self.identity_service._audit(
            event_type=AuditEventType.KEY_COMPROMISED,
            agent_id=agent_id,
            actor_id=actor,
            actor_type="human",
            resource_type="credentials",
            resource_id=agent_id,
            action="emergency_rotate",
            outcome="success",
            details={"incident_id": incident_id},
            correlation_id=incident_id
        )
        
        return new_token

# ============================================================================
# Block 9 (chapter listing #9)
# ============================================================================

class GracefulRotation:
    """
    Rotate credentials with overlap period.
    
    This allows agents to transition without downtime:
    1. Issue new credentials
    2. Both old and new work during overlap
    3. Old credentials expire naturally
    """
    
    def __init__(
        self,
        identity_service: AgentIdentityService,
        overlap_hours: int = 24
    ):
        self.identity_service = identity_service
        self.overlap_hours = overlap_hours
    
    async def rotate_gracefully(
        self,
        agent_id: str,
        actor: str
    ) -> tuple[str, str]:
        """
        Rotate with overlap.
        
        Returns (old_token_expiry, new_token).
        """
        identity = await self.identity_service.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        # Get current credentials
        old_credentials = await self.identity_service.store.get_credentials_for_agent(
            agent_id
        )
        
        # Issue new credentials with standard TTL
        new_token = await self.identity_service.issue_token(
            agent_id,
            actor=actor
        )
        
        # Set old credentials to expire after overlap period
        overlap_expiry = datetime.now(timezone.utc) + timedelta(hours=self.overlap_hours)
        for cred in old_credentials:
            if cred.expires_at > overlap_expiry and not cred.is_revoked:
                # Reduce TTL to overlap period
                cred.expires_at = overlap_expiry
                await self.identity_service.store.store_credential(cred)
        
        return overlap_expiry.isoformat(), new_token

# ============================================================================
# Block 10 (chapter listing #10)
# ============================================================================

@dataclass
class IdentityAuditEvent:
    """
    Comprehensive audit event structure.
    
    Designed for:
    - Compliance reporting (SOC 2, PCI-DSS, HIPAA)
    - Security incident investigation
    - Operational troubleshooting
    """
    # Event identification
    event_id: str              # Unique event ID (UUID)
    event_type: str            # Categorized event type
    timestamp: datetime        # When it happened (UTC)
    
    # Actor information
    actor_id: str              # Who performed the action
    actor_type: str            # "human", "agent", "system", "service"
    actor_ip: str | None       # Source IP address
    actor_user_agent: str | None  # Client information
    
    # Target information
    resource_type: str         # What type of resource
    resource_id: str           # Which specific resource
    agent_id: str | None       # Agent involved (if any)
    
    # Action details
    action: str                # What was done
    outcome: str               # "success", "failure", "denied"
    reason: str | None         # Why it failed/was denied
    
    # Context
    correlation_id: str | None # Links related events
    session_id: str | None     # Session context
    request_id: str | None     # Request tracing
    
    # Detailed changes
    details: dict              # Event-specific data
    previous_state: dict | None  # State before change
    new_state: dict | None       # State after change

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON storage; convert datetime to ISO 8601.

        ComplianceAuditStore.append() and verify_integrity() hash the
        JSON form of each event, so this method must produce a stable,
        json-serializable dict (no raw datetime objects).
        """
        from dataclasses import asdict
        d = asdict(self)
        if isinstance(self.timestamp, datetime):
            d["timestamp"] = self.timestamp.isoformat()
        return d

# ============================================================================
# Block 11 (chapter listing #11)
# ============================================================================

class ComplianceAuditStore:
    """
    Audit store with compliance features.

    Events are written to an append-only JSONL file and only the most recent
    events are cached in memory. In production, put this sink on append-only
    storage or an immutable log service, replicate it, and configure retention
    to match your control obligations.
    """
    # NOTE: class-level threading.Lock only serializes within a single
    # process. Cross-process serialization (e.g., gunicorn forked workers)
    # relies on _acquire_file_lock(), which uses fcntl.flock on the
    # shared on-disk audit file. Do not rely on _process_append_lock for
    # cross-process correctness.
    _process_append_lock = threading.Lock()
    
    def __init__(
        self,
        log_path: str | os.PathLike[str] = "compliance-audit.jsonl",
        recent_cache_size: int = 1000
    ):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._recent_events: deque[tuple[str, IdentityAuditEvent]] = deque(
            maxlen=recent_cache_size
        )
        self._lock_path = self.log_path.with_name(f"{self.log_path.name}.lock")
        self._last_hash: str = self._load_last_hash()

    def _read_last_record(self) -> Optional[dict]:
        """Read the last non-empty JSONL record without scanning the file."""
        if not self.log_path.exists():
            return None

        file_size = self.log_path.stat().st_size
        if file_size == 0:
            return None

        buffer = b""
        position = file_size
        chunk_size = 4096

        with self.log_path.open("rb") as f:
            while position > 0:
                read_size = min(chunk_size, position)
                position -= read_size
                f.seek(position)
                buffer = f.read(read_size) + buffer
                lines = buffer.split(b"\n")

                if position > 0 and len(lines) == 1:
                    continue

                candidates = lines if position == 0 else lines[1:]
                for line in reversed(candidates):
                    if line.strip():
                        return json.loads(line.decode("utf-8"))

        return None

    def _load_last_hash(self) -> str:
        """Resume the hash chain from the durable JSONL tail record."""
        last_record = self._read_last_record()
        if not last_record:
            return "genesis"
        return last_record["hash"]

    def _iter_records(self):
        """Stream persisted records instead of loading the full log."""
        if not self.log_path.exists():
            return

        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def _event_from_record(self, record: dict) -> IdentityAuditEvent:
        data = dict(record["event"])
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return IdentityAuditEvent(**data)

    def _prepare_lock_file(self, lock_file) -> None:
        """Ensure Windows byte-range locking has a byte to lock."""
        lock_file.seek(0)
        if lock_file.read(1) == "":
            lock_file.write("0")
            lock_file.flush()
        lock_file.seek(0)

    def _acquire_file_lock(self, lock_file) -> None:
        """Take an exclusive interprocess lock on the audit sink."""
        self._prepare_lock_file(lock_file)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

    def _release_file_lock(self, lock_file) -> None:
        """Release the audit sink interprocess lock."""
        lock_file.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    
    def _append_sync(
        self,
        event_dict: dict[str, Any],
        event: IdentityAuditEvent
    ) -> str:
        # Serialize appends across threads and service-worker processes.
        with ComplianceAuditStore._process_append_lock:
            with self._lock_path.open("a+", encoding="utf-8") as lock_file:
                self._acquire_file_lock(lock_file)
                try:
                    previous_hash = self._load_last_hash()
                    event_data = json.dumps(event_dict, sort_keys=True)
                    chain_data = f"{previous_hash}:{event_data}"
                    event_hash = hashlib.sha256(
                        chain_data.encode()
                    ).hexdigest()

                    record = {
                        "hash": event_hash,
                        "previous_hash": previous_hash,
                        "event": event_dict
                    }

                    # Persist first; keep only a bounded operational cache.
                    with self.log_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(record, sort_keys=True) + "\n")
                        f.flush()
                        os.fsync(f.fileno())

                    self._recent_events.append((event_hash, event))
                    self._last_hash = event_hash
                finally:
                    self._release_file_lock(lock_file)

        return event_hash

    async def append(self, event: IdentityAuditEvent) -> str:
        """
        Append event with chain integrity.
        
        Each event's hash includes the previous hash,
        creating a tamper-evident chain.
        """
        event_dict = event.to_dict()
        return await asyncio.to_thread(self._append_sync, event_dict, event)
    
    async def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify the audit log has not been tampered with.
        
        Returns (is_valid, list_of_issues).
        """
        issues = []
        prev_hash = "genesis"
        
        for i, record in enumerate(self._iter_records()):
            stored_hash = record["hash"]
            if record.get("previous_hash") != prev_hash:
                issues.append(f"Event {i}: previous_hash mismatch")

            event = self._event_from_record(record)
            event_data = json.dumps(event.to_dict(), sort_keys=True)
            chain_data = f"{prev_hash}:{event_data}"
            computed_hash = hashlib.sha256(chain_data.encode()).hexdigest()
            
            if computed_hash != stored_hash:
                issues.append(
                    f"Event {i} ({event.event_id}): hash mismatch"
                )
            
            prev_hash = stored_hash
        
        return len(issues) == 0, issues
    
    async def export_for_compliance(
        self,
        since: datetime,
        until: datetime,
        format: str = "json",
        page_size: int = 1000,
        cursor: int = 0
    ) -> str:
        """
        Export one page of audit events for compliance reporting.

        Keep source logs for the full retention period in the durable sink.
        Callers page through exports with cursor/next_cursor instead of
        materializing years of events in process memory.
        """
        events = []
        matched = 0
        next_cursor = None

        for record in self._iter_records():
            event = self._event_from_record(record)
            if not since <= event.timestamp <= until:
                continue

            if matched < cursor:
                matched += 1
                continue

            if len(events) >= page_size:
                next_cursor = matched
                break

            events.append(event)
            matched += 1
        
        if format == "json":
            return json.dumps(
                {
                    "events": [e.to_dict() for e in events],
                    "next_cursor": next_cursor,
                    "retention_source": str(self.log_path)
                },
                indent=2
            )
        elif format == "csv":
            # Flatten for CSV export
            lines = ["event_id,timestamp,event_type,actor_id,resource_type,action,outcome"]
            for e in events:
                lines.append(
                    f"{e.event_id},{e.timestamp.isoformat()},{e.event_type},"
                    f"{e.actor_id},{e.resource_type},{e.action},{e.outcome}"
                )
            return "\n".join(lines)
        else:
            raise ValueError(f"Unknown format: {format}")

# ============================================================================
# Block 12 (chapter listing #12)
# ============================================================================

class AuditQueries:
    """Common audit log queries."""
    
    def __init__(self, store: IdentityStore):
        self.store = store
    
    async def failed_authentications(
        self,
        since: datetime,
        threshold: int = 5
    ) -> list[dict]:
        """Find agents with multiple failed auth attempts."""
        events: list[AuditEvent] = []
        page_size = 100
        offset = 0

        while True:
            page = await self.store.query_audit_log(
                event_type=AuditEventType.TOKEN_REJECTED,
                since=since,
                limit=page_size,
                offset=offset
            )
            events.extend(page)
            if len(page) < page_size:
                break
            offset += len(page)
        
        # Count by agent
        counts: dict[str, int] = {}
        for event in events:
            agent_id = event.agent_id or "unknown"
            counts[agent_id] = counts.get(agent_id, 0) + 1
        
        # Return those exceeding threshold
        return [
            {"agent_id": agent_id, "count": count}
            for agent_id, count in counts.items()
            if count >= threshold
        ]
    
    async def permission_escalations(
        self,
        since: datetime
    ) -> list[AuditEvent]:
        """Find all permission grants."""
        return await self.store.query_audit_log(
            event_type=AuditEventType.PERMISSION_GRANTED,
            since=since
        )
    
    async def agent_activity_report(
        self,
        agent_id: str,
        since: datetime,
        until: datetime
    ) -> dict:
        """Generate activity report for an agent."""
        events = await self.store.query_audit_log(
            agent_id=agent_id,
            since=since,
            until=until
        )
        
        return {
            "agent_id": agent_id,
            "period": {
                "start": since.isoformat(),
                "end": until.isoformat()
            },
            "total_events": len(events),
            "by_type": self._count_by_field(events, "event_type"),
            "by_outcome": self._count_by_field(events, "outcome"),
            "events": [e.to_dict() for e in events]
        }
    
    def _count_by_field(
        self,
        events: list[AuditEvent],
        field: str
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in events:
            value = str(getattr(event, field, "unknown"))
            counts[value] = counts.get(value, 0) + 1
        return counts

# ============================================================================
# Block 13 (chapter listing #13)
# ============================================================================

class ApexAgentProvisioner:
    """
    Apex-specific agent provisioning with compliance controls.
    """
    
    ROLE_PERMISSIONS = {
        "trade_executor": [
            PermissionScope.DATA_READ,
            PermissionScope.DATA_WRITE,
            # Custom Apex scopes
            "orders:create",
            "orders:execute"
        ],
        "risk_analyst": [
            PermissionScope.DATA_READ,
            "risk:calculate",
            "risk:report"
        ],
        "compliance_monitor": [
            PermissionScope.DATA_READ,
            "audit:read",
            "compliance:report"
        ]
    }
    
    ROLE_LIMITS = {
        "trade_executor": {
            "max_trade_amount": 1_000_000,
            "max_daily_volume": 10_000_000,
            "allowed_asset_classes": ["equity", "etf"],
            "market_hours_only": True
        }
    }
    
    def __init__(self, identity_service: AgentIdentityService):
        self.identity_service = identity_service
    
    async def provision_trading_agent(
        self,
        name: str,
        role: str,
        desk: str,
        manager_email: str,
        approver_email: str,  # Four-eyes: different from manager
        ticket_id: str        # Change management ticket
    ) -> tuple[AgentIdentity, str]:
        """
        Provision a trading agent with full compliance trail.
        """
        if role not in self.ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: {role}")
        
        # Verify approvals (in production, check ticket system)
        if manager_email == approver_email:
            raise ValueError("Manager and approver must be different (four-eyes)")
        
        # Create with role-based permissions
        permissions = self.ROLE_PERMISSIONS[role]
        limits = self.ROLE_LIMITS.get(role, {})
        
        identity, token = await self.identity_service.create_identity(
            name=name,
            description=f"Trading agent for {desk} desk",
            owner_team=desk,
            owner_email=manager_email,
            permissions=permissions,
            metadata={
                "role": role,
                "desk": desk,
                "manager": manager_email,
                "approver": approver_email,
                "ticket_id": ticket_id,
                "limits": limits,
                "compliance_classification": "trading_system",
                "data_sensitivity": "confidential"
            },
            actor=f"provisioner:{approver_email}",
            correlation_id=ticket_id
        )
        
        return identity, token

# ============================================================================
# Block 14 (chapter listing #14)
# ============================================================================

@dataclass
class TradeRequest:
    """Trade request with identity context."""
    trade_id: str
    agent_id: str
    agent_token: str
    delegation_token: str | None  # If human-initiated
    symbol: str
    side: str  # "buy" or "sell"
    quantity: int
    price: float | None
    order_type: str


class TradeExecutor:
    """Execute trades with full identity verification."""
    
    def __init__(
        self,
        identity_service: AgentIdentityService,
        audit_store: IdentityStore
    ):
        self.identity_service = identity_service
        self.audit_store = audit_store
        self.auth = AgentAuthenticator(identity_service)
    
    async def execute_trade(self, request: TradeRequest) -> dict:
        """
        Execute a trade with complete identity verification.
        """
        correlation_id = request.trade_id
        
        # 1. Verify agent identity
        try:
            identity = await self.auth.authenticate(request.agent_token)
        except ValueError as e:
            await self._audit_trade_failure(
                request, "authentication_failed", str(e), correlation_id
            )
            raise
        
        # 2. Verify agent has trading permission
        if not identity.has_permission("orders:execute"):
            await self._audit_trade_failure(
                request, "permission_denied", "Missing orders:execute", correlation_id
            )
            raise PermissionError("Agent not authorized for trade execution")
        
        # 3. Verify limits
        limits = identity.metadata.get("limits", {})
        trade_value = request.quantity * (request.price or 0)
        
        if trade_value > limits.get("max_trade_amount", float("inf")):
            await self._audit_trade_failure(
                request, "limit_exceeded", 
                f"Trade value {trade_value} exceeds limit", correlation_id
            )
            raise ValueError(f"Trade exceeds maximum amount")
        
        # 4. If human-delegated, verify delegation
        human_context = None
        if request.delegation_token:
            _, delegation = await self.auth.authenticate_with_delegation(
                request.agent_token,
                request.delegation_token,
                required_scope="orders:execute"
            )
            human_context = {
                "delegator_sub": delegation["human_sub"],
                "delegator_email": delegation["human_email"]
            }
        
        # 5. Execute trade (simulated)
        execution_result = {
            "trade_id": request.trade_id,
            "status": "executed",
            "executed_price": request.price,
            "executed_quantity": request.quantity,
            "execution_time": datetime.now(timezone.utc).isoformat()
        }
        
        # 6. Comprehensive audit log
        await self._audit_trade_success(
            request, identity, execution_result, human_context, correlation_id
        )
        
        return execution_result
    
    async def _audit_trade_success(
        self,
        request: TradeRequest,
        identity: AgentIdentity,
        result: dict,
        human_context: dict | None,
        correlation_id: str
    ):
        """Record successful trade with full context."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.TRADE_EXECUTED,
            timestamp=datetime.now(timezone.utc),
            agent_id=identity.agent_id,
            actor_id=identity.agent_id,
            actor_type="agent",
            resource_type="trade",
            resource_id=request.trade_id,
            action="execute_trade",
            outcome="success",
            details={
                "symbol": request.symbol,
                "side": request.side,
                "quantity": request.quantity,
                "price": request.price,
                "order_type": request.order_type,
                "execution_result": result,
                "agent_permissions": [
                    permission_value(p) for p in identity.permissions
                ],
                "agent_limits": identity.metadata.get("limits"),
                "human_delegation": human_context,
                "agent_certificate_serial": identity.certificate_serial
            },
            client_ip=None,
            user_agent=None,
            correlation_id=correlation_id
        )
        await self.audit_store.log_audit_event(event)
    
    async def _audit_trade_failure(
        self,
        request: TradeRequest,
        failure_type: str,
        reason: str,
        correlation_id: str
    ):
        """Record failed trade attempt."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.TRADE_REJECTED,
            timestamp=datetime.now(timezone.utc),
            agent_id=request.agent_id,
            actor_id=request.agent_id,
            actor_type="agent",
            resource_type="trade",
            resource_id=request.trade_id,
            action="execute_trade",
            outcome="failure",
            details={
                "failure_type": failure_type,
                "reason": reason,
                "symbol": request.symbol,
                "side": request.side,
                "quantity": request.quantity
            },
            client_ip=None,
            user_agent=None,
            correlation_id=correlation_id
        )
        await self.audit_store.log_audit_event(event)

# ============================================================================
# Block 15 (chapter listing #15)
# ============================================================================

class ComplianceReporter:
    """Generate compliance reports for auditors."""
    
    def __init__(self, identity_service: AgentIdentityService):
        self.identity_service = identity_service

    async def _list_all_identities(
        self,
        page_size: int = 500
    ) -> list[AgentIdentity]:
        """Collect all identity pages instead of relying on the default limit."""
        identities: list[AgentIdentity] = []
        offset = 0

        while True:
            page = await self.identity_service.store.list_identities(
                limit=page_size,
                offset=offset
            )
            identities.extend(page)
            if len(page) < page_size:
                break
            offset += len(page)

        return identities

    async def _list_all_audit_events(
        self,
        period_start: datetime,
        period_end: datetime,
        page_size: int = 500
    ) -> list[AuditEvent]:
        """Collect every audit event in the review period page by page."""
        events: list[AuditEvent] = []
        offset = 0

        while True:
            page = await self.identity_service.get_audit_log(
                since=period_start,
                until=period_end,
                limit=page_size,
                offset=offset
            )
            events.extend(page)
            if len(page) < page_size:
                break
            offset += len(page)

        return events
    
    async def generate_access_review(
        self,
        period_start: datetime,
        period_end: datetime
    ) -> dict:
        """
        Generate quarterly access review report.
        
        Required for SOC 2 CC6.1, CC6.2.
        """
        # Get all identities
        identities = await self._list_all_identities()
        
        # Get all relevant audit events without truncating at the default limit.
        audit_events = await self._list_all_audit_events(period_start, period_end)
        permission_events = [
            e for e in audit_events
            if e.event_type in [
                AuditEventType.PERMISSION_GRANTED,
                AuditEventType.PERMISSION_REVOKED
            ]
        ]
        
        # Get all identity lifecycle events
        lifecycle_events = [
            e for e in audit_events
            if e.event_type in [
                AuditEventType.IDENTITY_CREATED,
                AuditEventType.IDENTITY_SUSPENDED,
                AuditEventType.IDENTITY_REVOKED
            ]
        ]
        
        return {
            "report_type": "quarterly_access_review",
            "period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat()
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_agents": len(identities),
                "active_agents": len([i for i in identities if i.status == IdentityStatus.ACTIVE]),
                "suspended_agents": len([i for i in identities if i.status == IdentityStatus.SUSPENDED]),
                "revoked_agents": len([i for i in identities if i.status == IdentityStatus.REVOKED]),
                "permission_changes": len(permission_events),
                "lifecycle_changes": len(lifecycle_events)
            },
            "agents": [
                {
                    "agent_id": i.agent_id,
                    "name": i.name,
                    "owner_team": i.owner_team,
                    "status": i.status.value,
                    "permissions": [permission_value(p) for p in i.permissions],
                    "created_at": i.created_at.isoformat(),
                    "last_used_at": i.last_used_at.isoformat() if i.last_used_at else None
                }
                for i in identities
            ],
            "permission_changes": [e.to_dict() for e in permission_events],
            "lifecycle_changes": [e.to_dict() for e in lifecycle_events]
        }
