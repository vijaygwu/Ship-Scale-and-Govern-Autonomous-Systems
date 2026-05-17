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
"""


# ============================================================================
# Block 1 (chapter listing #1)
# ============================================================================

# What the logs look like WITHOUT identity infrastructure
{
    "timestamp": "2024-03-15T03:14:22Z",
    "event": "trade_executed",
    "symbol": "AAPL",
    "quantity": 50000,
    "agent": "trading-agent"  # Which one? There are 12 instances.
}

# What the logs look like WITH identity infrastructure
{
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
        identity = await identity_service.validate_token(
            request.agent_token,
            required_scope=PermissionScope.DATA_READ
        )
    except ValueError:
        audit_log.record("database_access_denied", reason="invalid_token")
        return "Access denied: invalid credentials"

    # 2. LEAST PRIVILEGE: Check specific permission for this resource
    if "customers" in request.query and not identity.has_permission("data:customers:read"):
        audit_log.record("database_access_denied", reason="insufficient_scope")
        return "Access denied: missing customers:read permission"

    # 3. ASSUME BREACH: Log everything, even successful requests
    audit_log.record(
        "database_query_executed",
        agent_id=identity.agent_id,
        query_hash=hash(request.query),
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
    
    def to_jwt(self, signing_key: str) -> str:
        """Encode as signed JWT."""
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
        return jwt.encode(payload, signing_key, algorithm="RS256")

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

Code Navigation (line numbers are approximate):
- Permission Model (PermissionScope, IdentityStatus, AuditEventType) ... ~45
- Data Models (AgentIdentity, Credential, DelegationRecord, AuditEvent) ... ~120
- Storage Layer (IdentityStore, KeyVault) ... ~280
- Certificate Authority (CertificateAuthority) ... ~470
- Main Service (AgentIdentityService) ... ~700
"""

import asyncio
import hashlib
import json
import secrets
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

import jwt
from cryptography import x509
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
    
    # Key management
    KEY_ROTATED = "key.rotated"
    KEY_COMPROMISED = "key.compromised"



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
    permissions: list[PermissionScope]
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
    
    def has_permission(self, scope: PermissionScope) -> bool:
        """Check if identity has a specific permission."""
        if PermissionScope.ADMIN_FULL in self.permissions:
            return True
        return scope in self.permissions
    
    def has_any_permission(self, scopes: list[PermissionScope]) -> bool:
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
            "permissions": [p.value for p in self.permissions],
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
    
    def __init__(self, audit_log_capacity: int = 10_000):
        # Naturally bounded by user/agent population (one entry per agent_id,
        # credential_id, delegation_id). In production, back these with a
        # database so memory does not scale with fleet size.
        self._identities: dict[str, AgentIdentity] = {}
        self._credentials: dict[str, Credential] = {}
        self._delegations: dict[str, DelegationRecord] = {}
        # Audit log is *not* naturally bounded -- every action appends an event.
        # Use a bounded deque so the process cannot leak memory indefinitely.
        # For long-running production deployments, replace this in-memory ring
        # buffer with a durable sink (Kafka, Loki, CloudTrail, etc.) so that
        # events evicted from the deque are still retained for compliance.
        self._audit_log: deque[AuditEvent] = deque(maxlen=audit_log_capacity)
        self._revoked_certs: set[str] = set()  # Certificate Revocation List
    
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
        self._credentials[credential.credential_id] = credential
    
    async def get_credential(self, credential_id: str) -> Optional[Credential]:
        """Retrieve a credential by ID."""
        return self._credentials.get(credential_id)
    
    async def get_credentials_for_agent(self, agent_id: str) -> list[Credential]:
        """Get all credentials for an agent."""
        return [c for c in self._credentials.values() if c.agent_id == agent_id]
    
    async def store_delegation(self, delegation: DelegationRecord) -> None:
        """Store a delegation record."""
        self._delegations[delegation.delegation_id] = delegation
    
    async def get_delegation(self, delegation_id: str) -> Optional[DelegationRecord]:
        """Retrieve a delegation by ID."""
        return self._delegations.get(delegation_id)
    
    async def add_to_crl(self, cert_serial: str) -> None:
        """Add certificate to revocation list."""
        self._revoked_certs.add(cert_serial)
    
    async def is_cert_revoked(self, cert_serial: str) -> bool:
        """Check if certificate is revoked."""
        return cert_serial in self._revoked_certs
    
    async def log_audit_event(self, event: AuditEvent) -> None:
        """Append to audit log (immutable)."""
        self._audit_log.append(event)
    
    async def query_audit_log(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100
    ) -> list[AuditEvent]:
        """Query audit log with filters."""
        # Materialize the deque snapshot to a list so we can slice with [-limit:].
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

        return results[-limit:]


class KeyVault:
    """
    Secure key storage.
    
    In production, replace with:
    - AWS KMS
    - Azure Key Vault
    - HashiCorp Vault
    - Hardware Security Module (HSM)
    """
    
    def __init__(self):
        self._keys: dict[str, bytes] = {}
        self._metadata: dict[str, dict] = {}
    
    async def generate_key_pair(
        self,
        key_id: str,
        key_size: int = 2048,
        metadata: Optional[dict] = None
    ) -> rsa.RSAPublicKey:
        """Generate and store a new key pair, return public key."""
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
        pem = self._keys.get(key_id)
        if not pem:
            return None
        return serialization.load_pem_private_key(pem, password=None)
    
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
    
    # Custom OID for agent extensions
    # The arc 1.3.6.1.4.1 is IANA's Private Enterprise Numbers (PEN) space.
    # Register your organization's PEN at https://pen.iana.org/ to obtain a
    # unique arc. The example "99999" is illustrative only - replace with your
    # registered PEN for production use. See ITU-T X.660 for OID structure.
    AGENT_ID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
    AGENT_PERMISSIONS_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.2")
    AGENT_OWNER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.3")
    
    def __init__(
        self,
        key_vault: KeyVault,
        store: IdentityStore,
        ca_key_id: str = "ca_intermediate"
    ):
        self.key_vault = key_vault
        self.store = store
        self.ca_key_id = ca_key_id
        self._ca_cert: Optional[x509.Certificate] = None
    
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
            "permissions": [p.value for p in identity.permissions],
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
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False, "Certificate expired or not yet valid", None
            
            # Check revocation
            serial_hex = format(cert.serial_number, 'x')
            if await self.store.is_cert_revoked(serial_hex):
                return False, "Certificate has been revoked", None
            
            # Verify signature (simplified - in production, verify full chain)
            if self._ca_cert:
                try:
                    self._ca_cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                except Exception as e:
                    logger.warning(f"Cert signature verification failed: {e}")
                    return False, "Certificate signature verification failed", None
            
            # Extract agent data from extensions
            agent_data = None
            for ext in cert.extensions:
                if ext.oid == self.AGENT_ID_OID:
                    agent_data = json.loads(ext.value.value.decode())
                    break
            
            return True, None, agent_data
            
        except Exception as e:
            return False, f"Certificate parsing failed: {str(e)}", None
    
    async def revoke_certificate(self, cert_serial: str) -> None:
        """Add certificate to revocation list."""
        await self.store.add_to_crl(cert_serial)

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
        delegation_ttl_hours: int = 8
    ):
        self.store = store
        self.key_vault = key_vault
        self.ca = ca
        self.jwt_signing_key_id = jwt_signing_key_id
        self.token_ttl_hours = token_ttl_hours
        self.delegation_ttl_hours = delegation_ttl_hours
        self._jwt_secret: Optional[str] = None
    
    async def initialize(self) -> None:
        """Initialize the identity service."""
        # Initialize CA
        await self.ca.initialize()
        
        # Generate JWT signing key
        await self.key_vault.generate_key_pair(
            self.jwt_signing_key_id,
            metadata={"purpose": "jwt_signing"}
        )
        
        # For HS256, we need a symmetric secret.
        # IMPORTANT: In production, load JWT_SECRET from environment variable
        # or secrets manager. (Imports os/warnings are at module top.)
        # secrets.token_urlsafe(32) yields ~256 bits of entropy, matching HS256's
        # hash size; the 'DEMO_ONLY_' prefix is a deployment guard, not entropy.
        self._jwt_secret = os.environ.get(
            "JWT_SECRET", "DEMO_ONLY_" + secrets.token_urlsafe(32)
        )
        if self._jwt_secret.startswith("DEMO_ONLY_"):
            warnings.warn("Using generated demo secret. Set JWT_SECRET env var in production.")
    
    # -------------------------------------------------------
    # Identity Lifecycle
    # -------------------------------------------------------
    async def create_identity(
        self,
        name: str,
        description: str,
        owner_team: str,
        owner_email: str,
        permissions: list[PermissionScope],
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
        
        # Store identity
        await self.store.create_identity(identity)
        
        # Issue certificate
        cert, private_key = await self.ca.issue_agent_certificate(
            identity,
            validity_days=validity_days
        )
        
        # Update identity with certificate
        identity.certificate_pem = cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()
        identity.certificate_serial = format(cert.serial_number, 'x')
        identity.status = IdentityStatus.ACTIVE
        identity.activated_at = now
        
        await self.store.update_identity(identity)
        
        # Issue initial token
        token = await self._issue_token(identity, actor)
        
        # Audit
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
                "permissions": [p.value for p in permissions],
                "validity_days": validity_days
            },
            correlation_id=correlation_id
        )
        
        return identity, token
    
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
            await self.ca.revoke_certificate(identity.certificate_serial)
        
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
        scopes: Optional[list[PermissionScope]] = None,
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
                    f"Agent does not have permission: {scope.value}"
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
        scopes: Optional[list[PermissionScope]] = None,
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
            "scopes": [s.value for s in (scopes or identity.permissions)],
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": token_id,
            "iss": "agent-identity-service",
            "aud": "agent-platform"
        }
        
        token = jwt.encode(payload, self._jwt_secret, algorithm="HS256")
        
        # Store credential record
        credential = Credential(
            credential_id=token_id,
            agent_id=identity.agent_id,
            credential_type="jwt",
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            scopes=[s.value for s in (scopes or identity.permissions)],
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
                "scopes": [s.value for s in (scopes or identity.permissions)],
                "ttl_hours": ttl
            }
        )
        
        return token
    
    async def validate_token(
        self,
        token: str,
        required_scope: Optional[PermissionScope] = None
    ) -> dict:
        """
        Validate an authentication token.
        
        Returns the decoded payload if valid.
        Raises ValueError if invalid.
        """
        try:
            payload = jwt.decode(
                token,
                self._jwt_secret,
                algorithms=["HS256"],
                audience="agent-platform"
            )
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
            token_scopes = [PermissionScope(s) for s in payload["scopes"]]
            if required_scope not in token_scopes:
                if PermissionScope.ADMIN_FULL not in token_scopes:
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
                            "required": required_scope.value,
                            "available": payload["scopes"]
                        }
                    )
                    raise PermissionError(
                        f"Token does not have required scope: {required_scope.value}"
                    )
        
        # Update last used
        identity.last_used_at = datetime.now(timezone.utc)
        await self.store.update_identity(identity)
        
        await self._audit(
            event_type=AuditEventType.TOKEN_VALIDATED,
            agent_id=payload["sub"],
            actor_id=payload["sub"],
            actor_type="agent",
            resource_type="token",
            resource_id=payload["jti"],
            action="validate",
            outcome="success",
            details={}
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
        actor: str
    ) -> int:
        """Revoke all credentials for an agent."""
        credentials = await self.store.get_credentials_for_agent(agent_id)
        count = 0
        
        for cred in credentials:
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
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Rotate all credentials for an agent.
        
        This:
        1. Revokes all existing tokens
        2. Issues a new certificate
        3. Issues a new token
        
        Returns the new token.
        """
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if not identity.is_valid():
            raise ValueError(f"Identity is not valid: {identity.status.value}")
        
        # Revoke existing credentials
        revoked_count = await self._revoke_all_credentials(agent_id, actor)
        
        # Issue new certificate
        old_serial = identity.certificate_serial
        cert, _ = await self.ca.issue_agent_certificate(identity)
        
        identity.certificate_pem = cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()
        identity.certificate_serial = format(cert.serial_number, 'x')
        
        await self.store.update_identity(identity)
        
        # Revoke old certificate
        if old_serial:
            await self.ca.revoke_certificate(old_serial)
        
        # Issue new token
        new_token = await self._issue_token(identity, actor)
        
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
                "new_cert_serial": identity.certificate_serial
            },
            correlation_id=correlation_id
        )
        
        return new_token
    
    # -------------------------------------------------------
    # Human-Agent Delegation
    # -------------------------------------------------------
    async def create_delegation(
        self,
        human_oidc_token: dict,  # Decoded OIDC token
        agent_id: str,
        scopes: list[PermissionScope],
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
        # Validate agent exists and is active
        identity = await self.store.get_identity(agent_id)
        if not identity or not identity.is_valid():
            raise ValueError(f"Agent not valid for delegation: {agent_id}")
        
        # Validate human can delegate these scopes
        # (In production, check against human's permissions from OIDC claims)
        
        now = datetime.now(timezone.utc)
        ttl = ttl_hours or self.delegation_ttl_hours
        expires_at = now + timedelta(hours=ttl)
        
        delegation_id = str(uuid.uuid4())
        
        # Create delegation record
        delegation = DelegationRecord(
            delegation_id=delegation_id,
            human_subject=human_oidc_token["sub"],
            human_email=human_oidc_token.get("email", "unknown"),
            human_name=human_oidc_token.get("name", "Unknown"),
            agent_id=agent_id,
            delegated_scopes=[s.value for s in scopes],
            constraints=constraints or {},
            created_at=now,
            expires_at=expires_at,
            max_uses=max_uses
        )
        
        await self.store.store_delegation(delegation)
        
        # Create delegation token
        payload = {
            "type": "delegation",
            "del_id": delegation_id,
            "human_sub": human_oidc_token["sub"],
            "human_email": human_oidc_token.get("email"),
            "agent_id": agent_id,
            "scopes": [s.value for s in scopes],
            "constraints": constraints or {},
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": "agent-identity-service",
            "aud": "agent-platform"
        }
        
        delegation_token = jwt.encode(payload, self._jwt_secret, algorithm="HS256")
        
        await self._audit(
            event_type=AuditEventType.DELEGATION_CREATED,
            agent_id=agent_id,
            actor_id=human_oidc_token["sub"],
            actor_type="human",
            resource_type="delegation",
            resource_id=delegation_id,
            action="create",
            outcome="success",
            details={
                "human_email": human_oidc_token.get("email"),
                "scopes": [s.value for s in scopes],
                "ttl_hours": ttl,
                "max_uses": max_uses
            },
            correlation_id=correlation_id
        )
        
        return delegation_token
    
    async def validate_delegation(
        self,
        delegation_token: str,
        required_scope: Optional[PermissionScope] = None
    ) -> dict:
        """Validate a delegation token."""
        try:
            payload = jwt.decode(
                delegation_token,
                self._jwt_secret,
                algorithms=["HS256"],
                audience="agent-platform"
            )
        except jwt.ExpiredSignatureError as e:
            raise ValueError("Delegation has expired") from e
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid delegation: {e}") from e
        
        if payload.get("type") != "delegation":
            raise ValueError("Not a delegation token")
        
        # Check delegation record
        delegation = await self.store.get_delegation(payload["del_id"])
        if not delegation:
            raise ValueError("Delegation record not found")
        
        if delegation.is_revoked:
            raise ValueError("Delegation has been revoked")
        
        if delegation.max_uses and delegation.used_count >= delegation.max_uses:
            raise ValueError("Delegation has exceeded maximum uses")
        
        # Check required scope
        if required_scope and required_scope.value not in payload["scopes"]:
            raise PermissionError(
                f"Delegation does not include scope: {required_scope.value}"
            )
        
        # Increment use count
        delegation.used_count += 1
        await self.store.store_delegation(delegation)
        
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
        permission: PermissionScope,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> AgentIdentity:
        """Grant additional permission to an agent."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if permission not in identity.permissions:
            identity.permissions.append(permission)
            await self.store.update_identity(identity)
            
            await self._audit(
                event_type=AuditEventType.PERMISSION_GRANTED,
                agent_id=agent_id,
                actor_id=actor,
                actor_type="human",
                resource_type="permission",
                resource_id=permission.value,
                action="grant",
                outcome="success",
                details={"permission": permission.value},
                correlation_id=correlation_id
            )
        
        return identity
    
    async def revoke_permission(
        self,
        agent_id: str,
        permission: PermissionScope,
        actor: str,
        correlation_id: Optional[str] = None
    ) -> AgentIdentity:
        """Revoke a permission from an agent."""
        identity = await self.store.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Identity not found: {agent_id}")
        
        if permission in identity.permissions:
            identity.permissions.remove(permission)
            await self.store.update_identity(identity)
            
            await self._audit(
                event_type=AuditEventType.PERMISSION_REVOKED,
                agent_id=agent_id,
                actor_id=actor,
                actor_type="human",
                resource_type="permission",
                resource_id=permission.value,
                action="revoke",
                outcome="success",
                details={"permission": permission.value},
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
        await self.store.log_audit_event(event)
    
    async def get_audit_log(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        actor_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100
    ) -> list[AuditEvent]:
        """Query the audit log."""
        return await self.store.query_audit_log(
            agent_id=agent_id,
            event_type=event_type,
            actor_id=actor_id,
            since=since,
            until=until,
            limit=limit
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
        required_scope: PermissionScope
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
        required_scope: Optional[PermissionScope] = None
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
    """Demonstrate the identity service."""
    
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
    print(f"   Permissions: {[p.value for p in identity.permissions]}")
    
    # 5. Create human delegation
    print("\n5. Creating human-to-agent delegation...")
    mock_oidc_token = {
        "sub": "user_12345",
        "email": "alice@example.com",
        "name": "Alice Smith"
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
        
        identities = await self.identity_service.store.list_identities(
            status=IdentityStatus.ACTIVE
        )
        
        now = datetime.now(timezone.utc)
        
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
        1. Immediately suspends the agent
        2. Rotates all credentials
        3. Requires manual reactivation after review
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
            correlation_id=incident_id
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
class AuditEvent:
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

# ============================================================================
# Block 11 (chapter listing #11)
# ============================================================================

class ComplianceAuditStore:
    """
    Audit store with compliance features.
    
    In production, implement with:
    - Append-only database (or append-only mode)
    - Write-ahead log with checksums
    - Separate storage from main database
    - Replication across regions
    """
    
    def __init__(self):
        self._events: list[tuple[str, AuditEvent]] = []  # (hash, event)
        self._last_hash: str = "genesis"
    
    async def append(self, event: AuditEvent) -> str:
        """
        Append event with chain integrity.
        
        Each event's hash includes the previous hash,
        creating a tamper-evident chain.
        """
        # Create chain hash
        event_data = json.dumps(event.to_dict(), sort_keys=True)
        chain_data = f"{self._last_hash}:{event_data}"
        event_hash = hashlib.sha256(chain_data.encode()).hexdigest()
        
        # Store with hash
        self._events.append((event_hash, event))
        self._last_hash = event_hash
        
        return event_hash
    
    async def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify the audit log has not been tampered with.
        
        Returns (is_valid, list_of_issues).
        """
        issues = []
        prev_hash = "genesis"
        
        for i, (stored_hash, event) in enumerate(self._events):
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
        format: str = "json"
    ) -> str:
        """Export audit log for compliance reporting."""
        events = [
            event for _, event in self._events
            if since <= event.timestamp <= until
        ]
        
        if format == "json":
            return json.dumps(
                [e.to_dict() for e in events],
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
        events = await self.store.query_audit_log(
            event_type=AuditEventType.TOKEN_REJECTED,
            since=since
        )
        
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
            permissions=[PermissionScope(p) if isinstance(p, str) and ':' in p 
                        else p for p in permissions],
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
        if not identity.has_permission(PermissionScope("orders:execute")):
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
                request.delegation_token
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
            event_type=AuditEventType.TOKEN_VALIDATED,  # Custom: TRADE_EXECUTED
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
                "agent_permissions": [p.value for p in identity.permissions],
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
            event_type=AuditEventType.TOKEN_REJECTED,  # Custom: TRADE_REJECTED
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
        identities = await self.identity_service.store.list_identities()
        
        # Get all permission changes
        permission_events = await self.identity_service.get_audit_log(
            since=period_start,
            until=period_end
        )
        permission_events = [
            e for e in permission_events 
            if e.event_type in [
                AuditEventType.PERMISSION_GRANTED,
                AuditEventType.PERMISSION_REVOKED
            ]
        ]
        
        # Get all identity lifecycle events
        lifecycle_events = await self.identity_service.get_audit_log(
            since=period_start,
            until=period_end
        )
        lifecycle_events = [
            e for e in lifecycle_events
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
                    "permissions": [p.value for p in i.permissions],
                    "created_at": i.created_at.isoformat(),
                    "last_used_at": i.last_used_at.isoformat() if i.last_used_at else None
                }
                for i in identities
            ],
            "permission_changes": [e.to_dict() for e in permission_events],
            "lifecycle_changes": [e.to_dict() for e in lifecycle_events]
        }
