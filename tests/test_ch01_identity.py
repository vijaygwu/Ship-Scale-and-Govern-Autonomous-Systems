"""Regression tests for ch01 identity.py covering Phase 1, 5, 7 fixes."""
from __future__ import annotations

import hashlib
import importlib
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest


def test_identity_imports_cleanly():
    """Phase 1 fix: module-top dataclass + logger lets ``import identity`` succeed."""
    sys.modules.pop("identity", None)
    module = importlib.import_module("identity")
    assert hasattr(module, "IdentityAuditEvent")
    assert hasattr(module, "logger")


def test_identity_audit_event_has_to_dict():
    """IdentityAuditEvent.to_dict() must serialize datetimes as ISO 8601 strings."""
    sys.modules.pop("identity", None)
    module = importlib.import_module("identity")

    now = datetime.now(timezone.utc)
    event = module.IdentityAuditEvent(
        event_id=str(uuid.uuid4()),
        event_type="login",
        timestamp=now,
        actor_id="agent-1",
        actor_type="agent",
        actor_ip="10.0.0.1",
        actor_user_agent="pytest",
        resource_type="identity",
        resource_id="agent-1",
        agent_id="agent-1",
        action="authenticate",
        outcome="success",
        reason=None,
        correlation_id=None,
        session_id=None,
        request_id=None,
        details={},
        previous_state=None,
        new_state=None,
    )

    d = event.to_dict()
    assert isinstance(d, dict)
    assert isinstance(d["timestamp"], str)
    assert d["timestamp"] == now.isoformat()
    assert d["actor_id"] == "agent-1"


def test_block3_pedagogical_examples_callable():
    """Phase 7 stub bindings let Block 3's insecure example run without NameError."""
    sys.modules.pop("identity", None)
    module = importlib.import_module("identity")

    # Empty INTERNAL_NETWORK means the request is not from a trusted source,
    # so the function should return "Access denied" without raising.
    request = SimpleNamespace(source_ip="203.0.113.5", query="SELECT 1")
    result = module.handle_database_request_insecure(request)
    assert result == "Access denied"


def test_zero_trust_audit_uses_stable_sha256_query_hash(identity, monkeypatch, run_async):
    class RecordingAuditLog:
        def __init__(self):
            self.events = []

        def record(self, event_name, **fields):
            self.events.append((event_name, fields))

    class RecordingDatabase:
        def __init__(self):
            self.queries = []

        def execute(self, query):
            self.queries.append(query)
            return "rows"

    class IdentityService:
        async def validate_token(self, token, required_scope):
            assert token == "token"
            assert required_scope == identity.PermissionScope.DATA_READ
            return {"sub": "agent_test"}

        async def get_identity(self, agent_id):
            assert agent_id == "agent_test"
            return _identity_record(
                identity,
                agent_id=agent_id,
                permissions=["data:customers:read"],
                certificate_serial="cert-123",
            )

    query = "SELECT * FROM customers WHERE city = 'Z\\u00fcrich'"
    audit_log = RecordingAuditLog()
    database = RecordingDatabase()
    monkeypatch.setattr(identity, "audit_log", audit_log)
    monkeypatch.setattr(identity, "database", database)

    async def scenario():
        request = SimpleNamespace(agent_token="token", query=query)
        result = await identity.handle_database_request_zero_trust(
            request,
            IdentityService(),
        )
        assert result == "rows"

    run_async(scenario())

    expected_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
    assert audit_log.events == [
        (
            "database_query_executed",
            {
                "agent_id": "agent_test",
                "query_hash": expected_hash,
                "tables_accessed": ["customers"],
                "certificate_serial": "cert-123",
            },
        )
    ]
    assert identity._stable_query_hash(query.encode("utf-8")) == expected_hash
    assert database.queries == [query]


def test_identity_store_bounds_revoked_certificate_records(identity, run_async):
    async def scenario():
        store = identity.IdentityStore(
            max_revoked_cert_records=2,
            revoked_cert_retention_hours=1,
        )
        expired_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await store.add_to_crl("expired", expires_at=expired_at)
        assert await store.is_cert_revoked("expired") is True

        await store.add_to_crl("cert-1")
        await store.add_to_crl("cert-2")
        await store.add_to_crl("cert-3")

        assert len(store._revoked_certs) <= 2
        assert await store.is_cert_revoked("cert-3") is True

    run_async(scenario())


@pytest.fixture
def identity(import_chapter):
    return import_chapter("ch01-enterprise-identity", "identity")


STRONG_TEST_TOKEN_HASH_SECRET = (
    "unit-test-token-hash-secret-0123456789abcdef0123456789abcdef"
)
STRONG_PRODUCTION_TOKEN_HASH_SECRET = "0123456789abcdef0123456789abcdef"


def _identity_record(module, **overrides):
    now = datetime.now(timezone.utc)
    values = {
        "agent_id": "agent_test",
        "name": "test-agent",
        "description": "deterministic unit-test identity",
        "owner_team": "platform",
        "owner_email": "platform@example.com",
        "permissions": [module.PermissionScope.DATA_READ],
        "status": module.IdentityStatus.ACTIVE,
        "certificate_pem": None,
        "certificate_serial": None,
        "created_at": now,
        "activated_at": now,
        "expires_at": now + timedelta(hours=1),
        "last_used_at": None,
        "suspended_at": None,
        "revoked_at": None,
        "revocation_reason": None,
        "metadata": {},
    }
    values.update(overrides)
    return module.AgentIdentity(**values)


def _delegation_record(module, delegation_id: str, **overrides):
    now = datetime.now(timezone.utc)
    values = {
        "delegation_id": delegation_id,
        "human_subject": "human-1",
        "human_email": "human@example.com",
        "human_name": "Human One",
        "agent_id": "agent_test",
        "delegated_scopes": [module.PermissionScope.DATA_READ.value],
        "constraints": {},
        "created_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    values.update(overrides)
    return module.DelegationRecord(**values)


def _audit_event(module, event_id: str):
    return module.IdentityAuditEvent(
        event_id=event_id,
        event_type="identity.test",
        timestamp=datetime.now(timezone.utc),
        actor_id="agent-1",
        actor_type="agent",
        actor_ip="10.0.0.1",
        actor_user_agent="pytest",
        resource_type="identity",
        resource_id="agent-1",
        agent_id="agent-1",
        action="validate",
        outcome="success",
        reason=None,
        correlation_id=None,
        session_id=None,
        request_id=None,
        details={},
        previous_state=None,
        new_state=None,
    )


def _service_audit_event(module, event_id: str, event_type, timestamp: datetime):
    return module.AuditEvent(
        event_id=event_id,
        event_type=event_type,
        timestamp=timestamp,
        agent_id="agent-1",
        actor_id="unit-test",
        actor_type="human",
        resource_type="identity",
        resource_id="agent-1",
        action="test",
        outcome="success",
        details={},
        client_ip=None,
        user_agent=None,
        correlation_id=None,
    )


def test_audit_queries_failed_authentications_pages_all_matches(
    identity,
    run_async,
):
    async def scenario():
        store = identity.IdentityStore(audit_log_capacity=200)
        queries = identity.AuditQueries(store)
        agent_id = "agent-over-100"
        since = datetime.now(timezone.utc) - timedelta(seconds=1)

        for index in range(125):
            await store.log_audit_event(
                identity.AuditEvent(
                    event_id=f"failed-auth-{index:03d}",
                    event_type=identity.AuditEventType.TOKEN_REJECTED,
                    timestamp=since + timedelta(milliseconds=index),
                    agent_id=agent_id,
                    actor_id=agent_id,
                    actor_type="agent",
                    resource_type="credential",
                    resource_id=agent_id,
                    action="validate_token",
                    outcome="failure",
                    details={"reason": "invalid_token"},
                    client_ip=None,
                    user_agent=None,
                    correlation_id=None,
                )
            )

        failures = await queries.failed_authentications(since=since, threshold=1)

        assert failures == [{"agent_id": agent_id, "count": 125}]

    run_async(scenario())


async def _initialized_service_with_agent(
    module,
    permissions=None,
    audit_log_capacity: int = 1000,
):
    store = module.IdentityStore(audit_log_capacity=audit_log_capacity)
    vault = module.KeyVault()
    ca = module.CertificateAuthority(vault, store)
    service = module.AgentIdentityService(store, vault, ca)
    await service.initialize()
    await store.create_identity(
        _identity_record(
            module,
            permissions=permissions
            or [
                module.PermissionScope.DATA_READ,
                module.PermissionScope.DATA_WRITE,
            ],
        )
    )
    return service, store


async def _decode_service_token(module, service, token: str, **overrides):
    public_key = await service.key_vault.get_public_key(
        service.jwt_signing_key_id
    )
    assert public_key is not None
    kwargs = {
        "algorithms": ["RS256"],
        "audience": "agent-platform",
        "issuer": "agent-identity-service",
    }
    kwargs.update(overrides)
    return module.jwt.decode(token, public_key, **kwargs)


async def _encode_service_token(module, service, payload: dict) -> str:
    private_key = await service.key_vault.get_private_key(
        service.jwt_signing_key_id
    )
    assert private_key is not None
    return module.jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": service.jwt_signing_key_id},
    )


def test_agent_identity_validity_and_admin_scope(identity):
    record = _identity_record(identity, permissions=[identity.PermissionScope.ADMIN_FULL])

    assert record.is_valid() is True
    assert record.has_permission(identity.PermissionScope.DATA_DELETE) is True
    assert record.has_permission("custom:scope") is True

    expired = _identity_record(
        identity,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    assert expired.is_valid() is False

    suspended = _identity_record(identity, status=identity.IdentityStatus.SUSPENDED)
    assert suspended.is_valid() is False


def test_identity_service_issues_validates_and_audits_scoped_tokens(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_TEST_TOKEN_HASH_SECRET)

    async def scenario():
        store = identity.IdentityStore(audit_log_capacity=20)
        vault = identity.KeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(
            store,
            vault,
            ca,
            token_ttl_hours=1,
            last_used_update_interval=timedelta(0),
        )
        await service.initialize()

        agent, token = await service.create_identity(
            name="research-agent",
            description="research workload",
            owner_team="research",
            owner_email="research@example.com",
            permissions=[
                identity.PermissionScope.DATA_READ,
                identity.PermissionScope.TOOLS_INVOKE,
            ],
            validity_days=1,
            actor="unit-test",
            correlation_id="corr-test",
        )

        header = identity.jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"] == service.jwt_signing_key_id

        payload = await service.validate_token(
            token,
            required_scope=identity.PermissionScope.DATA_READ,
        )
        assert payload["sub"] == agent.agent_id
        assert identity.PermissionScope.DATA_READ.value in payload["scopes"]

        credential = await store.get_credential(payload["jti"])
        assert credential is not None
        assert credential.token_hash != token
        assert len(credential.token_hash) == 64

        with pytest.raises(PermissionError):
            await service.validate_token(
                token,
                required_scope=identity.PermissionScope.DATA_WRITE,
            )

        events = await store.query_audit_log(agent_id=agent.agent_id, limit=20)
        event_types = {event.event_type for event in events}
        assert identity.AuditEventType.IDENTITY_CREATED in event_types
        assert identity.AuditEventType.TOKEN_ISSUED in event_types
        assert identity.AuditEventType.TOKEN_VALIDATED in event_types
        assert identity.AuditEventType.TOKEN_REJECTED in event_types

    run_async(scenario())


def test_validate_token_rejects_wrong_or_missing_issuer(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_TEST_TOKEN_HASH_SECRET)

    async def scenario():
        service, _store = await _initialized_service_with_agent(identity)
        token = await service.issue_token("agent_test")
        payload = await _decode_service_token(identity, service, token)

        bad_issuer = dict(payload)
        bad_issuer["iss"] = "other-issuer"
        bad_token = await _encode_service_token(identity, service, bad_issuer)
        with pytest.raises(ValueError, match="Invalid token"):
            await service.validate_token(bad_token)

        missing_issuer = dict(payload)
        missing_issuer.pop("iss")
        missing_token = await _encode_service_token(
            identity,
            service,
            missing_issuer,
        )
        with pytest.raises(ValueError, match="Invalid token"):
            await service.validate_token(missing_token)

    run_async(scenario())


@pytest.mark.parametrize("environment", ["production", "prod"])
def test_identity_service_rejects_in_memory_key_vault_in_production(
    identity,
    monkeypatch,
    run_async,
    environment,
):
    monkeypatch.setenv("ENVIRONMENT", environment)
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_PRODUCTION_TOKEN_HASH_SECRET)

    async def scenario():
        store = identity.IdentityStore()
        vault = identity.KeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(store, vault, ca)

        with pytest.raises(RuntimeError, match="In-memory KeyVault"):
            await service.initialize()

    run_async(scenario())


@pytest.mark.parametrize("environment", ["demo", "test"])
def test_identity_service_allows_in_memory_key_vault_for_demo_and_tests(
    identity,
    monkeypatch,
    run_async,
    environment,
):
    monkeypatch.setenv("ENVIRONMENT", environment)
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_PRODUCTION_TOKEN_HASH_SECRET)

    async def scenario():
        store = identity.IdentityStore()
        vault = identity.KeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(store, vault, ca)

        await service.initialize()

        assert await vault.get_private_key(service.jwt_signing_key_id) is not None

    run_async(scenario())


def test_identity_service_allows_marked_key_provider_in_production(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_PRODUCTION_TOKEN_HASH_SECRET)

    class MarkedKeyVault(identity.KeyVault):
        is_production_key_provider = True

    class DurableIdentityStore(identity.IdentityStore):
        is_durable_production_store = True

    async def scenario():
        store = DurableIdentityStore()
        vault = MarkedKeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(store, vault, ca)

        await service.initialize()

        assert await vault.get_private_key(service.jwt_signing_key_id) is not None

    run_async(scenario())


def test_identity_service_rejects_in_memory_store_in_production(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_PRODUCTION_TOKEN_HASH_SECRET)

    class MarkedKeyVault(identity.KeyVault):
        is_production_key_provider = True

    async def scenario():
        store = identity.IdentityStore()
        vault = MarkedKeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(store, vault, ca)

        with pytest.raises(RuntimeError, match="durable identity store"):
            await service.initialize()

    run_async(scenario())


def test_identity_service_rejects_weak_token_hash_secret(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("TOKEN_HASH_SECRET", "short-secret")

    async def scenario():
        store = identity.IdentityStore()
        vault = identity.KeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(store, vault, ca)

        with pytest.raises(RuntimeError, match="at least 32 bytes"):
            await service.initialize()

    run_async(scenario())


def test_identity_service_rejects_demo_secret_outside_tests(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "TOKEN_HASH_SECRET",
        "demo-token-hash-secret-0123456789abcdef0123456789abcdef",
    )

    async def scenario():
        store = identity.IdentityStore()
        vault = identity.KeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(store, vault, ca)

        with pytest.raises(RuntimeError, match="demo/test/example"):
            await service.initialize()

    run_async(scenario())


def test_identity_store_prunes_terminal_delegation_records(
    identity,
    run_async,
):
    async def scenario():
        now = datetime.now(timezone.utc)
        store = identity.IdentityStore(
            max_delegation_records=10,
            terminal_delegation_retention_hours=0,
        )

        await store.store_delegation(
            _delegation_record(
                identity,
                "expired",
                expires_at=now - timedelta(seconds=1),
            )
        )
        await store.store_delegation(
            _delegation_record(
                identity,
                "revoked",
                is_revoked=True,
                revoked_at=now - timedelta(seconds=1),
            )
        )
        await store.store_delegation(
            _delegation_record(
                identity,
                "used-up",
                used_count=1,
                max_uses=1,
            )
        )

        assert await store.get_delegation("expired") is None
        assert await store.get_delegation("revoked") is None
        assert await store.get_delegation("used-up") is None

    run_async(scenario())


def test_identity_store_caps_active_delegation_records(identity, run_async):
    async def scenario():
        now = datetime.now(timezone.utc)
        store = identity.IdentityStore(max_delegation_records=2)

        await store.store_delegation(
            _delegation_record(identity, "first", expires_at=now + timedelta(hours=1))
        )
        await store.store_delegation(
            _delegation_record(identity, "second", expires_at=now + timedelta(hours=2))
        )
        await store.store_delegation(
            _delegation_record(identity, "third", expires_at=now + timedelta(hours=3))
        )

        assert len(store._delegations) == 2
        assert await store.get_delegation("first") is None
        assert await store.get_delegation("second") is not None
        assert await store.get_delegation("third") is not None

    run_async(scenario())


def test_identity_store_prunes_delegation_after_final_use(identity, run_async):
    async def scenario():
        store = identity.IdentityStore()
        await store.store_delegation(
            _delegation_record(identity, "single-use", max_uses=1)
        )

        consumed = await store.consume_delegation_use("single-use")

        assert consumed.used_count == 1
        assert await store.get_delegation("single-use") is None

    run_async(scenario())


def test_create_delegation_requires_delegable_scope_claim_and_audits_denial(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_TEST_TOKEN_HASH_SECRET)

    async def scenario():
        service, store = await _initialized_service_with_agent(identity)
        human_claims = {
            "sub": "human-1",
            "email": "human@example.com",
            "name": "Human One",
            "delegable_scopes": [identity.PermissionScope.DATA_READ.value],
        }

        with pytest.raises(PermissionError, match="not authorized"):
            await service.create_delegation(
                human_claims,
                "agent_test",
                [identity.PermissionScope.DATA_WRITE],
                correlation_id="corr-denied",
            )

        token = await service.create_delegation(
            human_claims,
            "agent_test",
            [identity.PermissionScope.DATA_READ],
        )
        payload = await _decode_service_token(identity, service, token)
        assert payload["scopes"] == [identity.PermissionScope.DATA_READ.value]

        denials = await store.query_audit_log(
            event_type=identity.AuditEventType.DELEGATION_REJECTED,
            limit=10,
        )
        assert len(denials) == 1
        denial = denials[0]
        assert denial.outcome == "denied"
        assert denial.details["reason"] == "human_scope_not_delegable"
        assert denial.details["missing_scopes"] == [
            identity.PermissionScope.DATA_WRITE.value
        ]
        assert denial.correlation_id == "corr-denied"

    run_async(scenario())


def test_validate_delegation_rejections_are_audited(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_TEST_TOKEN_HASH_SECRET)

    async def scenario():
        service, store = await _initialized_service_with_agent(identity)
        human_claims = {
            "sub": "human-1",
            "email": "human@example.com",
            "name": "Human One",
            "delegable_scopes": [
                identity.PermissionScope.DATA_READ.value,
                identity.PermissionScope.DATA_WRITE.value,
            ],
        }

        insufficient_token = await service.create_delegation(
            human_claims,
            "agent_test",
            [identity.PermissionScope.DATA_READ],
        )
        with pytest.raises(PermissionError, match="does not include scope"):
            await service.validate_delegation(
                insufficient_token,
                required_scope=identity.PermissionScope.DATA_WRITE,
            )

        missing_token = await service.create_delegation(
            human_claims,
            "agent_test",
            [identity.PermissionScope.DATA_READ],
        )
        missing_payload = await _decode_service_token(
            identity,
            service,
            missing_token,
        )
        store._delegations.pop(missing_payload["del_id"])
        with pytest.raises(ValueError, match="not found"):
            await service.validate_delegation(missing_token)

        revoked_token = await service.create_delegation(
            human_claims,
            "agent_test",
            [identity.PermissionScope.DATA_READ],
        )
        revoked_payload = await _decode_service_token(
            identity,
            service,
            revoked_token,
        )
        revoked = await store.get_delegation(revoked_payload["del_id"])
        assert revoked is not None
        revoked.is_revoked = True
        revoked.revoked_at = datetime.now(timezone.utc)
        await store.store_delegation(revoked)
        with pytest.raises(ValueError, match="revoked"):
            await service.validate_delegation(revoked_token)

        now = datetime.now(timezone.utc)
        expired_token = await _encode_service_token(
            identity,
            service,
            {
                "type": "delegation",
                "del_id": "expired-delegation",
                "human_sub": "human-1",
                "human_email": "human@example.com",
                "agent_id": "agent_test",
                "scopes": [identity.PermissionScope.DATA_READ.value],
                "iat": int((now - timedelta(hours=2)).timestamp()),
                "exp": int((now - timedelta(hours=1)).timestamp()),
                "iss": "agent-identity-service",
                "aud": "agent-platform",
            },
        )
        with pytest.raises(ValueError, match="expired"):
            await service.validate_delegation(expired_token)

        with pytest.raises(ValueError, match="Invalid delegation"):
            await service.validate_delegation("not-a-jwt")

        wrong_issuer_token = await service.create_delegation(
            human_claims,
            "agent_test",
            [identity.PermissionScope.DATA_READ],
        )
        wrong_issuer_payload = await _decode_service_token(
            identity,
            service,
            wrong_issuer_token,
        )
        wrong_issuer_payload["iss"] = "other-issuer"
        wrong_issuer_token = await _encode_service_token(
            identity,
            service,
            wrong_issuer_payload,
        )
        with pytest.raises(ValueError, match="Invalid delegation"):
            await service.validate_delegation(wrong_issuer_token)

        denials = await store.query_audit_log(
            event_type=identity.AuditEventType.DELEGATION_REJECTED,
            limit=20,
        )
        reasons = [event.details["reason"] for event in denials]
        for reason in [
            "insufficient_scope",
            "missing",
            "revoked",
            "expired",
            "invalid",
        ]:
            assert reason in reasons

    run_async(scenario())


def test_trade_executor_requires_trading_scope_on_delegation(
    identity,
    monkeypatch,
    run_async,
):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("TOKEN_HASH_SECRET", STRONG_TEST_TOKEN_HASH_SECRET)

    async def scenario():
        service, store = await _initialized_service_with_agent(
            identity,
            permissions=[
                identity.PermissionScope.DATA_READ,
                "orders:execute",
            ],
        )
        agent_token = await service.issue_token("agent_test")
        delegation_token = await service.create_delegation(
            {
                "sub": "human-1",
                "email": "human@example.com",
                "name": "Human One",
                "delegable_scopes": [identity.PermissionScope.DATA_READ.value],
            },
            "agent_test",
            [identity.PermissionScope.DATA_READ],
        )

        request = identity.TradeRequest(
            trade_id="trade-scope-regression",
            agent_id="agent_test",
            agent_token=agent_token,
            delegation_token=delegation_token,
            symbol="AAPL",
            side="buy",
            quantity=10,
            price=100.00,
            order_type="market",
        )

        executor = identity.TradeExecutor(service, store)
        with pytest.raises(PermissionError, match="orders:execute"):
            await executor.execute_trade(request)

        denials = await store.query_audit_log(
            event_type=identity.AuditEventType.DELEGATION_REJECTED,
            limit=10,
        )
        assert denials[-1].details["reason"] == "insufficient_scope"
        assert denials[-1].details["required"] == "orders:execute"

    run_async(scenario())


def test_compliance_reporter_collects_all_identity_and_audit_pages(
    identity,
    run_async,
):
    async def scenario():
        store = identity.IdentityStore(audit_log_capacity=1000)
        vault = identity.KeyVault()
        ca = identity.CertificateAuthority(vault, store)
        service = identity.AgentIdentityService(store, vault, ca)

        now = datetime.now(timezone.utc)
        for index in range(125):
            await store.create_identity(
                _identity_record(identity, agent_id=f"agent-{index:03d}")
            )

        for index in range(110):
            await store.log_audit_event(
                _service_audit_event(
                    identity,
                    f"permission-{index:03d}",
                    identity.AuditEventType.PERMISSION_GRANTED,
                    now,
                )
            )

        for index in range(115):
            await store.log_audit_event(
                _service_audit_event(
                    identity,
                    f"lifecycle-{index:03d}",
                    identity.AuditEventType.IDENTITY_CREATED,
                    now,
                )
            )

        reporter = identity.ComplianceReporter(service)
        report = await reporter.generate_access_review(
            period_start=now - timedelta(seconds=1),
            period_end=now + timedelta(seconds=1),
        )

        assert report["summary"]["total_agents"] == 125
        assert report["summary"]["active_agents"] == 125
        assert report["summary"]["permission_changes"] == 110
        assert report["summary"]["lifecycle_changes"] == 115
        assert len(report["agents"]) == 125
        assert len(report["permission_changes"]) == 110
        assert len(report["lifecycle_changes"]) == 115

    run_async(scenario())


def test_compliance_audit_append_uses_tail_record(
    identity,
    monkeypatch,
    tmp_path,
    run_async,
):
    async def scenario():
        store = identity.ComplianceAuditStore(tmp_path / "audit.jsonl")
        first_hash = await store.append(_audit_event(identity, "event-1"))

        tail_reads = 0
        original_read_last_record = store._read_last_record

        def spy_read_last_record():
            nonlocal tail_reads
            tail_reads += 1
            return original_read_last_record()

        monkeypatch.setattr(store, "_read_last_record", spy_read_last_record)
        second_hash = await store.append(_audit_event(identity, "event-2"))

        assert tail_reads == 1
        assert second_hash != first_hash
        valid, issues = await store.verify_integrity()
        assert valid is True
        assert issues == []

    run_async(scenario())
