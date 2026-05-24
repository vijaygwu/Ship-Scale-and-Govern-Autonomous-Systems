"""Regression tests for the production trip-wires added in Round 5.

Two independent guards protect against deploying the pedagogical
in-memory implementation under ``AGENT_ENV=production``:

1. **Module-load**: ``identity._check_internal_network()`` runs at import
   time and refuses the module load if ``INTERNAL_NETWORK`` is empty
   under production. Tests must therefore import the module under
   ``AGENT_ENV != "production"`` and flip the env var afterwards.

2. **Instantiate-time**: ``KeyVault.__init__`` re-reads ``AGENT_ENV`` on
   every instantiation and refuses the in-memory demo provider under
   production. Subclasses that set ``is_production_key_provider = True``
   bypass this check, so production deployments can still build on top.

The tests below exercise both fire-paths and both safe-paths to lock in
the layered-defense invariant.
"""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

CODE_ROOT = Path(__file__).resolve().parent.parent
IDENTITY_DIR = CODE_ROOT / "ch01-enterprise-identity"


def _run_isolated(env_overrides: dict[str, str], py_snippet: str) -> subprocess.CompletedProcess:
    """Run a Python snippet in a fresh subprocess with the given env.

    A fresh subprocess is necessary because Python caches modules in
    ``sys.modules``; once ``identity`` has been imported under one env,
    a second import in the same process reuses the cached module and
    never re-runs ``_check_internal_network``.
    """
    env = os.environ.copy()
    env.pop("AGENT_ENV", None)  # clean slate
    env.update(env_overrides)
    env["PYTHONPATH"] = f"{IDENTITY_DIR}:{CODE_ROOT}:" + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", py_snippet],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )


# ---------------------------------------------------------------------------
# Guard 1: module-load INTERNAL_NETWORK check
# ---------------------------------------------------------------------------


def test_module_load_refuses_empty_internal_network_in_production():
    """AGENT_ENV=production with empty INTERNAL_NETWORK must raise on import."""
    result = _run_isolated(
        {"AGENT_ENV": "production"},
        "import identity; print('NO_RAISE')",
    )
    assert result.returncode != 0, (
        f"identity import should have raised under AGENT_ENV=production with "
        f"empty INTERNAL_NETWORK. stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "INTERNAL_NETWORK" in result.stderr, (
        f"RuntimeError should reference INTERNAL_NETWORK. stderr={result.stderr!r}"
    )
    assert "production" in result.stderr.lower()


def test_module_load_succeeds_in_dev():
    """AGENT_ENV=dev with empty INTERNAL_NETWORK must import cleanly."""
    result = _run_isolated(
        {"AGENT_ENV": "dev"},
        "import identity; print('OK')",
    )
    assert result.returncode == 0, f"identity import failed in dev: {result.stderr!r}"
    assert "OK" in result.stdout


def test_module_load_succeeds_when_agent_env_unset():
    """No AGENT_ENV set must default to safe (the empty-INTERNAL_NETWORK guard
    only fires under production)."""
    result = _run_isolated({}, "import identity; print('OK')")
    assert result.returncode == 0, f"identity import failed with unset env: {result.stderr!r}"
    assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# Guard 2: KeyVault instantiation check
# ---------------------------------------------------------------------------


@pytest.fixture
def identity_mod():
    """Load identity under AGENT_ENV=dev so the module-load guard does not
    fire. Tests then flip ``AGENT_ENV`` per-test to exercise the
    instantiation-time guard."""
    saved = os.environ.get("AGENT_ENV")
    os.environ["AGENT_ENV"] = "dev"
    sys.modules.pop("identity", None)
    if str(IDENTITY_DIR) not in sys.path:
        sys.path.insert(0, str(IDENTITY_DIR))
    mod = importlib.import_module("identity")
    yield mod
    sys.modules.pop("identity", None)
    if saved is None:
        os.environ.pop("AGENT_ENV", None)
    else:
        os.environ["AGENT_ENV"] = saved


def test_keyvault_refuses_in_memory_demo_under_production(identity_mod, monkeypatch):
    """The default-constructed KeyVault is the in-memory demo provider;
    under AGENT_ENV=production it must raise RuntimeError."""
    monkeypatch.setenv("AGENT_ENV", "production")
    with pytest.raises(RuntimeError) as exc_info:
        identity_mod.KeyVault()
    assert "In-memory KeyVault refused in production" in str(exc_info.value)


def test_keyvault_succeeds_under_dev(identity_mod, monkeypatch):
    """The default-constructed KeyVault must succeed under AGENT_ENV=dev."""
    monkeypatch.setenv("AGENT_ENV", "dev")
    kv = identity_mod.KeyVault()
    assert kv is not None
    # Confirm the safety flags are wired as expected
    assert kv.is_in_memory_demo_provider is True
    assert kv.is_production_key_provider is False


def test_keyvault_subclass_marked_production_safe_succeeds(identity_mod, monkeypatch):
    """A subclass that sets is_production_key_provider=True (e.g. an HSM- or
    KMS-backed implementation) must construct cleanly under production."""

    class HSMBackedKeyVault(identity_mod.KeyVault):
        is_production_key_provider = True

    monkeypatch.setenv("AGENT_ENV", "production")
    kv = HSMBackedKeyVault()
    assert kv.is_production_key_provider is True
