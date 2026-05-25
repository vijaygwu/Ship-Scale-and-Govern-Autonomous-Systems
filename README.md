# Agentic AI in Production

**Companion Code Repository**

*Ship, Scale, and Govern Autonomous Systems*

by Dr. Vijay Raghavan

**Repository:** [github.com/vijaygwu/Ship-Scale-and-Govern-Autonomous-Systems](https://github.com/vijaygwu/Ship-Scale-and-Govern-Autonomous-Systems)

---

## About This Repository

This repository contains the code listings from *Agentic AI in Production: Ship, Scale, and Govern Autonomous Systems* (Book 2 of the Agentic AI Series). Each chapter has its own directory; inside is a single Python module that reproduces every code listing from that chapter in book order, with section banners showing the block number.

The code in this repository is a **faithful extraction** of the in-book listings. Some listings define classes and functions that build incrementally across the chapter; others are illustrative fragments (log output, file trees, Dockerfile snippets, JSON examples) that have been preserved as docstrings so the chapter file always remains valid Python. To run a particular component, copy the relevant class or function into your own project and provide surrounding context (imports, dependencies, configuration) as needed.

If you are looking for the design-pattern foundations (Orchestrator, Council, Swarm, Guardian, Hybrid) used by these production examples, see the companion repository for Book 1: [github.com/vijaygwu/Agent-Architectures](https://github.com/vijaygwu/Agent-Architectures).

## Status

This repository corresponds to *Agentic AI in Production* round 23 of `/book-eval6` (the parent manuscript's multi-reviewer publication-readiness gauntlet). The manuscript was declared `PUBLICATION_READY` at round 14 and has held that status across most subsequent rounds, with the score average hovering in a stable 4.55–4.69 band (rounds 13–23). The code in this repository carries the matching tag `book-2-r14-publication-ready`.

**Test suite: 156 passing.** This includes:

- Per-chapter regression tests (`tests/test_ch01_identity.py` through `tests/test_ch08_testing.py`)
- **Production trip-wire regression tests** (`tests/test_production_guards.py`): subprocess-isolated verification that `identity._check_internal_network()` raises under `AGENT_ENV=production` with empty `INTERNAL_NETWORK`, and that `KeyVault` refuses the in-memory demo provider in production
- **LaTeX-leak regression tests** (`tests/test_no_latex_leaks.py`): scans every `.py` file in this repository for 21 forbidden LaTeX commands (`\cite{}`, `\textbf{}`, `\ref{}`, stray `\\` escapes, etc.) that would leak through into the chapter listing PDF

Across 23 evaluation rounds, ~370 fixes have landed across the manuscript and this companion code. Recent rounds added: deterministic HMAC-SHA256 tokens in `PIITokenizer` (replaces the prior LRU-evicting random tokens so audit consistency survives long observation windows), bounded `Agent.conversation_history` (was unbounded across `run()` invocations), separate unbounded `MockLLM._total_call_count` for trigger comparisons, audit DLQ eviction Prometheus hooks, per-sink chain auto-recovery with operator-callable reset, rate-limited fall-through warnings, full-jitter audit retry backoff with proper scaling, and tracked uncancelable `RetryPolicy` futures with `ExecutorSaturatedError` backpressure.

## Book Overview

*Agentic AI in Production* covers the governance and operations work required to run autonomous AI systems where mistakes have consequences. Part I establishes enterprise-grade control (identity, secrets, rate limits, audit). Part II makes systems observable and reliable (deployment, monitoring, error handling, testing).

## Repository Layout

```
book-2/code/
├── ch01-enterprise-identity/    # X.509, OIDC delegation, zero-trust
│   └── identity.py
├── ch02-api-keys/               # Vault, AWS/Azure secrets, rotation, JIT
│   └── secrets.py
├── ch03-rate-limits/            # Token buckets, budgets, graceful degradation
│   └── rate_limits.py
├── ch04-audit-trails/           # Tamper-evident chains, PII tokenization
│   └── audit.py
├── ch05-deployment/             # Blue/green, canary, K8s, feature flags
│   └── deployment.py
├── ch06-monitoring/             # OpenTelemetry, agent-specific metrics, anomaly detection
│   └── monitoring.py
├── ch07-error-handling/         # Retries, circuit breakers, fallback chains, DLQs
│   └── error_handling.py
├── ch08-testing/                # MockLLM, behavioral evaluators, adversarial tests
│   ├── scenarios/
│   │   └── customer_support.yaml
│   └── testing.py
├── tests/                       # Companion regression tests for chapter listings
├── pyproject.toml               # Pytest markers and local test configuration
├── requirements-dev.txt
├── requirements.txt
├── .gitignore
└── README.md
```

## Chapter Code

| Chapter | Topic | Module |
|---|---|---|
| 1 | Enterprise Identity and Authentication | [`ch01-enterprise-identity/identity.py`](ch01-enterprise-identity/identity.py) |
| 2 | API Keys and Secrets Management | [`ch02-api-keys/secrets.py`](ch02-api-keys/secrets.py) |
| 3 | Rate Limiting and Cost Control | [`ch03-rate-limits/rate_limits.py`](ch03-rate-limits/rate_limits.py) |
| 4 | Audit Trails and Compliance | [`ch04-audit-trails/audit.py`](ch04-audit-trails/audit.py) |
| 5 | Agent Deployment Strategies | [`ch05-deployment/deployment.py`](ch05-deployment/deployment.py) |
| 6 | Monitoring and Observability | [`ch06-monitoring/monitoring.py`](ch06-monitoring/monitoring.py) |
| 7 | Error Handling and Resilience | [`ch07-error-handling/error_handling.py`](ch07-error-handling/error_handling.py) |
| 8 | Testing Agent Systems | [`ch08-testing/testing.py`](ch08-testing/testing.py) |

## Getting Started

```bash
# Clone the repository
git clone https://github.com/vijaygwu/Ship-Scale-and-Govern-Autonomous-Systems.git
cd Ship-Scale-and-Govern-Autonomous-Systems

# Create a virtual environment (Python 3.11+ recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Open any chapter module and read top-to-bottom alongside the book
$EDITOR ch01-enterprise-identity/identity.py

# Run the companion regression suite
python -m pytest tests
```

Each chapter module is a valid, parseable Python file. Most blocks are runnable Python that builds incrementally through the chapter; the runnable blocks compile standalone but may reference external services (Vault, AWS Secrets Manager, Redis, Anthropic API). Provide credentials and infrastructure as appropriate when running.

The test suite exercises the extracted listings as companion examples. Optional integration examples are guarded with skips when project-specific tools or services are not configured, so a local checkout can still validate the core examples without provisioning every external dependency.

## Conventions

- **Block banners**: Each listing is preceded by a banner showing its sequential position in the file (`Block N`) and the corresponding listing number from the chapter.
- **Wrapped listings**: Blocks that are not standalone Python (log samples, Dockerfile snippets, JSON examples, etc.) are wrapped in raw docstrings and labelled with a reason — they preserve the book content verbatim but are not meant to execute.
- **Future imports**: `from __future__ import annotations` is hoisted to the top of each file when used anywhere in the chapter.

## Runtime Notes

- Chapter 3's `TokenBucket.wait_for_capacity()` uses a bounded default wait. Pass `timeout=None` only when an intentionally unbounded wait is acceptable for the caller.
- Chapter 5's canary deployment flow cancels and awaits its external monitor task during cleanup, which avoids leaking a background coroutine after promotion or rollback.
- Chapter 8's sample `Agent.run(timeout=...)` enforces the timeout through the model/tool loop and forwards the remaining time to the mock LLM. The packaged `ch08-testing/scenarios/customer_support.yaml` file supports the behavioral harness examples.

## Infrastructure Companion (Forthcoming)

The book preface describes a forthcoming infrastructure bundle — Docker Compose for local Vault/Redis/Prometheus/Grafana, sample Grafana dashboards, and Prometheus alerting rules. These are not yet in this repository and will be added as a separate top-level directory in a future release.

## Compatibility

- **Python**: 3.11 or higher (uses modern type hints, `match` statements, and async/await throughout)
- **External services** referenced in the code (provide your own or mock them):
  - Anthropic API (`anthropic`)
  - HashiCorp Vault (`hvac`)
  - AWS Secrets Manager / KMS (`boto3`)
  - Redis (`redis`)
  - PostgreSQL or SQLite (`sqlalchemy`)
  - OpenTelemetry collector
  - Prometheus

## Errata

Code in this repository corresponds to the manuscript as of the date the repository was last refreshed. If you find a discrepancy with the published book, open an issue.

## License

MIT — see `LICENSE` (to be added).

---

*Part of the Agentic AI Series. See also: [Book 1: Agent Architectures](https://github.com/vijaygwu/Agent-Architectures) and Book 3: Scaling and Applying Autonomous Systems (forthcoming).*
