# Agentic AI in Production

**Companion Code Repository**

*Ship, Scale, and Govern Autonomous Systems*

by Dr. Vijay Raghavan

---

## About This Repository

This repository contains the code listings from *Agentic AI in Production: Ship, Scale, and Govern Autonomous Systems* (Book 2 of the Agentic AI Series). Each chapter has its own directory; inside is a single Python module that reproduces every code listing from that chapter in book order, with section banners showing the block number.

The code in this repository is a **faithful extraction** of the in-book listings. Some listings define classes and functions that build incrementally across the chapter; others are illustrative fragments (log output, file trees, Dockerfile snippets, JSON examples) that have been preserved as docstrings so the chapter file always remains valid Python. To run a particular component, copy the relevant class or function into your own project and provide surrounding context (imports, dependencies, configuration) as needed.

If you are looking for the design-pattern foundations (Orchestrator, Council, Swarm, Guardian, Hybrid) used by these production examples, see the companion repository for Book 1: [github.com/vijaygwu/Agent-Architectures](https://github.com/vijaygwu/Agent-Architectures).

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
│   └── testing.py
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
git clone <your-fork-url> agentic-ai-production-code
cd agentic-ai-production-code

# Create a virtual environment (Python 3.11+ recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Open any chapter module and read top-to-bottom alongside the book
$EDITOR ch01-enterprise-identity/identity.py
```

Each chapter module is a valid, parseable Python file. Most blocks are runnable Python that builds incrementally through the chapter; the runnable blocks compile standalone but may reference external services (Vault, AWS Secrets Manager, Redis, Anthropic API). Provide credentials and infrastructure as appropriate when running.

## Conventions

- **Block banners**: Each listing is preceded by a banner showing its sequential position in the file (`Block N`) and the corresponding listing number from the chapter.
- **Wrapped listings**: Blocks that are not standalone Python (log samples, Dockerfile snippets, JSON examples, etc.) are wrapped in raw docstrings and labelled with a reason — they preserve the book content verbatim but are not meant to execute.
- **Future imports**: `from __future__ import annotations` is hoisted to the top of each file when used anywhere in the chapter.

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
