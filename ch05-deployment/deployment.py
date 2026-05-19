"""
Agent Deployment Strategies

Code listings from Chapter 05, Book 2:
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

# serverless_agent.py
"""
AWS Lambda handler for a customer inquiry routing agent.
Designed for quick classification tasks that complete within seconds.
"""

import json
import logging
import os
from typing import Any
import boto3
from anthropic import Anthropic

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# Lazy-initialized resources. We deliberately avoid touching
# os.environ["ANTHROPIC_API_KEY"] at module import time: a missing env var
# would otherwise crash the Lambda cold-start before logger emits anything,
# leaving the operator with an opaque init failure. Instead we surface a
# clean RuntimeError on the first call so CloudWatch shows the cause.
_anthropic_client: Anthropic | None = None
_metrics_table = None


def _get_anthropic_client() -> Anthropic:
    """Return a process-cached Anthropic client; raise if API key missing."""
    global _anthropic_client
    if _anthropic_client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set; the Lambda must be deployed "
                "with this environment variable bound to a Secrets Manager "
                "reference or KMS-encrypted parameter."
            )
        _anthropic_client = Anthropic(api_key=api_key)
    return _anthropic_client


def _get_metrics_table():
    """Return the DynamoDB metrics table, lazy-initialized on first call."""
    global _metrics_table
    if _metrics_table is None:
        table_name = os.environ.get("METRICS_TABLE")
        if not table_name:
            raise RuntimeError("METRICS_TABLE env var is not set.")
        _metrics_table = boto3.resource("dynamodb").Table(table_name)
    return _metrics_table


class InquiryRouter:
    """Routes customer inquiries to appropriate handling queues."""
    
    ROUTING_PROMPT = """You are a customer inquiry routing assistant. 
    Analyze the inquiry and determine the appropriate department.
    
    Departments:
    - billing: Payment issues, invoices, refunds
    - technical: Product bugs, integration help, API questions
    - sales: Pricing, upgrades, enterprise inquiries
    - general: Everything else
    
    Respond with JSON: {"department": "...", "priority": "low|medium|high", "reasoning": "..."}
    """
    
    def __init__(self, client: Anthropic):
        self.client = client
    
    def route(self, inquiry: str, customer_tier: str) -> dict[str, Any]:
        """Classify inquiry and determine routing with priority adjustment."""
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=256,
            messages=[
                {"role": "user", "content": f"Customer tier: {customer_tier}\n\nInquiry: {inquiry}"}
            ],
            system=self.ROUTING_PROMPT
        )
        
        # LLM output is not guaranteed to be valid JSON. Parse defensively
        # and fall back to a safe default rather than 500-ing the request.
        try:
            parsed = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            logger.warning(
                "Model returned non-JSON: %s", response.content[0].text
            )
            return {
                "department": "general",
                "priority": "medium",
                "reasoning": "fallback: invalid model output",
            }
        # Validate required keys with defaults rather than KeyError on access.
        result = {
            "department": parsed.get("department", "general"),
            "priority": parsed.get("priority", "medium"),
            "reasoning": parsed.get("reasoning", ""),
        }

        # Enterprise customers get priority boost
        if customer_tier == "enterprise" and result["priority"] == "low":
            result["priority"] = "medium"

        return result


def lambda_handler(event: dict, context: Any) -> dict:
    """
    Lambda entry point for inquiry routing.
    
    Expected event structure:
    {
        "inquiry": "Customer message text",
        "customer_id": "cust_123",
        "customer_tier": "standard|premium|enterprise"
    }
    """
    try:
        inquiry = event["inquiry"]
        customer_id = event["customer_id"]
        customer_tier = event.get("customer_tier", "standard")
        
        router = InquiryRouter(_get_anthropic_client())
        result = router.route(inquiry, customer_tier)

        # Record metrics for monitoring. Best-effort: a slow or unavailable
        # DynamoDB endpoint must not extend Lambda duration or fail the
        # routing response that has already been computed. We log and
        # proceed; the metrics gap will surface in the dashboards.
        try:
            _get_metrics_table().put_item(Item={
                "request_id": context.aws_request_id,
                "customer_id": customer_id,
                "department": result["department"],
                "priority": result["priority"],
                "remaining_time_ms": context.get_remaining_time_in_millis()
            })
        except Exception as metrics_err:
            logger.warning(
                "Metrics write failed for request %s: %s",
                context.aws_request_id, metrics_err,
            )
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "routing": result,
                "request_id": context.aws_request_id
            })
        }
        
    except KeyError as e:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Missing required field: {e}"})
        }
    except Exception as e:
        # Outer safety net at the Lambda boundary: any unhandled exception
        # is logged with full traceback and reported to the caller as a
        # generic 500. The broad catch is deliberate; without it the
        # runtime would surface internal stack frames to the API caller.
        logger.exception("Error processing request")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal processing error"})
        }

# ============================================================================
# Block 2 (chapter block #2) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_2_listing = r"""
# Multi-stage build to minimize final image size

# Stage 1: Build dependencies
FROM python:3.11-slim as builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production image
FROM python:3.11-slim as production

# Security: Run as non-root user
RUN groupadd --gid 1000 agent && \
    useradd --uid 1000 --gid agent --shell /bin/bash --create-home agent

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=agent:agent src/ ./src/
# Bake non-secret config into the image; mount tenant-specific or rotating
# config at runtime instead of COPYing it. With readOnlyRootFilesystem=true
# (recommended in the manifest below), writable paths must be backed by an
# explicit volume (e.g., an emptyDir mount at /tmp).
COPY --chown=agent:agent config/ ./config/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Switch to non-root user
USER agent

EXPOSE 8080

CMD ["python", "-m", "src.main"]
"""

# ============================================================================
# Block 3 (chapter block #3) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_3_listing = r"""
# requirements.txt

anthropic==0.39.0
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
httpx==0.26.0
structlog==24.1.0
prometheus-client==0.19.0
redis==5.0.1
tenacity==8.2.3
"""

# ============================================================================
# Block 4 (chapter block #4) — Python fragment (incomplete, depends on surrounding context)
# Preserved verbatim from the book. Not standalone-runnable.
# ============================================================================

_block_4_listing = r"""
# terraform/main.tf
# Infrastructure for VM-based agent deployment

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "c6i.xlarge"
}

resource "aws_launch_template" "agent" {
  name_prefix   = "agent-${var.environment}-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.agent.name
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.agent.id]
  }

  user_data = base64encode(templatefile("${path.module}/userdata.sh", {
    environment = var.environment
    region      = data.aws_region.current.name
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "agent-${var.environment}"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

resource "aws_autoscaling_group" "agent" {
  name                = "agent-${var.environment}"
  desired_capacity    = 3
  max_size            = 10
  min_size            = 2
  target_group_arns   = [aws_lb_target_group.agent.arn]
  vpc_zone_identifier = data.aws_subnets.private.ids

  launch_template {
    id      = aws_launch_template.agent.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 75
    }
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
}
"""

# ============================================================================
# Block 5 (chapter listing #5)
# ============================================================================

# scripts/blue_green_deploy.py
"""
Blue-green deployment orchestrator for agent systems.
Handles traffic switching and validation between environments.
"""

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class DeploymentConfig:
    """Configuration for blue-green deployment."""
    namespace: str
    service_name: str
    blue_deployment: str
    green_deployment: str
    health_endpoint: str
    validation_endpoint: str
    validation_timeout: int = 300
    health_check_interval: int = 5
    # Time to wait after cutover before scaling down the old color.
    # Tune this per workload; some agents need much longer than 60s to
    # drain in-flight requests. For best results, poll for zero in-flight
    # via metrics instead of sleeping.
    stabilization_seconds: int = 60


class BlueGreenDeployer:
    """Orchestrates blue-green deployments with validation."""

    def __init__(self, config: DeploymentConfig):
        self.config = config
        self.client = httpx.Client(timeout=30.0)

    # Make the deployer usable as a context manager so callers can ensure
    # the underlying HTTP connection pool is closed deterministically:
    #     with BlueGreenDeployer(cfg) as deployer:
    #         deployer.deploy(...)
    def __enter__(self) -> "BlueGreenDeployer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.client.close()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self.client.close()
    
    def get_active_version(self) -> str:
        """Determine which version is currently receiving traffic."""
        # 30s is generous for a single read against the API server -- if it
        # takes longer, the cluster is unhealthy and we should not silently
        # block the deploy.
        try:
            result = subprocess.run(
                [
                    "kubectl", "get", "service", self.config.service_name,
                    "-n", self.config.namespace,
                    "-o", "jsonpath={.spec.selector.version}"
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"kubectl get service timed out after {e.timeout}s; "
                "API server may be unhealthy"
            ) from e
        return result.stdout.strip()
    
    def get_inactive_version(self) -> str:
        """Return the standby version."""
        active = self.get_active_version()
        return "green" if active == "blue" else "blue"
    
    def scale_deployment(self, version: str, replicas: int) -> None:
        """Scale a deployment to the specified replica count."""
        deployment = (
            self.config.blue_deployment if version == "blue"
            else self.config.green_deployment
        )
        # `kubectl scale` returns once the API accepts the change; it does not
        # wait for pods to become Ready. 30s is plenty for the write.
        try:
            subprocess.run(
                [
                    "kubectl", "scale", "deployment", deployment,
                    "-n", self.config.namespace,
                    f"--replicas={replicas}"
                ],
                check=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"kubectl scale {deployment} timed out after {e.timeout}s"
            ) from e
        print(f"Scaled {deployment} to {replicas} replicas")
    
    def wait_for_ready(self, version: str, timeout: int = 300) -> bool:
        """Wait for all pods in a deployment to be ready."""
        deployment = (
            self.config.blue_deployment if version == "blue"
            else self.config.green_deployment
        )
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            # Each `kubectl rollout status` invocation uses --timeout=10s
            # server-side, but we also wrap the subprocess in a hard 30s
            # wall-clock timeout so a hung client cannot wedge the loop. A
            # TimeoutExpired here is treated like any other non-zero exit:
            # log, back off, and retry on the next loop iteration.
            try:
                result = subprocess.run(
                    [
                        "kubectl", "rollout", "status", "deployment", deployment,
                        "-n", self.config.namespace,
                        "--timeout=10s"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    return True
            except subprocess.TimeoutExpired:
                print(
                    f"kubectl rollout status hung; retrying after "
                    f"{self.config.health_check_interval}s"
                )
            time.sleep(self.config.health_check_interval)

        return False
    
    def validate_deployment(self, endpoint: str) -> bool:
        """Run validation checks against the deployment."""
        try:
            response = self.client.get(endpoint)
            return response.status_code == 200
        except httpx.RequestError as e:
            print(f"Validation request failed: {e}")
            return False
    
    def switch_traffic(self, target_version: str) -> None:
        """Update service selector to route traffic to target version."""
        patch = f'{{"spec":{{"selector":{{"version":"{target_version}"}}}}}}'
        # Service patches are tiny, fast writes; 30s is a hard upper bound.
        try:
            subprocess.run(
                [
                    "kubectl", "patch", "service", self.config.service_name,
                    "-n", self.config.namespace,
                    "-p", patch
                ],
                check=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"kubectl patch service timed out after {e.timeout}s; "
                "traffic switch did not complete"
            ) from e
        print(f"Traffic switched to {target_version}")
    
    def deploy(self, new_image: str) -> bool:
        """
        Execute blue-green deployment.
        
        Returns True if deployment succeeded, False otherwise.
        """
        inactive = self.get_inactive_version()
        active = self.get_active_version()
        
        print(f"Current active: {active}, deploying to: {inactive}")
        
        # Update inactive deployment with new image
        deployment = (
            self.config.blue_deployment if inactive == "blue"
            else self.config.green_deployment
        )
        # `kubectl set image` is a pure write to the API server; it returns
        # before pods roll. 60s gives slow API servers headroom without
        # letting a totally hung client block the deploy indefinitely.
        try:
            subprocess.run(
                [
                    "kubectl", "set", "image", f"deployment/{deployment}",
                    f"agent={new_image}",
                    "-n", self.config.namespace
                ],
                check=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"kubectl set image timed out after {e.timeout}s"
            ) from e
        
        # Scale up inactive deployment
        self.scale_deployment(inactive, 3)
        
        # Wait for pods to be ready
        if not self.wait_for_ready(inactive):
            print("ERROR: Deployment failed to become ready")
            self.scale_deployment(inactive, 0)
            return False
        
        # Validate new deployment
        if not self.validate_deployment(self.config.validation_endpoint):
            print("ERROR: Validation failed")
            self.scale_deployment(inactive, 0)
            return False
        
        # Switch traffic
        self.switch_traffic(inactive)
        
        # Scale down old deployment after stabilization period. Configurable
        # so workloads with longer drain requirements can extend it without
        # editing the deployer. For best results, replace this sleep with a
        # poll against an in-flight-requests metric.
        time.sleep(self.config.stabilization_seconds)
        self.scale_deployment(active, 0)
        
        print("Deployment completed successfully")
        return True
    
    def rollback(self) -> None:
        """Immediately roll back to the previous version."""
        inactive = self.get_inactive_version()
        active = self.get_active_version()
        
        # Scale up previous deployment
        self.scale_deployment(inactive, 3)
        self.wait_for_ready(inactive)
        
        # Switch traffic back
        self.switch_traffic(inactive)
        
        # Scale down failed deployment
        self.scale_deployment(active, 0)
        
        print(f"Rolled back to {inactive}")


def main():
    parser = argparse.ArgumentParser(description="Blue-green deployment tool")
    parser.add_argument("--namespace", default="production")
    parser.add_argument("--image", required=True, help="New image to deploy")
    parser.add_argument("--rollback", action="store_true", help="Rollback to previous version")
    
    args = parser.parse_args()
    
    config = DeploymentConfig(
        namespace=args.namespace,
        service_name="customer-agent",
        blue_deployment="customer-agent-blue",
        green_deployment="customer-agent-green",
        health_endpoint="http://customer-agent.production/health/ready",
        validation_endpoint="http://customer-agent.production/validate"
    )
    
    deployer = BlueGreenDeployer(config)
    
    if args.rollback:
        deployer.rollback()
    else:
        success = deployer.deploy(args.image)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

# ============================================================================
# Block 6 (chapter listing #6)
# ============================================================================

# scripts/canary_controller.py
"""
Canary release controller with automated analysis and promotion.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

import httpx


class CanaryStatus(Enum):
    PROGRESSING = "progressing"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass
class CanaryStage:
    """Defines a canary release stage."""
    weight: int  # Percentage of traffic to canary
    duration_minutes: int  # Time to wait before analysis
    success_threshold: float  # Required success rate

    @property
    def duration_seconds(self) -> float:
        return self.duration_minutes * 60


@dataclass
class StageResult:
    """Outcome of running a single canary stage."""
    status: CanaryStatus
    reason: str = ""

    @classmethod
    def ok(cls) -> "StageResult":
        return cls(status=CanaryStatus.HEALTHY)

    @classmethod
    def aborted(cls, reason: str) -> "StageResult":
        return cls(status=CanaryStatus.FAILED, reason=reason)


@dataclass
class CanaryConfig:
    """Configuration for canary release."""
    stages: list[CanaryStage] = field(default_factory=lambda: [
        CanaryStage(weight=5, duration_minutes=10, success_threshold=0.99),
        CanaryStage(weight=25, duration_minutes=15, success_threshold=0.99),
        CanaryStage(weight=50, duration_minutes=20, success_threshold=0.98),
        CanaryStage(weight=100, duration_minutes=0, success_threshold=0.98),
    ])
    prometheus_url: str = "http://prometheus:9090"
    rollback_on_failure: bool = True


class CanaryAnalyzer:
    """Analyzes canary metrics to determine health."""
    
    def __init__(self, prometheus_url: str):
        self.prometheus_url = prometheus_url
        self.client = httpx.Client(timeout=30.0)
    
    def query_prometheus(self, query: str) -> float:
        """Execute a Prometheus query and return the result."""
        response = self.client.get(
            f"{self.prometheus_url}/api/v1/query",
            params={"query": query}
        )
        response.raise_for_status()
        data = response.json()
        
        if data["data"]["result"]:
            return float(data["data"]["result"][0]["value"][1])
        return 0.0
    
    def get_success_rate(self, version: str, window: str = "5m") -> float:
        """Calculate request success rate for a version."""
        success_query = f'''
            sum(rate(http_requests_total{{version="{version}",status=~"2.."}}[{window}]))
            /
            sum(rate(http_requests_total{{version="{version}"}}[{window}]))
        '''
        return self.query_prometheus(success_query)
    
    def get_latency_p99(self, version: str, window: str = "5m") -> float:
        """Get 99th percentile latency for a version."""
        latency_query = f'''
            histogram_quantile(0.99, 
                sum(rate(http_request_duration_seconds_bucket{{version="{version}"}}[{window}])) 
                by (le)
            )
        '''
        return self.query_prometheus(latency_query)
    
    def get_error_rate(self, version: str, window: str = "5m") -> float:
        """Calculate error rate for a version."""
        error_query = f'''
            sum(rate(http_requests_total{{version="{version}",status=~"5.."}}[{window}]))
            /
            sum(rate(http_requests_total{{version="{version}"}}[{window}]))
        '''
        return self.query_prometheus(error_query)
    
    def analyze(self, success_threshold: float) -> CanaryStatus:
        """
        Analyze canary health against thresholds.
        
        Compares canary metrics against stable baseline.
        """
        canary_success = self.get_success_rate("canary")
        stable_success = self.get_success_rate("stable")
        
        canary_latency = self.get_latency_p99("canary")
        stable_latency = self.get_latency_p99("stable")
        
        # Check absolute success rate
        if canary_success < success_threshold:
            return CanaryStatus.FAILED
        
        # Check relative degradation
        if stable_success > 0 and canary_success < stable_success * 0.95:
            return CanaryStatus.DEGRADED
        
        # Check latency regression: 20% is a placeholder default that should
        # be tuned to your SLO error budget. Different teams reasonably use
        # 5%, 10%, or 25% depending on customer sensitivity.
        if stable_latency > 0 and canary_latency > stable_latency * 1.2:
            return CanaryStatus.DEGRADED
        
        return CanaryStatus.HEALTHY


class CanaryController:
    """Controls canary release progression."""

    def __init__(
        self,
        config: CanaryConfig,
        analyzer: CanaryAnalyzer,
        traffic_manager: Callable[[int], None],
        rollback_handler: Callable[[], None],
    ):
        self.config = config
        self.analyzer = analyzer
        self.set_traffic_weight = traffic_manager
        self.rollback = rollback_handler
        self.current_stage = 0
        # External signal an operator (or a sibling monitor task) can
        # set to interrupt the running stage at the next poll boundary.
        self._abort_event = asyncio.Event()

    def abort(self) -> None:
        """Signal the running stage to stop at the next poll boundary."""
        self._abort_event.set()

    def _slo_check_passes(self, stage: CanaryStage) -> bool:
        """Re-evaluate canary health against the active stage's threshold."""
        status = self.analyzer.analyze(stage.success_threshold)
        return status not in (CanaryStatus.FAILED, CanaryStatus.DEGRADED)

    async def _run_stage(self, stage: CanaryStage) -> StageResult:
        """Run a canary stage; abort early on SLO violation or external signal."""
        deadline = time.monotonic() + stage.duration_seconds
        poll_interval = 5.0
        while time.monotonic() < deadline:
            if self._abort_event.is_set():
                return StageResult.aborted(reason="controller signal")
            remaining = deadline - time.monotonic()
            await asyncio.sleep(min(poll_interval, remaining))
            if not self._slo_check_passes(stage):
                self._abort_event.set()
                return StageResult.aborted(reason="SLO violation")
        return StageResult.ok()

    async def run(self) -> bool:
        """
        Execute canary release through all stages.

        Returns True if release completed successfully.
        """
        for i, stage in enumerate(self.config.stages):
            self.current_stage = i
            print(f"Stage {i + 1}: Setting canary weight to {stage.weight}%")
            self.set_traffic_weight(stage.weight)

            if stage.duration_seconds <= 0:
                continue

            print(f"Waiting {stage.duration_minutes} minutes for analysis...")
            result = await self._run_stage(stage)
            print(f"Stage result: {result.status.value} ({result.reason or 'ok'})")

            if result.status == CanaryStatus.FAILED:
                print(f"Canary aborted: {result.reason}")
                if self.config.rollback_on_failure:
                    self.rollback()
                return False

        print("Canary release completed successfully")
        return True

# ============================================================================
# Block 7 (chapter listing #7)
# ============================================================================

# scripts/canary_runner.py
async def external_monitor(controller: CanaryController) -> None:
    """Watch out-of-band signals and abort the canary if needed."""
    while True:
        await asyncio.sleep(5)
        if pager_fired() or error_budget_exhausted():
            controller.abort()
            return


async def main(controller: CanaryController) -> bool:
    # The controller's run() will return as soon as either:
    #   (a) all stages complete, or
    #   (b) any stage observes _abort_event being set.
    # The monitor task is cancelled once run() returns.
    run_task = asyncio.create_task(controller.run())
    monitor_task = asyncio.create_task(external_monitor(controller))
    try:
        return await run_task
    finally:
        monitor_task.cancel()

# ============================================================================
# Block 8 (chapter listing #8)
# ============================================================================

# src/features/feature_flags.py
"""
Feature flag system for agent capabilities.
Supports multiple backends and provides type-safe flag access.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Any, Optional
import hashlib
import json
import os

import httpx
import redis


class FlagType(Enum):
    BOOLEAN = "boolean"
    STRING = "string"
    INTEGER = "integer"
    PERCENTAGE = "percentage"
    JSON = "json"


@dataclass
class FeatureFlag:
    """Represents a feature flag with its configuration."""
    name: str
    flag_type: FlagType
    default_value: Any
    description: str = ""


class FlagBackend(ABC):
    """Abstract backend for feature flag storage."""
    
    @abstractmethod
    def get_flag(self, name: str) -> Optional[Any]:
        """Retrieve flag value from backend."""
        pass
    
    @abstractmethod
    def set_flag(self, name: str, value: Any) -> None:
        """Set flag value in backend."""
        pass


class EnvironmentBackend(FlagBackend):
    """Feature flags from environment variables."""
    
    def __init__(self, prefix: str = "FEATURE_"):
        self.prefix = prefix
    
    def get_flag(self, name: str) -> Optional[str]:
        env_name = f"{self.prefix}{name.upper()}"
        return os.environ.get(env_name)
    
    def set_flag(self, name: str, value: Any) -> None:
        env_name = f"{self.prefix}{name.upper()}"
        os.environ[env_name] = str(value)


class RedisBackend(FlagBackend):
    """Feature flags from Redis for dynamic updates."""
    
    def __init__(self, redis_url: str, prefix: str = "feature:"):
        self.client = redis.from_url(redis_url)
        self.prefix = prefix
    
    def get_flag(self, name: str) -> Optional[str]:
        key = f"{self.prefix}{name}"
        value = self.client.get(key)
        return value.decode() if value else None
    
    def set_flag(self, name: str, value: Any) -> None:
        key = f"{self.prefix}{name}"
        self.client.set(key, json.dumps(value) if isinstance(value, (dict, list)) else str(value))


class LaunchDarklyBackend(FlagBackend):
    """Feature flags from LaunchDarkly service."""
    
    def __init__(self, sdk_key: str):
        import ldclient
        from ldclient.config import Config
        
        ldclient.set_config(Config(sdk_key))
        self.client = ldclient.get()
    
    def get_flag(self, name: str, user_key: str = "default") -> Any:
        from ldclient import Context
        
        context = Context.builder(user_key).build()
        return self.client.variation(name, context, None)
    
    def set_flag(self, name: str, value: Any) -> None:
        raise NotImplementedError("LaunchDarkly flags are managed via dashboard")


class FeatureFlagManager:
    """
    Manages feature flags with type coercion and caching.
    
    Supports percentage-based rollouts and user targeting.
    """
    
    # Define available flags
    FLAGS = {
        "advanced_reasoning": FeatureFlag(
            name="advanced_reasoning",
            flag_type=FlagType.BOOLEAN,
            default_value=True,
            description="Enable multi-step reasoning chains"
        ),
        "multimodal_input": FeatureFlag(
            name="multimodal_input",
            flag_type=FlagType.BOOLEAN,
            default_value=False,
            description="Accept image inputs"
        ),
        "max_tool_calls": FeatureFlag(
            name="max_tool_calls",
            flag_type=FlagType.INTEGER,
            default_value=10,
            description="Maximum tool calls per request"
        ),
        "model_version": FeatureFlag(
            name="model_version",
            flag_type=FlagType.STRING,
            default_value="claude-sonnet-4-20250514",
            description="Model to use for inference"
        ),
        "beta_features_rollout": FeatureFlag(
            name="beta_features_rollout",
            flag_type=FlagType.PERCENTAGE,
            default_value=0,
            description="Percentage of users seeing beta features"
        ),
    }
    
    def __init__(self, backends: list[FlagBackend]):
        """
        Initialize with ordered list of backends.
        First backend with a value wins.
        """
        self.backends = backends
        # Bounded cache prevents unbounded growth across per-user evaluation;
        # callers needing strict TTL semantics should swap in cachetools.TTLCache.
        self._cache: dict[str, Any] = {}
        self._cache_max_size = 100_000
    
    def _coerce_value(self, flag: FeatureFlag, raw_value: str) -> Any:
        """Convert string value to appropriate type."""
        if flag.flag_type == FlagType.BOOLEAN:
            return raw_value.lower() in ("true", "1", "yes", "on")
        elif flag.flag_type == FlagType.INTEGER:
            return int(raw_value)
        elif flag.flag_type == FlagType.PERCENTAGE:
            return min(100, max(0, int(raw_value)))
        elif flag.flag_type == FlagType.JSON:
            return json.loads(raw_value)
        return raw_value
    
    def get(self, name: str, user_id: Optional[str] = None) -> Any:
        """
        Get flag value, checking backends in order.
        
        For percentage flags, user_id determines inclusion.
        """
        if name not in self.FLAGS:
            raise ValueError(f"Unknown feature flag: {name}")
        
        flag = self.FLAGS[name]
        
        # Check cache first
        cache_key = f"{name}:{user_id}" if user_id else name
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Check backends
        value = None
        for backend in self.backends:
            raw_value = backend.get_flag(name)
            if raw_value is not None:
                value = self._coerce_value(flag, raw_value)
                break
        
        if value is None:
            value = flag.default_value
        
        # Handle percentage rollout
        if flag.flag_type == FlagType.PERCENTAGE and user_id:
            # SHA-256 instead of builtin hash() because Python randomizes
            # hash() per process (PYTHONHASHSEED), which would land the same
            # user in different rollout buckets across replicas/restarts.
            digest = hashlib.sha256(f"{name}:{user_id}".encode()).hexdigest()
            user_hash = int(digest[:8], 16) % 100
            value = user_hash < value
        
        # Evict an arbitrary entry once over the bound (simple FIFO via
        # iteration order; replace with TTLCache if eviction policy matters).
        if len(self._cache) >= self._cache_max_size:
            try:
                self._cache.pop(next(iter(self._cache)))
            except StopIteration:
                pass
        self._cache[cache_key] = value
        return value
    
    def is_enabled(self, name: str, user_id: Optional[str] = None) -> bool:
        """Check if a boolean flag is enabled."""
        return bool(self.get(name, user_id))
    
    def clear_cache(self) -> None:
        """Clear the flag cache to pick up changes."""
        self._cache.clear()


_manager: Optional[FeatureFlagManager] = None


def init_feature_flags(backends: list[FlagBackend]) -> FeatureFlagManager:
    """Initialize the global feature flag manager."""
    global _manager
    _manager = FeatureFlagManager(backends)
    return _manager


def get_flag(name: str, user_id: Optional[str] = None) -> Any:
    """Get a feature flag value using the global manager."""
    if _manager is None:
        raise RuntimeError("Feature flags not initialized")
    return _manager.get(name, user_id)


def is_enabled(name: str, user_id: Optional[str] = None) -> bool:
    """Check if a feature is enabled using the global manager."""
    if _manager is None:
        raise RuntimeError("Feature flags not initialized")
    return _manager.is_enabled(name, user_id)

# ============================================================================
# Block 9 (chapter listing #9)
# ============================================================================

# src/agent/capabilities.py
"""
Agent capability management with feature flag integration.
"""

from dataclasses import dataclass
from typing import Optional

from src.features.feature_flags import get_flag, is_enabled


@dataclass
class AgentCapabilities:
    """Runtime capabilities for an agent instance."""
    advanced_reasoning: bool
    multimodal_input: bool
    max_tool_calls: int
    model_version: str
    
    @classmethod
    def for_user(cls, user_id: str) -> "AgentCapabilities":
        """Build capabilities based on feature flags for a user."""
        return cls(
            advanced_reasoning=is_enabled("advanced_reasoning", user_id),
            multimodal_input=is_enabled("multimodal_input", user_id),
            max_tool_calls=get_flag("max_tool_calls"),
            model_version=get_flag("model_version")
        )


class CapabilityGatedAgent:
    """Agent that respects capability flags."""
    
    def __init__(self, capabilities: AgentCapabilities):
        self.capabilities = capabilities
    
    def process_request(self, request: dict) -> dict:
        """Process request within capability constraints."""
        
        # Check multimodal capability
        if "image" in request and not self.capabilities.multimodal_input:
            return {"error": "Image input not enabled for this account"}
        
        # Apply tool call limits
        tool_calls = 0
        max_calls = self.capabilities.max_tool_calls
        
        # Use appropriate reasoning strategy
        if self.capabilities.advanced_reasoning:
            return self._advanced_process(request, max_calls)
        else:
            return self._simple_process(request, max_calls)
    
    def _advanced_process(self, request: dict, max_tools: int) -> dict:
        """Multi-step reasoning process."""
        # Implementation with chain-of-thought, tool use, etc.
        pass
    
    def _simple_process(self, request: dict, max_tools: int) -> dict:
        """Direct response without extensive reasoning."""
        # Simpler implementation
        pass

# ============================================================================
# Block 10 (chapter listing #10)
# ============================================================================

# src/config/settings.py
"""
Configuration management with environment layering.
Supports YAML files, environment variables, and secrets.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseConfig(BaseModel):
    """Database connection configuration."""
    host: str = "localhost"
    port: int = 5432
    name: str = "agent_db"
    user: str = "agent"
    password: SecretStr = SecretStr("")
    pool_size: int = 10
    max_overflow: int = 20
    
    @property
    def url(self) -> str:
        """Build database URL."""
        password = self.password.get_secret_value()
        return f"postgresql://{self.user}:{password}@{self.host}:{self.port}/{self.name}"


class RedisConfig(BaseModel):
    """Redis connection configuration."""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[SecretStr] = None
    
    @property
    def url(self) -> str:
        """Build Redis URL."""
        auth = ""
        if self.password:
            auth = f":{self.password.get_secret_value()}@"
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"


class LLMConfig(BaseModel):
    """
    LLM provider configuration.
    
    Model names should always be externalized to configuration rather than
    hardcoded. This enables: (1) switching models without code changes,
    (2) using different models per environment (cheaper models in dev),
    (3) rapid response to model deprecations or pricing changes.
    """
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key: SecretStr = SecretStr("")
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout_seconds: int = 120
    max_retries: int = 3
    # Fallback model for degraded operation
    fallback_model: Optional[str] = None


class ObservabilityConfig(BaseModel):
    """Observability and monitoring configuration."""
    log_level: str = "INFO"
    log_format: str = "json"
    metrics_enabled: bool = True
    metrics_port: int = 9090
    tracing_enabled: bool = False
    tracing_endpoint: Optional[str] = None
    tracing_sample_rate: float = 0.1


class AgentConfig(BaseModel):
    """Agent behavior configuration."""
    max_turns: int = 20
    max_tool_calls_per_turn: int = 5
    session_timeout_minutes: int = 30
    enable_memory: bool = True
    memory_window_size: int = 10


class Settings(BaseSettings):
    """
    Application settings with layered configuration.
    
    Configuration sources (in priority order):
    1. Environment variables
    2. .env file
    3. Environment-specific YAML
    4. Base YAML defaults
    """
    
    model_config = SettingsConfigDict(
        env_prefix="AGENT_",
        env_nested_delimiter="__",
        case_sensitive=False
    )
    
    # Environment
    environment: str = Field(default="development", description="Deployment environment")
    debug: bool = Field(default=False, description="Enable debug mode")
    
    # Nested configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    
    @classmethod
    def load(cls, config_dir: Optional[Path] = None) -> "Settings":
        """
        Load settings from YAML files and environment.
        
        Merges base.yaml with environment-specific overrides.
        """
        if config_dir is None:
            config_dir = Path(__file__).parent / "files"
        
        # Load base configuration
        base_path = config_dir / "base.yaml"
        config_data = {}
        if base_path.exists():
            with open(base_path) as f:
                config_data = yaml.safe_load(f) or {}
        
        # Load environment-specific overrides
        env = os.environ.get("AGENT_ENVIRONMENT", "development")
        env_path = config_dir / f"{env}.yaml"
        if env_path.exists():
            with open(env_path) as f:
                env_data = yaml.safe_load(f) or {}
                config_data = cls._deep_merge(config_data, env_data)
        
        return cls(**config_data)
    
    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Settings._deep_merge(result[key], value)
            else:
                result[key] = value
        return result


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings

# ============================================================================
# Block 11 (chapter listing #11)
# ============================================================================

# src/health/checks.py
"""
Health check implementations for agent systems.
Supports Kubernetes liveness and readiness probes.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Awaitable, Optional

import httpx
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy import text


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class CheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str
    duration_ms: float
    timestamp: datetime


class HealthChecker:
    """
    Manages health checks for the agent system.
    
    Distinguishes between critical checks (affect liveness)
    and non-critical checks (affect readiness only).
    """
    
    def __init__(self):
        self.checks: dict[str, tuple[Callable[[], Awaitable[CheckResult]], bool]] = {}
        self._startup_complete = False
        self._startup_time: Optional[datetime] = None
    
    def register(
        self,
        name: str,
        check: Callable[[], Awaitable[CheckResult]],
        critical: bool = False
    ) -> None:
        """
        Register a health check.
        
        Args:
            name: Unique identifier for the check
            check: Async function that performs the check
            critical: If True, failure affects liveness probe
        """
        self.checks[name] = (check, critical)
    
    def mark_startup_complete(self) -> None:
        """Mark that startup has completed successfully."""
        self._startup_complete = True
        self._startup_time = datetime.now(timezone.utc)
    
    async def run_check(self, name: str) -> CheckResult:
        """Run a single health check by name."""
        if name not in self.checks:
            return CheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Unknown check: {name}",
                duration_ms=0,
                timestamp=datetime.now(timezone.utc)
            )
        
        check_fn, _ = self.checks[name]
        start = datetime.now(timezone.utc)
        
        try:
            result = await asyncio.wait_for(check_fn(), timeout=10.0)
            result.duration_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            return result
        except asyncio.TimeoutError:
            return CheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message="Check timed out",
                duration_ms=10000,
                timestamp=datetime.now(timezone.utc)
            )
        except Exception as e:
            return CheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                duration_ms=(datetime.now(timezone.utc) - start).total_seconds() * 1000,
                timestamp=datetime.now(timezone.utc)
            )
    
    async def run_all_checks(self) -> dict[str, CheckResult]:
        """Run all registered health checks concurrently."""
        tasks = [self.run_check(name) for name in self.checks]
        results = await asyncio.gather(*tasks)
        return {result.name: result for result in results}
    
    async def is_live(self) -> tuple[bool, dict]:
        """
        Check liveness - is the process fundamentally healthy?
        
        Only critical checks affect liveness.
        """
        if not self._startup_complete:
            return False, {"status": "starting"}
        
        results = await self.run_all_checks()
        critical_results = {
            name: result for name, result in results.items()
            if self.checks[name][1]  # Is critical
        }
        
        is_healthy = all(
            r.status != HealthStatus.UNHEALTHY
            for r in critical_results.values()
        )
        
        return is_healthy, {
            "status": "healthy" if is_healthy else "unhealthy",
            "checks": {name: result.status.value for name, result in critical_results.items()}
        }
    
    async def is_ready(self) -> tuple[bool, dict]:
        """
        Check readiness - can the system handle traffic?
        
        All checks affect readiness.
        """
        if not self._startup_complete:
            return False, {"status": "starting"}
        
        results = await self.run_all_checks()
        
        is_ready = all(
            r.status == HealthStatus.HEALTHY
            for r in results.values()
        )
        
        return is_ready, {
            "status": "ready" if is_ready else "not_ready",
            "checks": {
                name: {
                    "status": result.status.value,
                    "message": result.message,
                    "duration_ms": result.duration_ms
                }
                for name, result in results.items()
            }
        }



async def create_database_check(engine: AsyncEngine) -> Callable[[], Awaitable[CheckResult]]:
    """Create a database connectivity check."""
    async def check() -> CheckResult:
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return CheckResult(
                name="database",
                status=HealthStatus.HEALTHY,
                message="Connected",
                duration_ms=0,
                timestamp=datetime.now(timezone.utc)
            )
        except Exception as e:
            return CheckResult(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                duration_ms=0,
                timestamp=datetime.now(timezone.utc)
            )
    return check


async def create_redis_check(redis_client: redis.Redis) -> Callable[[], Awaitable[CheckResult]]:
    """Create a Redis connectivity check."""
    async def check() -> CheckResult:
        try:
            await redis_client.ping()
            return CheckResult(
                name="redis",
                status=HealthStatus.HEALTHY,
                message="Connected",
                duration_ms=0,
                timestamp=datetime.now(timezone.utc)
            )
        except Exception as e:
            return CheckResult(
                name="redis",
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                duration_ms=0,
                timestamp=datetime.now(timezone.utc)
            )
    return check


async def create_llm_check(api_key: str) -> Callable[[], Awaitable[CheckResult]]:
    """Create an LLM API connectivity check."""
    async def check() -> CheckResult:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": api_key},
                    timeout=5.0
                )
                if response.status_code == 200:
                    return CheckResult(
                        name="llm_api",
                        status=HealthStatus.HEALTHY,
                        message="API accessible",
                        duration_ms=0,
                        timestamp=datetime.now(timezone.utc)
                    )
                else:
                    return CheckResult(
                        name="llm_api",
                        status=HealthStatus.DEGRADED,
                        message=f"API returned {response.status_code}",
                        duration_ms=0,
                        timestamp=datetime.now(timezone.utc)
                    )
        except Exception as e:
            return CheckResult(
                name="llm_api",
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                duration_ms=0,
                timestamp=datetime.now(timezone.utc)
            )
    return check

# ============================================================================
# Block 12 (chapter listing #12)
# ============================================================================

# src/api/health.py
"""
Health check API endpoints.
"""

from fastapi import APIRouter, Response, status

from src.health.checks import HealthChecker

router = APIRouter(prefix="/health", tags=["health"])


def create_health_router(checker: HealthChecker) -> APIRouter:
    """Create health router with the given checker."""
    
    @router.get("/live")
    async def liveness(response: Response):
        """
        Liveness probe endpoint.
        
        Returns 200 if the process is running and not deadlocked.
        Returns 503 if critical systems have failed.
        """
        is_live, details = await checker.is_live()
        if not is_live:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return details
    
    @router.get("/ready")
    async def readiness(response: Response):
        """
        Readiness probe endpoint.
        
        Returns 200 if the service can handle requests.
        Returns 503 if dependencies are unavailable.
        """
        is_ready, details = await checker.is_ready()
        if not is_ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return details
    
    @router.get("/detailed")
    async def detailed():
        """
        Detailed health status for debugging.
        
        Not used by probes - provides comprehensive diagnostics.
        """
        results = await checker.run_all_checks()
        return {
            "checks": {
                name: {
                    "status": result.status.value,
                    "message": result.message,
                    "duration_ms": round(result.duration_ms, 2),
                    "timestamp": result.timestamp.isoformat()
                }
                for name, result in results.items()
            }
        }
    
    return router

# ============================================================================
# Block 13 (chapter listing #13)
# ============================================================================

# src/lifecycle/shutdown.py
"""
Graceful shutdown handling for agent systems.
Ensures in-flight requests complete before termination.
"""

import asyncio
import signal
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Callable, Awaitable, Optional
import structlog

logger = structlog.get_logger()


class GracefulShutdown:
    """
    Manages graceful shutdown of the agent system.
    
    Coordinates between signal handlers, the web server,
    and long-running agent sessions.
    """
    
    def __init__(
        self,
        shutdown_timeout: int = 30,
        drain_timeout: int = 10
    ):
        """
        Initialize shutdown handler.
        
        Args:
            shutdown_timeout: Max seconds to wait for requests to complete
            drain_timeout: Seconds to wait after stopping new requests
        """
        self.shutdown_timeout = shutdown_timeout
        self.drain_timeout = drain_timeout
        self._shutdown_event = asyncio.Event()
        self._active_requests: set[str] = set()
        self._shutdown_callbacks: list[Callable[[], Awaitable[None]]] = []
        self._is_shutting_down = False
    
    def register_callback(self, callback: Callable[[], Awaitable[None]]) -> None:
        """Register a callback to run during shutdown."""
        self._shutdown_callbacks.append(callback)
    
    def is_shutting_down(self) -> bool:
        """Check if shutdown has been initiated."""
        return self._is_shutting_down
    
    @asynccontextmanager
    async def track_request(self, request_id: str):
        """
        Context manager to track active requests.
        
        Usage:
            async with shutdown_handler.track_request(request_id):
                # Handle request
                pass
        """
        self._active_requests.add(request_id)
        try:
            yield
        finally:
            self._active_requests.discard(request_id)
    
    def active_request_count(self) -> int:
        """Return count of active requests."""
        return len(self._active_requests)
    
    async def wait_for_shutdown(self) -> None:
        """Block until shutdown signal received."""
        await self._shutdown_event.wait()
    
    async def initiate_shutdown(self) -> None:
        """
        Begin graceful shutdown process.
        
        1. Stop accepting new requests
        2. Wait for active requests to complete
        3. Run shutdown callbacks
        4. Exit
        """
        if self._is_shutting_down:
            return
        
        self._is_shutting_down = True
        logger.info("Initiating graceful shutdown", active_requests=self.active_request_count())
        
        # Signal that shutdown has started
        self._shutdown_event.set()
        
        # Wait for drain period (allow load balancer to remove us)
        logger.info("Entering drain period", duration_seconds=self.drain_timeout)
        await asyncio.sleep(self.drain_timeout)
        
        # Wait for active requests to complete
        shutdown_deadline = datetime.now(timezone.utc) + timedelta(seconds=self.shutdown_timeout)
        
        while self._active_requests and datetime.now(timezone.utc) < shutdown_deadline:
            logger.info(
                "Waiting for requests to complete",
                active_requests=self.active_request_count(),
                remaining_seconds=(shutdown_deadline - datetime.now(timezone.utc)).seconds
            )
            await asyncio.sleep(1)
        
        if self._active_requests:
            logger.warning(
                "Shutdown timeout reached with active requests",
                abandoned_requests=list(self._active_requests)
            )
        
        # Run shutdown callbacks
        for callback in self._shutdown_callbacks:
            try:
                await callback()
            except Exception as e:
                logger.error("Shutdown callback failed", error=str(e))
        
        logger.info("Graceful shutdown complete")


def setup_signal_handlers(shutdown: GracefulShutdown) -> None:
    """Install signal handlers for graceful shutdown."""
    loop = asyncio.get_running_loop()

    def handle_signal(sig: signal.Signals) -> None:
        logger.info("Received signal", signal=sig.name)
        # Hold a strong reference so the task is not garbage-collected mid-shutdown.
        shutdown._shutdown_task = asyncio.create_task(shutdown.initiate_shutdown())
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal, sig)



from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
import uuid


class ShutdownMiddleware(BaseHTTPMiddleware):
    """Middleware to track requests and reject during shutdown."""
    
    def __init__(self, app: FastAPI, shutdown: GracefulShutdown):
        super().__init__(app)
        self.shutdown = shutdown
    
    async def dispatch(self, request: Request, call_next):
        # Reject new requests during shutdown
        if self.shutdown.is_shutting_down():
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=503,
                content={"error": "Service is shutting down"},
                headers={"Retry-After": "30"}
            )
        
        # Track request lifecycle
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        async with self.shutdown.track_request(request_id):
            response = await call_next(request)
        
        return response
