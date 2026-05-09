import json
from langchain_core.prompts import ChatPromptTemplate
from app.core.llm import get_llm
from app.core.dedup import is_duplicate as _is_duplicate
from app.models import AgentReport, Finding, Severity
from app.agents.security import _detect_infra_type
from app.parsers.kubernetes import get_pod_spec, get_containers, get_resource_name

RELIABILITY_K8S_PROMPT = """You are an Infrastructure Reliability Agent specializing in Kubernetes.
Analyze ONLY Kubernetes YAML manifests for reliability risks.
Focus on: missing liveness/readiness/startup probes, insufficient replicas, no PodDisruptionBudget, missing anti-affinity, no HPA, missing resource requests, no rolling update strategy, missing terminationGracePeriodSeconds.
Do NOT reference Terraform, cloud provider, EC2, RDS, or IaC concepts.

Respond ONLY with valid JSON:
{{"findings": [{{"severity": "critical|high|medium|low|info", "title": "...", "description": "...", "resource": "...", "recommendation": "..."}}], "summary": "brief assessment", "score": 0-100}}
"""

RELIABILITY_TF_PROMPT = """You are an Infrastructure Reliability Agent specializing in Terraform and cloud infrastructure (AWS, Azure, GCP).
Analyze ONLY Terraform/cloud configuration for reliability risks.
Focus on: single-AZ deployments, no auto-scaling groups, missing backups, no health checks, missing Multi-AZ for databases, no deletion protection, missing disaster recovery, no CloudWatch alarms, missing dead letter queues, no point-in-time recovery.
Do NOT apply Kubernetes concepts (pods, containers, resource requests/limits, probes, replicas, PDB, HPA, securityContext). EC2 instances do NOT have "resource requests" or "liveness probes" — evaluate ASG health checks, scaling policies, CloudWatch alarms, and instance recovery instead.

Respond ONLY with valid JSON:
{{"findings": [{{"severity": "critical|high|medium|low|info", "title": "...", "description": "...", "resource": "...", "recommendation": "..."}}], "summary": "brief assessment", "score": 0-100}}
"""


def run_reliability_rules(resources: dict) -> list[Finding]:
    """Run deterministic reliability checks."""
    findings = []
    workload_kinds = ("Deployment", "StatefulSet", "DaemonSet")
    hpa_targets = set()
    pdb_selectors = []

    # Collect HPA targets
    for hpa in resources.get("HorizontalPodAutoscaler", []):
        target = hpa.get("spec", {}).get("scaleTargetRef", {})
        hpa_targets.add(f"{target.get('kind', '')}/{target.get('name', '')}")

    # Collect PDB selectors
    for pdb in resources.get("PodDisruptionBudget", []):
        selector = pdb.get("spec", {}).get("selector", {}).get("matchLabels", {})
        pdb_selectors.append(selector)

    for kind, items in resources.items():
        if kind not in workload_kinds:
            continue
        for resource in items:
            name = get_resource_name(resource)
            spec = resource.get("spec", {})
            pod_spec = get_pod_spec(resource)
            containers = get_containers(spec)
            replicas = spec.get("replicas", 1)
            metadata = resource.get("metadata", {})
            res_name = metadata.get("name", "")

            # Single replica — severity depends on workload type
            if kind in ("Deployment", "StatefulSet") and replicas <= 1:
                is_cache = any(
                    kw in res_name.lower()
                    for kw in ("redis", "memcached", "cache")
                )
                findings.append(Finding(
                    agent="Reliability Agent",
                    category="replicas",
                    severity=Severity.MEDIUM if is_cache else Severity.HIGH,
                    title="Single replica (SPOF)",
                    description=f"{name} has only {replicas} replica(s). "
                                + ("Cache workloads may be acceptable as single replica." if is_cache
                                   else "Single point of failure."),
                    resource=name,
                    recommendation="Consider replicas >= 2 for production workloads." if is_cache
                                   else "Set replicas >= 2 for production workloads.",
                ))

            # No HPA (skip for cache/stateful workloads like Redis)
            target_key = f"{kind}/{res_name}"
            is_cache_workload = any(
                kw in res_name.lower()
                for kw in ("redis", "memcached", "cache", "etcd")
            )
            if kind in ("Deployment", "StatefulSet") and target_key not in hpa_targets and not is_cache_workload:
                findings.append(Finding(
                    agent="Reliability Agent",
                    category="autoscaling",
                    severity=Severity.LOW,
                    title="No HorizontalPodAutoscaler",
                    description=f"{name} has no HPA configured.",
                    resource=name,
                    recommendation="Consider adding HPA for automatic scaling under load.",
                ))

            # No anti-affinity
            affinity = pod_spec.get("affinity", {})
            if kind in ("Deployment", "StatefulSet") and replicas > 1:
                pod_anti = affinity.get("podAntiAffinity")
                if not pod_anti:
                    findings.append(Finding(
                        agent="Reliability Agent",
                        category="anti-affinity",
                        severity=Severity.LOW,
                        title="No pod anti-affinity",
                        description=f"{name} has multiple replicas but no anti-affinity. Pods may co-locate.",
                        resource=name,
                        recommendation="Consider adding podAntiAffinity to spread across nodes.",
                    ))

            # No PDB
            labels = (
                spec.get("template", {}).get("metadata", {}).get("labels", {})
            )
            has_pdb = any(
                all(labels.get(k) == v for k, v in sel.items())
                for sel in pdb_selectors
                if sel
            )
            if kind in ("Deployment", "StatefulSet") and replicas > 1 and not has_pdb:
                findings.append(Finding(
                    agent="Reliability Agent",
                    category="pdb",
                    severity=Severity.MEDIUM,
                    title="No PodDisruptionBudget",
                    description=f"{name} has no PDB. All pods may be evicted during maintenance.",
                    resource=name,
                    recommendation="Create a PodDisruptionBudget with minAvailable or maxUnavailable.",
                ))

            # Check containers for probes
            for container in containers:
                c_name = container.get("name", "unnamed")

                if not container.get("livenessProbe"):
                    findings.append(Finding(
                        agent="Reliability Agent",
                        category="probes",
                        severity=Severity.HIGH,
                        title="Missing liveness probe",
                        description=f"Container '{c_name}' in {name} has no liveness probe.",
                        resource=name,
                        recommendation="Add livenessProbe to detect and restart unhealthy containers.",
                    ))

                if not container.get("readinessProbe"):
                    findings.append(Finding(
                        agent="Reliability Agent",
                        category="probes",
                        severity=Severity.HIGH,
                        title="Missing readiness probe",
                        description=f"Container '{c_name}' in {name} has no readiness probe.",
                        resource=name,
                        recommendation="Add readinessProbe to prevent routing traffic to unready pods.",
                    ))

                # Missing resource requests
                res = container.get("resources", {})
                if not res.get("requests"):
                    findings.append(Finding(
                        agent="Reliability Agent",
                        category="resources",
                        severity=Severity.MEDIUM,
                        title="No resource requests",
                        description=f"Container '{c_name}' in {name} has no resource requests.",
                        resource=name,
                        recommendation="Set resources.requests to ensure proper scheduling.",
                    ))

            # Rolling update strategy
            strategy = spec.get("strategy", {})
            if kind == "Deployment" and not strategy:
                findings.append(Finding(
                    agent="Reliability Agent",
                    category="strategy",
                    severity=Severity.LOW,
                    title="No update strategy specified",
                    description=f"{name} has no explicit update strategy.",
                    resource=name,
                    recommendation="Set strategy to RollingUpdate with maxSurge/maxUnavailable.",
                ))

    return findings


def run_terraform_reliability_rules(tf_resources: list) -> list[Finding]:
    """Run deterministic reliability checks on parsed Terraform resources."""
    findings = []

    for res in tf_resources:
        rtype = res.get("type", "")
        rname = res.get("name", "")
        config = res.get("config", {})
        full_name = f"{rtype}.{rname}"

        # --- RDS: no Multi-AZ ---
        if rtype == "aws_db_instance":
            multi_az = config.get("multi_az")
            if not multi_az or multi_az in (False, [False]):
                findings.append(Finding(
                    agent="Reliability Agent", category="high-availability",
                    severity=Severity.HIGH,
                    title="RDS instance not Multi-AZ",
                    description=f"{full_name} does not have Multi-AZ enabled. Single AZ failure risk.",
                    resource=full_name,
                    recommendation="Set multi_az = true for production databases.",
                ))
            if not config.get("backup_retention_period") or config.get("backup_retention_period") in (0, [0]):
                findings.append(Finding(
                    agent="Reliability Agent", category="backup",
                    severity=Severity.HIGH,
                    title="RDS backups disabled",
                    description=f"{full_name} has no backup retention. Data loss risk.",
                    resource=full_name,
                    recommendation="Set backup_retention_period >= 7 for production.",
                ))

        # --- Auto Scaling Group: no health check ---
        if rtype == "aws_autoscaling_group":
            hc = config.get("health_check_type", "EC2")
            if isinstance(hc, list):
                hc = hc[0] if hc else "EC2"
            if hc == "EC2":
                findings.append(Finding(
                    agent="Reliability Agent", category="health-check",
                    severity=Severity.MEDIUM,
                    title="ASG using EC2 health check only",
                    description=f"{full_name} uses EC2 health check, not ELB. Won't detect app failures.",
                    resource=full_name,
                    recommendation="Set health_check_type = \"ELB\" when behind a load balancer.",
                ))

        # --- ELB without health check ---
        if rtype in ("aws_lb", "aws_alb"):
            # Check if there's a target group with health check
            pass  # LLM handles this contextually

        # --- EC2 without auto-scaling ---
        if rtype == "aws_instance":
            findings.append(Finding(
                agent="Reliability Agent", category="scaling",
                severity=Severity.MEDIUM,
                title="Standalone EC2 instance (no ASG)",
                description=f"{full_name} is a standalone instance, not in an Auto Scaling Group.",
                resource=full_name,
                recommendation="Use aws_autoscaling_group for self-healing and scaling.",
            ))

        # --- Azure VM without availability set ---
        if rtype == "azurerm_virtual_machine" or rtype == "azurerm_linux_virtual_machine":
            if not config.get("availability_set_id") and not config.get("zone"):
                findings.append(Finding(
                    agent="Reliability Agent", category="high-availability",
                    severity=Severity.MEDIUM,
                    title="VM without availability zone/set",
                    description=f"{full_name} has no availability set or zone specified.",
                    resource=full_name,
                    recommendation="Assign to an availability set or specify an availability zone.",
                ))

        # --- S3 without versioning ---
        if rtype == "aws_s3_bucket":
            versioning = config.get("versioning", {})
            if isinstance(versioning, list):
                versioning = versioning[0] if versioning else {}
            if not versioning or not versioning.get("enabled"):
                findings.append(Finding(
                    agent="Reliability Agent", category="backup",
                    severity=Severity.MEDIUM,
                    title="S3 bucket without versioning",
                    description=f"{full_name} does not have versioning enabled. No protection against accidental deletes.",
                    resource=full_name,
                    recommendation="Enable versioning { enabled = true } for data protection.",
                ))

        # --- DynamoDB without point-in-time recovery ---
        if rtype == "aws_dynamodb_table":
            pitr = config.get("point_in_time_recovery", {})
            if isinstance(pitr, list):
                pitr = pitr[0] if pitr else {}
            enabled = pitr.get("enabled") if isinstance(pitr, dict) else None
            if not enabled or enabled in (False, [False]):
                findings.append(Finding(
                    agent="Reliability Agent", category="backup",
                    severity=Severity.HIGH,
                    title="DynamoDB without point-in-time recovery",
                    description=f"{full_name} does not have PITR enabled. Data cannot be recovered to a specific point in time.",
                    resource=full_name,
                    recommendation="Set point_in_time_recovery { enabled = true } for data protection.",
                ))

        # --- ElastiCache not Multi-AZ ---
        if rtype == "aws_elasticache_replication_group":
            multi_az = config.get("automatic_failover_enabled")
            if not multi_az or multi_az in (False, [False]):
                findings.append(Finding(
                    agent="Reliability Agent", category="high-availability",
                    severity=Severity.MEDIUM,
                    title="ElastiCache without automatic failover",
                    description=f"{full_name} does not have automatic failover. Cache unavailable during AZ failure.",
                    resource=full_name,
                    recommendation="Set automatic_failover_enabled = true for Multi-AZ resilience.",
                ))

        # --- Lambda without dead letter queue ---
        if rtype == "aws_lambda_function":
            dlq = config.get("dead_letter_config")
            if not dlq:
                findings.append(Finding(
                    agent="Reliability Agent", category="error-handling",
                    severity=Severity.MEDIUM,
                    title="Lambda without dead letter queue",
                    description=f"{full_name} has no dead_letter_config. Failed invocations are silently lost.",
                    resource=full_name,
                    recommendation="Set dead_letter_config { target_arn = <SQS/SNS ARN> } to capture failed events.",
                ))

        # --- SQS without dead letter queue ---
        if rtype == "aws_sqs_queue":
            redrive = config.get("redrive_policy")
            if not redrive:
                findings.append(Finding(
                    agent="Reliability Agent", category="error-handling",
                    severity=Severity.MEDIUM,
                    title="SQS queue without dead letter queue",
                    description=f"{full_name} has no redrive_policy. Poison messages will block processing.",
                    resource=full_name,
                    recommendation="Set redrive_policy with a dead letter queue ARN and maxReceiveCount.",
                ))

        # --- ELB without cross-zone load balancing ---
        if rtype in ("aws_lb", "aws_alb"):
            cross_zone = config.get("enable_cross_zone_load_balancing")
            if cross_zone in (False, [False]):
                findings.append(Finding(
                    agent="Reliability Agent", category="high-availability",
                    severity=Severity.MEDIUM,
                    title="Load balancer without cross-zone balancing",
                    description=f"{full_name} has cross-zone load balancing disabled. Uneven traffic distribution across AZs.",
                    resource=full_name,
                    recommendation="Set enable_cross_zone_load_balancing = true.",
                ))

        # --- RDS without deletion protection ---
        if rtype == "aws_db_instance":
            deletion_protection = config.get("deletion_protection")
            if not deletion_protection or deletion_protection in (False, [False]):
                findings.append(Finding(
                    agent="Reliability Agent", category="protection",
                    severity=Severity.MEDIUM,
                    title="RDS without deletion protection",
                    description=f"{full_name} can be accidentally deleted. No deletion protection enabled.",
                    resource=full_name,
                    recommendation="Set deletion_protection = true for production databases.",
                ))

        # --- CloudWatch alarm missing (heuristic: no alarms at all) ---
        # This is a cross-resource check handled below

    # Cross-resource check: any monitoring alarms present?
    has_alarms = any(r["type"] == "aws_cloudwatch_metric_alarm" for r in tf_resources)
    has_ec2_or_rds = any(r["type"] in ("aws_instance", "aws_db_instance", "aws_autoscaling_group") for r in tf_resources)
    if has_ec2_or_rds and not has_alarms:
        findings.append(Finding(
            agent="Reliability Agent", category="monitoring",
            severity=Severity.MEDIUM,
            title="No CloudWatch alarms defined",
            description="Infrastructure has compute/database resources but no CloudWatch metric alarms for monitoring.",
            resource="infrastructure",
            recommendation="Add aws_cloudwatch_metric_alarm resources for CPU, memory, disk, and error rate monitoring.",
        ))

    return findings


async def analyze_reliability(
    file_contents: dict[str, str], resources: dict, tf_resources: list | None = None
) -> AgentReport:
    """Run reliability analysis using rules + LLM reasoning."""
    rule_findings = run_reliability_rules(resources)
    if tf_resources:
        rule_findings.extend(run_terraform_reliability_rules(tf_resources))

    # Select prompt based on file type
    infra_type = _detect_infra_type(file_contents)
    if infra_type == "terraform":
        system_prompt = RELIABILITY_TF_PROMPT
    else:
        system_prompt = RELIABILITY_K8S_PROMPT

    llm = get_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Analyze infrastructure reliability:\n\n{infra_content}"),
    ])

    infra_content = ""
    for fname, content in file_contents.items():
        infra_content += f"\n--- {fname} ---\n{content}\n"

    chain = prompt | llm
    try:
        response = await chain.ainvoke({"infra_content": infra_content})
        response_text = response.content.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1]
            response_text = response_text.rsplit("```", 1)[0]

        llm_result = json.loads(response_text)
        llm_findings = [
            Finding(
                agent="Reliability Agent",
                category="ai-analysis",
                severity=Severity(f.get("severity", "medium")),
                title=f.get("title", ""),
                description=f.get("description", ""),
                resource=f.get("resource", ""),
                recommendation=f.get("recommendation", ""),
            )
            for f in llm_result.get("findings", [])
        ]
        llm_summary = llm_result.get("summary", "")
        llm_score = llm_result.get("score", 50)
    except Exception:
        llm_findings = []
        llm_summary = ""
        llm_score = None

    all_findings = rule_findings[:]
    for f in llm_findings:
        if not _is_duplicate(f, rule_findings):
            all_findings.append(f)

    deductions = {
        Severity.CRITICAL: 20, Severity.HIGH: 10,
        Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0,
    }
    rule_score = max(0, 100 - sum(deductions[f.severity] for f in all_findings))
    if llm_score is not None:
        final_score = round(rule_score * 0.6 + llm_score * 0.4, 1)
    else:
        final_score = float(rule_score)

    return AgentReport(
        agent_name="Reliability Agent",
        findings=all_findings,
        summary=llm_summary or f"Found {len(all_findings)} reliability issues.",
        score=final_score,
    )
