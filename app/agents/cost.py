import json
from langchain_core.prompts import ChatPromptTemplate
from app.core.llm import get_llm
from app.core.dedup import is_duplicate as _is_duplicate
from app.core.skills import get_agent_prompt
from app.models import AgentReport, Finding, Severity
from app.agents.security import _detect_infra_type
from app.parsers.kubernetes import get_pod_spec, get_containers, get_resource_name


def parse_resource_value(value: str, resource_type: str) -> float:
    """Parse K8s resource value to a numeric value."""
    if not value:
        return 0.0
    value = str(value)
    if resource_type == "cpu":
        if value.endswith("m"):
            return float(value[:-1]) / 1000
        return float(value)
    elif resource_type == "memory":
        multipliers = {
            "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3,
            "Ti": 1024**4, "K": 1000, "M": 1000**2,
            "G": 1000**3, "T": 1000**4,
        }
        for suffix, mult in multipliers.items():
            if value.endswith(suffix):
                return float(value[: -len(suffix)]) * mult
        return float(value)
    return 0.0


def run_cost_rules(resources: dict) -> list[Finding]:
    """Run deterministic cost checks."""
    findings = []
    workload_kinds = ("Deployment", "StatefulSet", "DaemonSet")

    for kind, items in resources.items():
        if kind not in workload_kinds:
            continue
        for resource in items:
            name = get_resource_name(resource)
            spec = resource.get("spec", {})
            containers = get_containers(spec)
            replicas = spec.get("replicas", 1)

            for container in containers:
                c_name = container.get("name", "unnamed")
                res = container.get("resources", {})
                requests = res.get("requests", {})
                limits = res.get("limits", {})

                # No resource requests at all
                if not requests and not limits:
                    findings.append(Finding(
                        agent="Cost Agent",
                        category="unbounded-resources",
                        severity=Severity.HIGH,
                        title="No resource requests or limits",
                        description=f"Container '{c_name}' in {name} has no resource constraints. Cost is unbounded.",
                        resource=name,
                        recommendation="Set resource requests and limits based on actual usage.",
                    ))
                    continue

                # Check for overprovisioning (limits >> requests)
                if requests and limits:
                    for res_type in ("cpu", "memory"):
                        req_val = parse_resource_value(requests.get(res_type, "0"), res_type)
                        lim_val = parse_resource_value(limits.get(res_type, "0"), res_type)
                        if req_val > 0 and lim_val > 0 and lim_val > req_val * 5:
                            findings.append(Finding(
                                agent="Cost Agent",
                                category="overprovisioned",
                                severity=Severity.MEDIUM,
                                title=f"Overprovisioned {res_type}",
                                description=f"Container '{c_name}' in {name}: {res_type} limit ({limits.get(res_type)}) "
                                            f"is >5x the request ({requests.get(res_type)}). Likely wasting resources.",
                                resource=name,
                                recommendation=f"Right-size {res_type} limits closer to actual usage.",
                            ))

                    # Very high memory
                    mem_req = parse_resource_value(requests.get("memory", "0"), "memory")
                    if mem_req > 4 * 1024**3:  # > 4Gi
                        findings.append(Finding(
                            agent="Cost Agent",
                            category="high-memory",
                            severity=Severity.LOW,
                            title="High memory request",
                            description=f"Container '{c_name}' in {name} requests {requests.get('memory')} memory.",
                            resource=name,
                            recommendation="Verify if this much memory is actually needed. Consider profiling.",
                        ))

            # Excessive replicas for cost
            if kind in ("Deployment", "StatefulSet") and replicas > 5:
                findings.append(Finding(
                    agent="Cost Agent",
                    category="excessive-replicas",
                    severity=Severity.LOW,
                    title="High replica count",
                    description=f"{name} has {replicas} replicas. Verify this is needed.",
                    resource=name,
                    recommendation="Use HPA instead of static high replica counts.",
                ))

    # Check for LoadBalancer services (cost more than ClusterIP)
    for svc in resources.get("Service", []):
        name = get_resource_name(svc)
        svc_type = svc.get("spec", {}).get("type", "ClusterIP")
        if svc_type == "LoadBalancer":
            findings.append(Finding(
                agent="Cost Agent",
                category="expensive-service",
                severity=Severity.MEDIUM,
                title="LoadBalancer service (expensive)",
                description=f"{name} uses LoadBalancer type. Each LB costs ~$15-20/month on cloud.",
                resource=name,
                recommendation="Use ClusterIP + shared Ingress controller to reduce costs.",
            ))

    # Check PVCs for large storage
    for pvc in resources.get("PersistentVolumeClaim", []):
        name = get_resource_name(pvc)
        storage = pvc.get("spec", {}).get("resources", {}).get("requests", {}).get("storage", "")
        storage_bytes = parse_resource_value(storage, "memory")
        if storage_bytes > 100 * 1024**3:  # > 100Gi
            findings.append(Finding(
                agent="Cost Agent",
                category="storage",
                severity=Severity.MEDIUM,
                title="Large PVC",
                description=f"{name} requests {storage} storage. Large PVCs are expensive.",
                resource=name,
                recommendation="Verify storage needs. Consider lifecycle policies or tiered storage.",
            ))

    return findings


def run_terraform_cost_rules(tf_resources: list) -> list[Finding]:
    """Run deterministic cost checks on parsed Terraform resources."""
    findings = []

    # Track expensive instance type prefixes
    expensive_ec2_prefixes = ("x1", "x2", "p3", "p4", "p5", "g4", "g5", "g6", "f1", "i3", "i4", "r6", "r7", "m6", "m7")
    expensive_rds_prefixes = ("db.r5", "db.r6", "db.r7", "db.x1", "db.x2", "db.m6", "db.m7")

    for res in tf_resources:
        rtype = res.get("type", "")
        rname = res.get("name", "")
        config = res.get("config", {})
        full_name = f"{rtype}.{rname}"

        # --- EC2 instance type cost ---
        if rtype == "aws_instance":
            instance_type = config.get("instance_type", "")
            if isinstance(instance_type, list):
                instance_type = instance_type[0] if instance_type else ""
            family = instance_type.split(".")[0] if instance_type else ""
            if any(family.startswith(p) for p in expensive_ec2_prefixes):
                findings.append(Finding(
                    agent="Cost Agent", category="expensive-resource",
                    severity=Severity.MEDIUM,
                    title="Expensive EC2 instance type",
                    description=f"{full_name} uses {instance_type} which is an expensive instance family.",
                    resource=full_name,
                    recommendation="Evaluate if workload needs this instance class. Consider spot/reserved instances.",
                ))

        # --- RDS instance type cost ---
        if rtype == "aws_db_instance":
            instance_class = config.get("instance_class", "")
            if isinstance(instance_class, list):
                instance_class = instance_class[0] if instance_class else ""
            if any(instance_class.startswith(p) for p in expensive_rds_prefixes):
                findings.append(Finding(
                    agent="Cost Agent", category="expensive-resource",
                    severity=Severity.MEDIUM,
                    title="Expensive RDS instance class",
                    description=f"{full_name} uses {instance_class} which is costly.",
                    resource=full_name,
                    recommendation="Consider right-sizing or using reserved DB instances.",
                ))
            # Allocated storage
            storage = config.get("allocated_storage", 0)
            if isinstance(storage, list):
                storage = storage[0] if storage else 0
            if isinstance(storage, (int, float)) and storage > 500:
                findings.append(Finding(
                    agent="Cost Agent", category="storage",
                    severity=Severity.LOW,
                    title="Large RDS storage allocation",
                    description=f"{full_name} allocates {storage}GB storage.",
                    resource=full_name,
                    recommendation="Verify if this storage is needed. Enable autoscaling instead of over-allocating.",
                ))

        # --- NAT Gateway (expensive) ---
        if rtype == "aws_nat_gateway":
            findings.append(Finding(
                agent="Cost Agent", category="expensive-resource",
                severity=Severity.LOW,
                title="NAT Gateway in use",
                description=f"{full_name}: NAT Gateways cost ~$32/month + data transfer fees.",
                resource=full_name,
                recommendation="Consider NAT instances for lower cost, or VPC endpoints for AWS service traffic.",
            ))

        # --- EIP not attached ---
        if rtype == "aws_eip":
            if not config.get("instance") and not config.get("network_interface"):
                findings.append(Finding(
                    agent="Cost Agent", category="unused-resource",
                    severity=Severity.MEDIUM,
                    title="Unattached Elastic IP",
                    description=f"{full_name} is not attached to any instance. Unattached EIPs cost money.",
                    resource=full_name,
                    recommendation="Attach to an instance or release the EIP.",
                ))

        # --- Large EBS volumes ---
        if rtype == "aws_ebs_volume":
            size = config.get("size", 0)
            if isinstance(size, list):
                size = size[0] if size else 0
            vol_type = config.get("type", "gp3")
            if isinstance(vol_type, list):
                vol_type = vol_type[0] if vol_type else "gp3"
            if isinstance(size, (int, float)) and size > 500:
                findings.append(Finding(
                    agent="Cost Agent", category="storage",
                    severity=Severity.LOW,
                    title="Large EBS volume",
                    description=f"{full_name} is {size}GB ({vol_type}). Large volumes increase costs.",
                    resource=full_name,
                    recommendation="Verify usage and consider gp3 type for cost efficiency.",
                ))

        # --- Azure expensive VM SKUs ---
        if rtype in ("azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"):
            vm_size = config.get("size", config.get("vm_size", ""))
            if isinstance(vm_size, list):
                vm_size = vm_size[0] if vm_size else ""
            if any(kw in str(vm_size).lower() for kw in ("standard_e", "standard_m", "standard_l", "standard_n")):
                findings.append(Finding(
                    agent="Cost Agent", category="expensive-resource",
                    severity=Severity.MEDIUM,
                    title="Expensive Azure VM size",
                    description=f"{full_name} uses {vm_size} which is a premium VM series.",
                    resource=full_name,
                    recommendation="Evaluate if this VM series is required. Consider B-series for burstable workloads.",
                ))

        # --- S3 bucket without lifecycle rules ---
        if rtype == "aws_s3_bucket":
            lifecycle = config.get("lifecycle_rule")
            if not lifecycle:
                findings.append(Finding(
                    agent="Cost Agent", category="storage",
                    severity=Severity.MEDIUM,
                    title="S3 bucket without lifecycle rules",
                    description=f"{full_name} has no lifecycle rules. Data stored indefinitely incurs ongoing costs.",
                    resource=full_name,
                    recommendation="Add lifecycle_rule to transition old objects to cheaper storage or expire them.",
                ))

        # --- CloudWatch log group without retention ---
        if rtype == "aws_cloudwatch_log_group":
            retention = config.get("retention_in_days")
            if not retention or retention in (0, [0]):
                findings.append(Finding(
                    agent="Cost Agent", category="storage",
                    severity=Severity.MEDIUM,
                    title="CloudWatch logs with unlimited retention",
                    description=f"{full_name} has no retention limit. Logs grow indefinitely and increase costs.",
                    resource=full_name,
                    recommendation="Set retention_in_days (e.g., 30, 90, 365) to control log storage costs.",
                ))

        # --- EBS io1/io2 volumes (very expensive) ---
        if rtype == "aws_ebs_volume":
            vol_type = config.get("type", "gp3")
            if isinstance(vol_type, list):
                vol_type = vol_type[0] if vol_type else "gp3"
            if vol_type in ("io1", "io2"):
                iops = config.get("iops", 0)
                if isinstance(iops, list):
                    iops = iops[0] if iops else 0
                findings.append(Finding(
                    agent="Cost Agent", category="expensive-resource",
                    severity=Severity.MEDIUM,
                    title=f"Provisioned IOPS EBS volume ({vol_type})",
                    description=f"{full_name} uses {vol_type} with {iops} IOPS. This is significantly more expensive than gp3.",
                    resource=full_name,
                    recommendation="Evaluate if provisioned IOPS is needed. gp3 offers 3000 IOPS baseline for free.",
                ))

        # --- DynamoDB provisioned mode (risk of over-provisioning) ---
        if rtype == "aws_dynamodb_table":
            billing_mode = config.get("billing_mode", "PROVISIONED")
            if isinstance(billing_mode, list):
                billing_mode = billing_mode[0] if billing_mode else "PROVISIONED"
            if billing_mode == "PROVISIONED":
                read_cap = config.get("read_capacity", 0)
                write_cap = config.get("write_capacity", 0)
                if isinstance(read_cap, list):
                    read_cap = read_cap[0] if read_cap else 0
                if isinstance(write_cap, list):
                    write_cap = write_cap[0] if write_cap else 0
                if (isinstance(read_cap, (int, float)) and read_cap > 100) or \
                   (isinstance(write_cap, (int, float)) and write_cap > 100):
                    findings.append(Finding(
                        agent="Cost Agent", category="overprovisioned",
                        severity=Severity.MEDIUM,
                        title="DynamoDB high provisioned capacity",
                        description=f"{full_name} has read={read_cap}/write={write_cap} capacity units. May be over-provisioned.",
                        resource=full_name,
                        recommendation="Consider PAY_PER_REQUEST billing mode or enable auto-scaling.",
                    ))

        # --- ElastiCache expensive node types ---
        if rtype in ("aws_elasticache_cluster", "aws_elasticache_replication_group"):
            node_type = config.get("node_type", "")
            if isinstance(node_type, list):
                node_type = node_type[0] if node_type else ""
            if any(node_type.startswith(p) for p in ("cache.r5", "cache.r6", "cache.r7", "cache.m5", "cache.m6", "cache.m7")):
                findings.append(Finding(
                    agent="Cost Agent", category="expensive-resource",
                    severity=Severity.LOW,
                    title="Expensive ElastiCache node type",
                    description=f"{full_name} uses {node_type}. Memory-optimized cache nodes are costly.",
                    resource=full_name,
                    recommendation="Verify if this node class is needed. Consider cache.t3 for smaller workloads.",
                ))

        # --- Multiple NAT Gateways (already have per-NAT check, add multi-NAT warning) ---
        # Handled by per-resource check above

    return findings


async def analyze_cost(
    file_contents: dict[str, str], resources: dict, tf_resources: list | None = None
) -> AgentReport:
    """Run cost analysis using rules + LLM reasoning."""
    rule_findings = run_cost_rules(resources)
    if tf_resources:
        rule_findings.extend(run_terraform_cost_rules(tf_resources))

    # Select prompt based on file type
    infra_type = _detect_infra_type(file_contents)
    if infra_type == "terraform":
        system_prompt = get_agent_prompt("cost", "terraform")
    else:
        system_prompt = get_agent_prompt("cost", "kubernetes")

    llm = get_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Analyze infrastructure cost efficiency:\n\n{infra_content}"),
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
                agent="Cost Agent",
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
        agent_name="Cost Agent",
        findings=all_findings,
        summary=llm_summary or f"Found {len(all_findings)} cost issues.",
        score=final_score,
    )
