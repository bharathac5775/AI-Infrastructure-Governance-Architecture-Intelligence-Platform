import json
from langchain_core.prompts import ChatPromptTemplate
from app.core.llm import get_llm
from app.models import AgentReport, Finding, Severity
from app.parsers.kubernetes import (
    get_pod_spec,
    get_containers,
    get_resource_name,
)

SECURITY_K8S_PROMPT = """You are an Infrastructure Security Agent specializing in Kubernetes.
Analyze ONLY Kubernetes YAML manifests for security issues.
Focus on: privileged containers, missing securityContext, runAsNonRoot, readOnlyRootFilesystem, capabilities, missing resource limits, dangerous RBAC (cluster-admin), public exposure (LoadBalancer), hardcoded secrets in env vars, untagged images, host namespace sharing (hostPID/hostNetwork), hostPath volume mounts.
Do NOT reference Terraform, cloud provider, or IaC concepts.

Respond ONLY with valid JSON:
{{"findings": [{{"severity": "critical|high|medium|low|info", "title": "...", "description": "...", "resource": "...", "recommendation": "..."}}], "summary": "brief assessment", "score": 0-100}}
"""

SECURITY_TF_PROMPT = """You are an Infrastructure Security Agent specializing in Terraform and cloud infrastructure (AWS, Azure, GCP).
Analyze ONLY Terraform/cloud configuration for security issues.
Focus on: open security groups (0.0.0.0/0), public S3/storage buckets, unencrypted databases/volumes, overly permissive IAM policies, missing encryption at rest/in transit, hardcoded credentials, missing IMDSv2, disabled CloudTrail/logging, KMS key rotation, VPC flow logs, HTTPS enforcement.
Do NOT apply Kubernetes concepts (pods, containers, resource requests/limits, probes, securityContext). EC2 instances do NOT have "resource requests" — evaluate instance type sizing, ASG policies, and scaling instead.

Respond ONLY with valid JSON:
{{"findings": [{{"severity": "critical|high|medium|low|info", "title": "...", "description": "...", "resource": "...", "recommendation": "..."}}], "summary": "brief assessment", "score": 0-100}}
"""

# Stop words excluded from keyword matching
_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "be", "been", "being", "have", "has",
    "had", "do", "does", "did", "will", "would", "could", "should", "may",
    "might", "can", "shall", "to", "of", "in", "for", "on", "with", "at",
    "by", "from", "as", "into", "through", "during", "before", "after",
    "and", "but", "or", "nor", "not", "no", "so", "if", "than", "too",
    "it", "its", "this", "that", "these", "those", "set", "add", "use",
})


# Domain synonyms for better dedup matching
_SYNONYMS = {
    "missing": "no", "no": "missing", "lacks": "missing", "absent": "missing",
    "without": "missing", "undefined": "missing",
    "limits": "limit", "limit": "limits",
    "requests": "request", "request": "requests",
    "probes": "probe", "probe": "probes",
    "replicas": "replica", "replica": "replicas",
    "securitycontext": "security", "security": "securitycontext",
    "root": "nonroot", "nonroot": "root", "runasnonroot": "root",
    "image": "tag", "tag": "image", "latest": "untagged", "untagged": "latest",
    "secret": "password", "password": "secret", "credential": "secret",
    "credentials": "secret", "hardcoded": "plaintext", "plaintext": "hardcoded",
    "loadbalancer": "public", "public": "loadbalancer",
    "hpa": "autoscaling", "autoscaling": "hpa", "autoscaler": "hpa",
    "pdb": "disruption", "disruption": "pdb",
    "affinity": "antiaffinity", "antiaffinity": "affinity",
    "liveness": "health", "readiness": "health", "health": "liveness",
}


def _extract_keywords(text: str) -> set[str]:
    """Extract significant keywords from text, with synonym expansion."""
    words = set()
    for w in text.lower().replace("-", " ").replace("_", " ").replace("/", " ").split():
        w = w.strip(".,;:!?()[]{}\"'`")
        if len(w) > 2 and w not in _STOP_WORDS:
            words.add(w)
            if w in _SYNONYMS:
                words.add(_SYNONYMS[w])
    return words


def _is_duplicate(llm_finding: Finding, rule_findings: list[Finding]) -> bool:
    """Check if an LLM finding duplicates any rule finding using keyword overlap."""
    llm_keywords = _extract_keywords(llm_finding.title + " " + llm_finding.description)
    if not llm_keywords:
        return False
    for rf in rule_findings:
        rule_keywords = _extract_keywords(rf.title + " " + rf.description + " " + rf.category)
        overlap = llm_keywords & rule_keywords
        if len(overlap) >= max(2, len(llm_keywords) * 0.25):
            return True
    return False


def run_security_rules(resources: dict) -> list[Finding]:
    """Run deterministic security checks on parsed K8s resources."""
    findings = []
    workload_kinds = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod")

    for kind, items in resources.items():
        if kind not in workload_kinds:
            continue
        for resource in items:
            name = get_resource_name(resource)
            pod_spec = get_pod_spec(resource)
            containers = get_containers(resource.get("spec", {}))

            # Check host namespaces
            for ns in ("hostPID", "hostNetwork", "hostIPC"):
                if pod_spec.get(ns, False):
                    findings.append(Finding(
                        agent="Security Agent",
                        category="host-namespace",
                        severity=Severity.CRITICAL,
                        title=f"{ns} enabled",
                        description=f"{name} has {ns}=true, sharing host namespace.",
                        resource=name,
                        recommendation=f"Remove {ns}: true unless absolutely required.",
                    ))

            # Pod-level security context (applies to all containers)
            pod_sec_ctx = pod_spec.get("securityContext", {})

            for container in containers:
                c_name = container.get("name", "unnamed")
                sec_ctx = container.get("securityContext", {})

                # Privileged container
                if sec_ctx.get("privileged", False):
                    findings.append(Finding(
                        agent="Security Agent",
                        category="privileged",
                        severity=Severity.CRITICAL,
                        title="Privileged container",
                        description=f"Container '{c_name}' in {name} runs in privileged mode.",
                        resource=name,
                        recommendation="Set securityContext.privileged: false",
                    ))

                # runAsRoot — check both container-level AND pod-level securityContext
                container_run_as_non_root = sec_ctx.get("runAsNonRoot")
                pod_run_as_non_root = pod_sec_ctx.get("runAsNonRoot")
                container_run_as_user = sec_ctx.get("runAsUser")
                pod_run_as_user = pod_sec_ctx.get("runAsUser")

                effective_non_root = container_run_as_non_root if container_run_as_non_root is not None else pod_run_as_non_root
                effective_user = container_run_as_user if container_run_as_user is not None else pod_run_as_user

                if effective_non_root is None and (effective_user is None or effective_user == 0):
                    findings.append(Finding(
                        agent="Security Agent",
                        category="run-as-root",
                        severity=Severity.HIGH,
                        title="Container may run as root",
                        description=f"Container '{c_name}' in {name} has no runAsNonRoot and may run as root.",
                        resource=name,
                        recommendation="Set securityContext.runAsNonRoot: true",
                    ))

                # readOnlyRootFilesystem — check container-level (pod-level doesn't support this)
                if not sec_ctx.get("readOnlyRootFilesystem", False):
                    findings.append(Finding(
                        agent="Security Agent",
                        category="filesystem",
                        severity=Severity.MEDIUM,
                        title="Writable root filesystem",
                        description=f"Container '{c_name}' in {name} has writable root filesystem.",
                        resource=name,
                        recommendation="Set securityContext.readOnlyRootFilesystem: true",
                    ))

                # Missing resource limits
                res = container.get("resources", {})
                if not res.get("limits"):
                    findings.append(Finding(
                        agent="Security Agent",
                        category="resource-limits",
                        severity=Severity.HIGH,
                        title="No resource limits",
                        description=f"Container '{c_name}' in {name} has no resource limits, enabling potential DoS.",
                        resource=name,
                        recommendation="Set resources.limits for cpu and memory.",
                    ))

                # Image tag :latest
                image = container.get("image", "")
                if ":latest" in image or ":" not in image:
                    findings.append(Finding(
                        agent="Security Agent",
                        category="image-tag",
                        severity=Severity.MEDIUM,
                        title="Using latest or untagged image",
                        description=f"Container '{c_name}' in {name} uses image '{image}' without specific tag.",
                        resource=name,
                        recommendation="Use a specific image tag/digest for reproducibility.",
                    ))

    # Check for hardcoded secrets in env vars
    for kind, items in resources.items():
        if kind not in workload_kinds:
            continue
        for resource in items:
            name = get_resource_name(resource)
            containers = get_containers(resource.get("spec", {}))
            for container in containers:
                c_name = container.get("name", "unnamed")
                for env in container.get("env", []):
                    env_name = env.get("name", "")
                    env_value = env.get("value")
                    # Flag if env var has a plain-text value and looks like a secret
                    if env_value and not env.get("valueFrom"):
                        secret_keywords = ("password", "secret", "token", "key", "api_key",
                                          "apikey", "credentials", "private", "passwd")
                        if any(kw in env_name.lower() for kw in secret_keywords):
                            findings.append(Finding(
                                agent="Security Agent",
                                category="hardcoded-secret",
                                severity=Severity.CRITICAL,
                                title="Hardcoded secret in environment variable",
                                description=f"Container '{c_name}' in {name} has secret '{env_name}' hardcoded in plain text.",
                                resource=name,
                                recommendation="Use Kubernetes Secrets or external secret managers (Vault, Sealed Secrets) instead of plain-text env values.",
                            ))

    # Check Services
    for svc in resources.get("Service", []):
        name = get_resource_name(svc)
        svc_type = svc.get("spec", {}).get("type", "ClusterIP")
        if svc_type == "LoadBalancer":
            findings.append(Finding(
                agent="Security Agent",
                category="public-exposure",
                severity=Severity.HIGH,
                title="Public LoadBalancer service",
                description=f"{name} is a LoadBalancer service, publicly accessible.",
                resource=name,
                recommendation="Use ClusterIP with Ingress, or restrict with loadBalancerSourceRanges.",
            ))

    # Check RBAC
    for role_kind in ("ClusterRoleBinding", "RoleBinding"):
        for binding in resources.get(role_kind, []):
            name = get_resource_name(binding)
            role_ref = binding.get("roleRef", {})
            if role_ref.get("name") == "cluster-admin":
                findings.append(Finding(
                    agent="Security Agent",
                    category="rbac",
                    severity=Severity.CRITICAL,
                    title="cluster-admin binding",
                    description=f"{name} grants cluster-admin privileges.",
                    resource=name,
                    recommendation="Use least-privilege RBAC. Create specific roles.",
                ))

    for role_kind in ("ClusterRole", "Role"):
        for role in resources.get(role_kind, []):
            name = get_resource_name(role)
            for rule in role.get("rules", []):
                verbs = rule.get("verbs", [])
                api_resources = rule.get("resources", [])
                if "*" in verbs or "*" in api_resources:
                    findings.append(Finding(
                        agent="Security Agent",
                        category="rbac",
                        severity=Severity.HIGH,
                        title="Wildcard RBAC permissions",
                        description=f"{name} uses wildcard ('*') in verbs or resources.",
                        resource=name,
                        recommendation="Replace wildcards with specific verbs and resources.",
                    ))

    return findings


def run_terraform_security_rules(tf_resources: list) -> list[Finding]:
    """Run deterministic security checks on parsed Terraform resources."""
    findings = []

    for res in tf_resources:
        rtype = res.get("type", "")
        rname = res.get("name", "")
        config = res.get("config", {})
        full_name = f"{rtype}.{rname}"

        # --- AWS Security Group: unrestricted ingress ---
        if rtype == "aws_security_group":
            for ingress in config.get("ingress", []):
                cidr = ingress.get("cidr_blocks", [])
                if isinstance(cidr, list) and "0.0.0.0/0" in cidr:
                    from_port = ingress.get("from_port", "?")
                    to_port = ingress.get("to_port", "?")
                    findings.append(Finding(
                        agent="Security Agent", category="network",
                        severity=Severity.CRITICAL,
                        title="Security group open to 0.0.0.0/0",
                        description=f"{full_name} allows ingress from 0.0.0.0/0 on ports {from_port}-{to_port}.",
                        resource=full_name,
                        recommendation="Restrict CIDR blocks to specific IP ranges.",
                    ))

        # --- S3 bucket public access ---
        if rtype == "aws_s3_bucket":
            acl = config.get("acl", "private")
            if isinstance(acl, list):
                acl = acl[0] if acl else "private"
            if acl in ("public-read", "public-read-write"):
                findings.append(Finding(
                    agent="Security Agent", category="public-exposure",
                    severity=Severity.CRITICAL,
                    title="Public S3 bucket",
                    description=f"{full_name} has ACL '{acl}'. Data may be publicly accessible.",
                    resource=full_name,
                    recommendation="Set ACL to 'private' and use bucket policies for controlled access.",
                ))

        # --- S3 bucket encryption ---
        if rtype == "aws_s3_bucket":
            encryption = config.get("server_side_encryption_configuration")
            if not encryption:
                findings.append(Finding(
                    agent="Security Agent", category="encryption",
                    severity=Severity.HIGH,
                    title="S3 bucket without encryption",
                    description=f"{full_name} has no server-side encryption configured.",
                    resource=full_name,
                    recommendation="Enable server_side_encryption_configuration with AES256 or aws:kms.",
                ))

        # --- RDS public access ---
        if rtype == "aws_db_instance":
            if config.get("publicly_accessible") in (True, [True]):
                findings.append(Finding(
                    agent="Security Agent", category="public-exposure",
                    severity=Severity.CRITICAL,
                    title="RDS instance publicly accessible",
                    description=f"{full_name} is publicly accessible. Database exposed to internet.",
                    resource=full_name,
                    recommendation="Set publicly_accessible = false and use VPC endpoints.",
                ))
            if not config.get("storage_encrypted") or config.get("storage_encrypted") in (False, [False]):
                findings.append(Finding(
                    agent="Security Agent", category="encryption",
                    severity=Severity.HIGH,
                    title="RDS storage not encrypted",
                    description=f"{full_name} does not have storage encryption enabled.",
                    resource=full_name,
                    recommendation="Set storage_encrypted = true.",
                ))

        # --- Azure/GCP storage public access ---
        if rtype == "azurerm_storage_account":
            public_access = config.get("allow_nested_items_to_be_public", config.get("public_network_access_enabled"))
            if public_access in (True, [True], "Enabled", ["Enabled"]):
                findings.append(Finding(
                    agent="Security Agent", category="public-exposure",
                    severity=Severity.HIGH,
                    title="Azure storage account allows public access",
                    description=f"{full_name} allows public network access.",
                    resource=full_name,
                    recommendation="Set public_network_access_enabled = false.",
                ))

        # --- Hardcoded secrets in Terraform variables ---
        if rtype in ("aws_db_instance", "aws_rds_cluster", "azurerm_sql_server",
                      "google_sql_database_instance"):
            password = config.get("password") or config.get("administrator_login_password") or config.get("master_password")
            if password and isinstance(password, str) and not password.startswith("var.") and not password.startswith("$"):
                findings.append(Finding(
                    agent="Security Agent", category="hardcoded-secret",
                    severity=Severity.CRITICAL,
                    title="Hardcoded database password in Terraform",
                    description=f"{full_name} has a hardcoded password in the config.",
                    resource=full_name,
                    recommendation="Use var references or secret managers instead of plain-text passwords.",
                ))

        # --- IAM overly permissive policies ---
        if rtype in ("aws_iam_policy", "aws_iam_role_policy"):
            policy = str(config.get("policy", ""))
            if "'*'" in policy or '"*"' in policy:
                findings.append(Finding(
                    agent="Security Agent", category="iam",
                    severity=Severity.HIGH,
                    title="Overly permissive IAM policy",
                    description=f"{full_name} uses wildcard (*) actions or resources.",
                    resource=full_name,
                    recommendation="Follow least-privilege. Specify exact actions and resources.",
                ))

        # --- EC2 without IMDSv2 ---
        if rtype == "aws_instance":
            metadata = config.get("metadata_options", {})
            if isinstance(metadata, list):
                metadata = metadata[0] if metadata else {}
            if not metadata.get("http_tokens") or metadata.get("http_tokens") != "required":
                findings.append(Finding(
                    agent="Security Agent", category="instance-metadata",
                    severity=Severity.MEDIUM,
                    title="EC2 instance without IMDSv2",
                    description=f"{full_name} does not enforce IMDSv2 (http_tokens=required).",
                    resource=full_name,
                    recommendation="Set metadata_options { http_tokens = \"required\" } to prevent SSRF attacks.",
                ))

        # --- EBS volume not encrypted ---
        if rtype == "aws_ebs_volume":
            encrypted = config.get("encrypted")
            if not encrypted or encrypted in (False, [False]):
                findings.append(Finding(
                    agent="Security Agent", category="encryption",
                    severity=Severity.HIGH,
                    title="EBS volume not encrypted",
                    description=f"{full_name} does not have encryption enabled. Data at rest is unprotected.",
                    resource=full_name,
                    recommendation="Set encrypted = true and specify a kms_key_id.",
                ))

        # --- CloudTrail not enabled / missing ---
        if rtype == "aws_cloudtrail":
            if not config.get("enable_logging") or config.get("enable_logging") in (False, [False]):
                findings.append(Finding(
                    agent="Security Agent", category="logging",
                    severity=Severity.HIGH,
                    title="CloudTrail logging disabled",
                    description=f"{full_name} has logging disabled. No audit trail for API activity.",
                    resource=full_name,
                    recommendation="Set enable_logging = true for compliance and incident response.",
                ))
            if not config.get("is_multi_region_trail") or config.get("is_multi_region_trail") in (False, [False]):
                findings.append(Finding(
                    agent="Security Agent", category="logging",
                    severity=Severity.MEDIUM,
                    title="CloudTrail not multi-region",
                    description=f"{full_name} only covers one region. Activity in other regions is not audited.",
                    resource=full_name,
                    recommendation="Set is_multi_region_trail = true for full coverage.",
                ))
            if not config.get("enable_log_file_validation") or config.get("enable_log_file_validation") in (False, [False]):
                findings.append(Finding(
                    agent="Security Agent", category="logging",
                    severity=Severity.MEDIUM,
                    title="CloudTrail log validation disabled",
                    description=f"{full_name} does not validate log file integrity. Logs could be tampered.",
                    resource=full_name,
                    recommendation="Set enable_log_file_validation = true.",
                ))

        # --- VPC flow logs not enabled ---
        if rtype == "aws_vpc":
            # Note: flow logs are a separate resource (aws_flow_log), so absence is the concern.
            # We flag the VPC itself; the LLM handles cross-resource analysis.
            pass  # Handled by _check_missing_flow_logs below

        # --- ALB/ELB listener without HTTPS ---
        if rtype in ("aws_lb_listener", "aws_alb_listener"):
            protocol = config.get("protocol", "")
            if isinstance(protocol, list):
                protocol = protocol[0] if protocol else ""
            if protocol.upper() == "HTTP":
                port = config.get("port", "")
                if isinstance(port, list):
                    port = port[0] if port else ""
                findings.append(Finding(
                    agent="Security Agent", category="encryption-in-transit",
                    severity=Severity.HIGH,
                    title="Load balancer listener using HTTP (not HTTPS)",
                    description=f"{full_name} uses HTTP on port {port}. Traffic is unencrypted in transit.",
                    resource=full_name,
                    recommendation="Use protocol = \"HTTPS\" with a valid SSL certificate.",
                ))

        # --- RDS without SSL enforcement ---
        if rtype == "aws_db_parameter_group":
            params = config.get("parameter", [])
            if isinstance(params, list):
                ssl_params = [p for p in params if isinstance(p, dict) and p.get("name") == "rds.force_ssl"]
                for p in ssl_params:
                    val = p.get("value", "0")
                    if isinstance(val, list):
                        val = val[0] if val else "0"
                    if str(val) == "0":
                        findings.append(Finding(
                            agent="Security Agent", category="encryption-in-transit",
                            severity=Severity.MEDIUM,
                            title="RDS SSL not enforced",
                            description=f"{full_name} has rds.force_ssl = 0. Database connections may be unencrypted.",
                            resource=full_name,
                            recommendation="Set rds.force_ssl = 1 to enforce encrypted connections.",
                        ))

        # --- ECS task definition with privileged containers ---
        if rtype == "aws_ecs_task_definition":
            container_defs = config.get("container_definitions", "")
            if isinstance(container_defs, str) and '"privileged": true' in container_defs.lower().replace(" ", ""):
                findings.append(Finding(
                    agent="Security Agent", category="privileged",
                    severity=Severity.CRITICAL,
                    title="ECS privileged container",
                    description=f"{full_name} runs containers in privileged mode.",
                    resource=full_name,
                    recommendation="Remove privileged=true from container definitions.",
                ))

        # --- KMS key without rotation ---
        if rtype == "aws_kms_key":
            rotation = config.get("enable_key_rotation")
            if not rotation or rotation in (False, [False]):
                findings.append(Finding(
                    agent="Security Agent", category="encryption",
                    severity=Severity.MEDIUM,
                    title="KMS key rotation not enabled",
                    description=f"{full_name} does not have automatic key rotation enabled.",
                    resource=full_name,
                    recommendation="Set enable_key_rotation = true for key management best practices.",
                ))

        # --- Lambda without VPC (if processing sensitive data) ---
        if rtype == "aws_lambda_function":
            vpc_config = config.get("vpc_config")
            if not vpc_config:
                findings.append(Finding(
                    agent="Security Agent", category="network",
                    severity=Severity.LOW,
                    title="Lambda function not in VPC",
                    description=f"{full_name} runs outside a VPC. May have unrestricted internet access.",
                    resource=full_name,
                    recommendation="Place Lambda in a VPC if it accesses sensitive resources.",
                ))

        # --- GCP firewall rules open to 0.0.0.0/0 ---
        if rtype == "google_compute_firewall":
            source_ranges = config.get("source_ranges", [])
            if isinstance(source_ranges, list) and "0.0.0.0/0" in source_ranges:
                findings.append(Finding(
                    agent="Security Agent", category="network",
                    severity=Severity.CRITICAL,
                    title="GCP firewall open to 0.0.0.0/0",
                    description=f"{full_name} allows traffic from 0.0.0.0/0.",
                    resource=full_name,
                    recommendation="Restrict source_ranges to specific CIDR blocks.",
                ))

    # Cross-resource checks: VPC without flow logs
    vpc_ids = {r["name"] for r in tf_resources if r["type"] == "aws_vpc"}
    flow_log_vpcs = set()
    for r in tf_resources:
        if r["type"] == "aws_flow_log":
            vpc_id_ref = r.get("config", {}).get("vpc_id", "")
            if isinstance(vpc_id_ref, str):
                flow_log_vpcs.add(vpc_id_ref)
    for vpc_name in vpc_ids:
        # Check if any flow log references this VPC (heuristic: check if vpc name appears)
        has_flow_log = any(vpc_name in ref for ref in flow_log_vpcs)
        if not has_flow_log:
            findings.append(Finding(
                agent="Security Agent", category="logging",
                severity=Severity.MEDIUM,
                title="VPC without flow logs",
                description=f"aws_vpc.{vpc_name} has no associated aws_flow_log resource.",
                resource=f"aws_vpc.{vpc_name}",
                recommendation="Create an aws_flow_log resource to capture network traffic for security analysis.",
            ))

    return findings


def _detect_infra_type(file_contents: dict[str, str]) -> str:
    """Detect whether files are kubernetes, terraform, or mixed."""
    has_k8s = False
    has_tf = False
    for fname, content in file_contents.items():
        # Content-based detection first (handles pasted content with wrong extension)
        content_has_k8s = "apiVersion:" in content and "kind:" in content
        content_has_tf = (
            ("resource " in content or "provider " in content)
            and ("{" in content)
            and any(kw in content for kw in ("aws_", "azurerm_", "google_", "module ", "terraform {"))
        )
        if content_has_k8s:
            has_k8s = True
        if content_has_tf:
            has_tf = True
        # Fall back to extension only if content detection found nothing
        if not content_has_k8s and not content_has_tf:
            if fname.endswith((".yaml", ".yml")):
                has_k8s = True
            elif fname.endswith((".tf", ".hcl")):
                has_tf = True
    if has_k8s and has_tf:
        return "mixed"
    elif has_tf:
        return "terraform"
    return "kubernetes"


async def analyze_security(
    file_contents: dict[str, str], resources: dict, tf_resources: list | None = None
) -> AgentReport:
    """Run security analysis using rules + LLM reasoning."""
    # 1. Run deterministic rules
    rule_findings = run_security_rules(resources)
    if tf_resources:
        rule_findings.extend(run_terraform_security_rules(tf_resources))

    # 2. Select prompt based on file type
    infra_type = _detect_infra_type(file_contents)
    if infra_type == "terraform":
        system_prompt = SECURITY_TF_PROMPT
    else:
        system_prompt = SECURITY_K8S_PROMPT

    # 3. Use LLM for deeper analysis
    llm = get_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Analyze the following infrastructure files for security issues:\n\n{infra_content}"),
    ])

    infra_content = ""
    for fname, content in file_contents.items():
        infra_content += f"\n--- {fname} ---\n{content}\n"

    chain = prompt | llm
    try:
        response = await chain.ainvoke({"infra_content": infra_content})
        response_text = response.content.strip()
        # Clean markdown code block if present
        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1]
            response_text = response_text.rsplit("```", 1)[0]

        llm_result = json.loads(response_text)
        llm_findings = []
        for f in llm_result.get("findings", []):
            llm_findings.append(Finding(
                agent="Security Agent",
                category="ai-analysis",
                severity=Severity(f.get("severity", "medium")),
                title=f.get("title", ""),
                description=f.get("description", ""),
                resource=f.get("resource", ""),
                recommendation=f.get("recommendation", ""),
            ))
        llm_summary = llm_result.get("summary", "")
        llm_score = llm_result.get("score", 50)
    except Exception:
        llm_findings = []
        llm_summary = ""
        llm_score = None

    # 3. Merge findings (rules + LLM), deduplicate by keyword overlap
    all_findings = rule_findings[:]
    for f in llm_findings:
        if not _is_duplicate(f, rule_findings):
            all_findings.append(f)

    # 4. Calculate score
    deductions = {
        Severity.CRITICAL: 20,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }
    rule_score = 100
    for f in all_findings:
        rule_score -= deductions[f.severity]
    rule_score = max(0, rule_score)

    # When LLM is available, blend scores; otherwise use rule score directly
    if llm_score is not None:
        final_score = round(rule_score * 0.6 + llm_score * 0.4, 1)
    else:
        final_score = float(rule_score)

    return AgentReport(
        agent_name="Security Agent",
        findings=all_findings,
        summary=llm_summary or f"Found {len(all_findings)} security issues.",
        score=final_score,
    )
