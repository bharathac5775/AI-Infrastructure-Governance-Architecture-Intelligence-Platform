"""Phase 3.4 — Auto-Remediation Agent.

Given a Finding plus the original uploaded file bundle, generate a Patch that
fixes the finding. The strategy:

1. **File discovery** — locate which uploaded file contains the resource named
   by the finding (re-parse all files, match by resource type/name/kind).
2. **Deterministic fixer** — for known rule categories, hand-code the edit
   (PyYAML round-trip for K8s; surgical HCL block injection for Terraform).
3. **LLM fallback** — when no deterministic fixer exists (e.g. ``category="ai-analysis"``
   findings produced by the LLM at scan time), call the local model with a
   constrained prompt that returns the full patched file as a JSON string.
4. **Validation** — re-parse every patched output. Reject patches that don't
   parse. For LLM patches, retry once before giving up.

We never write to disk. The Patch object is returned over the API and rendered
in the UI for the user to copy.
"""
from __future__ import annotations

import asyncio
import difflib
import json
import logging
import re
from typing import Any, Optional

import yaml

from app.core.llm import get_llm
from app.core.skills import load_skill
from app.models import Finding, Patch, Severity
from app.parsers.kubernetes import (
    extract_k8s_resources,
    parse_kubernetes_yaml,
)
from app.parsers.terraform import extract_tf_resources, parse_terraform

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class RemediationError(Exception):
    """Raised when remediation cannot proceed (no file match, no fixer, etc.)."""


class NonPatchableFinding(RemediationError):
    """The finding is advisory — it has no associated resource in any file
    and is not something a code patch can fix (e.g. "Lack of Commitment
    Discounts" recommending a Reserved Instances purchase). The frontend
    should hide the Generate-fix button for these."""


class CompanionResourceRequired(NonPatchableFinding):
    """The finding requires creating a NEW Kubernetes resource alongside
    the existing one — e.g., a HorizontalPodAutoscaler for the workload,
    a PodDisruptionBudget, or a NetworkPolicy. These can't be patched
    into the existing file because:

    1. JSON files cannot hold multiple top-level resources, and
    2. Even YAML multi-doc concatenation is fragile when the source was
       Helm-rendered or kustomize-generated and the user round-trips.

    The frontend renders the companion YAML template inline so the user
    can copy it into a new file. Distinct from regular NonPatchable
    findings so the UI can format the message differently (with the
    template body in a code block).
    """
    def __init__(self, message: str, template: str = "", filename: str = ""):
        super().__init__(message)
        self.template = template
        self.filename = filename


class PatchValidationError(Exception):
    """Raised when a generated patch produces unparseable output."""


# Resource values that mean "no specific resource". These findings are
# advisories about the infrastructure overall (purchasing decisions, missing
# whole-architecture concerns) and cannot be remediated by a code patch.
_NON_PATCHABLE_RESOURCE_VALUES: set[str] = {
    "", "n/a", "na", "none", "null", "-",
    "infrastructure", "all", "global", "various", "multiple",
}


# ---------------------------------------------------------------------------
# Companion-resource categories (Phase 3.4)
#
# These reliability/security findings require ADDING a brand-new Kubernetes
# resource (HPA, PodDisruptionBudget, NetworkPolicy) rather than editing
# fields inside the existing workload. We can't safely express that as a
# single-file in-place patch — especially for .json manifests, which
# physically can't hold multiple top-level resources — so we surface a
# clear message + a YAML template the user can copy into a new file.
# ---------------------------------------------------------------------------


_COMPANION_RESOURCE_CATEGORIES: set[str] = {"autoscaling", "pdb", "network-policy"}

# Phase 3.5 — roll-up / meta findings emitted by plugin agents (e.g. the
# Compliance Agent) summarize OTHER findings against a framework and point at a
# Categories that are NEVER individually patchable by a code diff:
# - "compliance-gap": roll-up meta-findings pointing at a framework id, not a
#   runtime resource. Fix by remediating the underlying findings.
# - "resilience": SPOF/architecture observations (this resource is structurally
#   central). The fix is a human design decision (add redundancy / decouple),
#   not a mechanical single-attribute edit.
# Detected up-front so the remediator returns a clean, meaningful refusal
# instead of falling through to the LLM (which mangles/drops resources).
_NON_PATCHABLE_CATEGORIES: set[str] = {"compliance-gap", "resilience"}


def _companion_template(category: str, finding: Finding) -> tuple[str, str]:
    """Return (yaml_template, suggested_filename) for the companion
    resource implied by this finding. Templates use CHANGE_ME_ prefixes
    for values the user must edit. The workload name is best-effort
    extracted from the finding resource (Kind/ns/name)."""
    parts = (finding.resource or "").split("/")
    workload_name = parts[-1] if parts else "CHANGE_ME_WORKLOAD"
    namespace = parts[1] if len(parts) >= 3 else "default"
    workload_kind = parts[0] if len(parts) >= 2 else "Deployment"

    if category == "autoscaling":
        tmpl = (
            f"apiVersion: autoscaling/v2\n"
            f"kind: HorizontalPodAutoscaler\n"
            f"metadata:\n"
            f"  name: {workload_name}-hpa\n"
            f"  namespace: {namespace}\n"
            f"spec:\n"
            f"  scaleTargetRef:\n"
            f"    apiVersion: apps/v1\n"
            f"    kind: {workload_kind}\n"
            f"    name: {workload_name}\n"
            f"  minReplicas: 2  # CHANGE_ME — minimum healthy replicas\n"
            f"  maxReplicas: 10  # CHANGE_ME — upper bound for cost protection\n"
            f"  metrics:\n"
            f"    - type: Resource\n"
            f"      resource:\n"
            f"        name: cpu\n"
            f"        target:\n"
            f"          type: Utilization\n"
            f"          averageUtilization: 70  # CHANGE_ME — scale-out threshold\n"
        )
        return tmpl, f"{workload_name}-hpa.yaml"

    if category == "pdb":
        tmpl = (
            f"apiVersion: policy/v1\n"
            f"kind: PodDisruptionBudget\n"
            f"metadata:\n"
            f"  name: {workload_name}-pdb\n"
            f"  namespace: {namespace}\n"
            f"spec:\n"
            f"  minAvailable: 1  # CHANGE_ME — or use maxUnavailable instead\n"
            f"  selector:\n"
            f"    matchLabels:\n"
            f"      app: {workload_name}  # CHANGE_ME — match your workload's pod labels\n"
        )
        return tmpl, f"{workload_name}-pdb.yaml"

    if category == "network-policy":
        tmpl = (
            f"apiVersion: networking.k8s.io/v1\n"
            f"kind: NetworkPolicy\n"
            f"metadata:\n"
            f"  name: {workload_name}-netpol\n"
            f"  namespace: {namespace}\n"
            f"spec:\n"
            f"  podSelector:\n"
            f"    matchLabels:\n"
            f"      app: {workload_name}  # CHANGE_ME — match your workload's pod labels\n"
            f"  policyTypes:\n"
            f"    - Ingress\n"
            f"    - Egress\n"
            f"  ingress:\n"
            f"    - from:\n"
            f"        - podSelector:\n"
            f"            matchLabels:\n"
            f"              app: CHANGE_ME_ALLOWED_CALLER\n"
            f"  egress:\n"
            f"    - to:\n"
            f"        - namespaceSelector: {{}}\n"
            f"      ports:\n"
            f"        - protocol: TCP\n"
            f"          port: 443  # CHANGE_ME — restrict to actual egress targets\n"
        )
        return tmpl, f"{workload_name}-netpol.yaml"

    # Fallback for any future category we mark as companion but haven't
    # written a template for yet
    return ("", "")


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


_K8S_EXT = (".yaml", ".yml")
_TF_HCL_EXT = (".tf", ".hcl")
_TF_JSON_EXT = (".json",)


def _filename_kind(filename: str) -> str:
    """Return one of: 'kubernetes_yaml', 'terraform_hcl', 'terraform_json',
    or 'unknown'."""
    lower = filename.lower()
    if lower.endswith(_K8S_EXT):
        return "kubernetes_yaml"
    if lower.endswith(_TF_HCL_EXT):
        return "terraform_hcl"
    if lower.endswith(_TF_JSON_EXT):
        return "terraform_json"
    return "unknown"


def is_non_patchable(finding: Finding) -> bool:
    """Return True for findings that don't map to any file-level edit.

    These are typically advisory findings about purchasing decisions, missing
    whole-architecture concerns, or items where the LLM filled the resource
    field with a sentinel ("N/A", "infrastructure", etc.) because there's
    no specific resource to patch.
    """
    resource = (finding.resource or "").strip().lower()
    return resource in _NON_PATCHABLE_RESOURCE_VALUES


# Words that signal the LLM produced a *decision* finding rather than a
# concrete code change — "Analyze your usage to determine if X is right" is
# not a patch, it's homework for the user. The LLM's recommendation field
# starting with one of these verbs is a strong signal that no code patch
# can fix it without external context the platform doesn't have.
#
# Limited to the FIRST word of the recommendation so we don't false-positive
# on real fixes that happen to mention "monitor" or "consider" later.
_ADVISORY_RECOMMENDATION_VERBS: tuple[str, ...] = (
    "analyze",
    "monitor",
    "consider",
    "evaluate",
    "review",
    "determine",
    "investigate",
    "audit",
    "assess",
    # "Maintain X" / "Continue using X" — recommendations that praise the
    # current config and ask the user to keep doing it. The Cost Agent
    # often emits these when the resource is already cost-efficient.
    "maintain",
    "continue",
    "keep",
)


# Recommendation prefixes that signal "no code change needed" — the LLM
# is congratulating the user on what they've already done correctly. These
# are praise findings, not bugs to fix. Match against the lowercased start
# of the recommendation.
_NO_ACTION_PHRASES: tuple[str, ...] = (
    "no immediate action",
    "no action",
    "no change",
    "no changes",
    "no fix",
    "this is already",
    "this is a recommended",
    "this is best practice",
    "this is correct",
    "this is the recommended",
    "already configured",
    "already enabled",
    "already in place",
    "already meets",
    "already follows",
    "the current configuration is correct",
    "the configuration is already",
)


def _is_advisory_language(finding: Finding) -> bool:
    """True when the finding's recommendation reads like a decision/research
    task, a praise note, or a "no action needed" advisory rather than a
    concrete code-level fix.

    Two conditions must hold:
      1. ``finding.category == "ai-analysis"`` — rule-engine findings always
         carry concrete fixers, so we never want to misclassify one.
      2. The recommendation matches one of:
         - First word in :data:`_ADVISORY_RECOMMENDATION_VERBS`
         - Recommendation starts with a phrase in :data:`_NO_ACTION_PHRASES`

    The category guard means a deterministic fix that happens to use one of
    these verbs ("Monitor the impact after applying...") cannot accidentally
    be marked non-patchable.
    """
    if finding.category != "ai-analysis":
        return False
    rec = (finding.recommendation or "").strip()
    if not rec:
        return False
    rec_lower = rec.lower()
    # No-action phrase match (full prefix, case-insensitive)
    for phrase in _NO_ACTION_PHRASES:
        if rec_lower.startswith(phrase):
            return True
    # First-word verb match
    first_word = rec.split(maxsplit=1)[0].strip(".,:;").lower()
    return first_word in _ADVISORY_RECOMMENDATION_VERBS


# ---------------------------------------------------------------------------
# Inference: route ai-analysis findings to deterministic fixers
# ---------------------------------------------------------------------------
#
# The Reliability/Cost agents emit findings with ``category="ai-analysis"``
# that frequently describe issues the rule engine ALREADY has a deterministic
# fixer for — just with an LLM-paraphrased title (e.g. "Publicly Accessible
# Database" instead of the rule-engine's "RDS instance publicly accessible").
#
# Without inference, every ai-analysis finding falls through to the slow
# LLM remediation path (~120s+ per attempt on a 7B local model, 2 attempts
# per call). With inference, semantically-identical findings get the
# instant deterministic fix.
#
# Each entry is (set of title keywords, optional resource-type prefix tuple,
# target rule-engine category). All keywords must appear in the title (case-
# insensitive). If `resource_prefixes` is non-empty, the finding's resource
# type must start with one of them. The first matching entry wins.
_AI_CATEGORY_INFERENCE: tuple[tuple[tuple[str, ...], tuple[str, ...], str], ...] = (
    # ----- Public exposure -----
    (("publicly", "accessible"), ("aws_db_instance", "aws_rds"), "public-exposure"),
    (("public", "database"),     ("aws_db_instance", "aws_rds"), "public-exposure"),
    (("public", "rds"),          ("aws_db_instance", "aws_rds"), "public-exposure"),
    (("public", "bucket"),       ("aws_s3_bucket",), "public-exposure"),
    (("public", "s3"),           ("aws_s3_bucket",), "public-exposure"),
    (("public", "ip"),           ("google_sql_database_instance",), "public-exposure"),
    # ----- Encryption at rest -----
    (("unencrypted", "ebs"),       ("aws_ebs_volume",), "encryption"),
    (("ebs", "not", "encrypted"),  ("aws_ebs_volume",), "encryption"),
    (("ebs", "encryption"),        ("aws_ebs_volume",), "encryption"),
    (("unencrypted", "rds"),       ("aws_db_instance", "aws_rds"), "encryption"),
    (("unencrypted", "database"),  ("aws_db_instance", "aws_rds"), "encryption"),
    (("rds", "encryption"),        ("aws_db_instance", "aws_rds"), "encryption"),
    (("unencrypted", "s3"),        ("aws_s3_bucket",), "encryption"),
    (("unencrypted", "bucket"),    ("aws_s3_bucket",), "encryption"),
    (("s3", "encryption"),         ("aws_s3_bucket",), "encryption"),
    (("bucket", "encryption"),     ("aws_s3_bucket",), "encryption"),
    (("kms", "rotation"),          ("aws_kms_key",), "encryption"),
    (("key", "rotation"),          ("aws_kms_key",), "encryption"),
    # ----- Encryption in transit -----
    (("http", "listener"),         ("aws_lb_listener", "aws_alb_listener"), "encryption-in-transit"),
    (("https", "listener"),        ("aws_lb_listener", "aws_alb_listener"), "encryption-in-transit"),
    (("alb", "http"),              ("aws_lb_listener", "aws_alb_listener"), "encryption-in-transit"),
    # ----- Hardcoded secrets -----
    (("hardcoded", "password"),    (), "hardcoded-secret"),
    (("hardcoded", "secret"),      (), "hardcoded-secret"),
    (("hardcoded", "credential"),  (), "hardcoded-secret"),
    (("plain", "text", "password"),(), "hardcoded-secret"),
    # ----- Logging -----
    (("cloudtrail", "logging", "disabled"), ("aws_cloudtrail",), "logging"),
    (("cloudtrail", "disabled"),            ("aws_cloudtrail",), "logging"),
    (("no", "cloudtrail"),                  ("aws_cloudtrail",), "logging"),
    (("cloudtrail", "multi-region"),        ("aws_cloudtrail",), "logging"),
    (("cloudtrail", "log", "validation"),   ("aws_cloudtrail",), "logging"),
    (("vpc", "flow", "logs"),               ("aws_vpc",), "logging"),
    (("flow", "logs"),                      ("aws_vpc",), "logging"),
    # ----- Instance metadata -----
    (("imdsv2",),                  ("aws_instance", "aws_launch_template"), "instance-metadata"),
    (("imds", "v2"),               ("aws_instance", "aws_launch_template"), "instance-metadata"),
    (("metadata", "service"),      ("aws_instance", "aws_launch_template"), "instance-metadata"),
    # ----- Network: 0.0.0.0/0 ingress -----
    (("0.0.0.0/0",),               ("aws_security_group", "google_compute_firewall"), "network"),
    (("open", "internet"),         ("aws_security_group", "azurerm_network_security"), "network"),
    (("permissive", "ingress"),    ("aws_security_group",), "network"),
    (("permissive", "egress"),     ("aws_security_group",), "network"),
    # ----- High availability (zone redundancy / Multi-AZ) -----
    (("zone", "redundan"),         ("azurerm_mssql_database", "azurerm_sql"), "high-availability"),
    (("zone-redundant",),          ("azurerm_mssql_database", "azurerm_sql"), "high-availability"),
    (("multi-az",),                ("aws_db_instance", "aws_rds"), "high-availability"),
    (("availability", "zone"),     ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine"), "high-availability"),
    # ----- Backup / recoverability (Azure Key Vault deletion protection) -----
    (("purge", "protection"),      ("azurerm_key_vault",), "backup"),
    (("deletion", "protection"),   ("azurerm_key_vault",), "backup"),
    (("soft", "delete"),           ("azurerm_key_vault",), "backup"),
    (("deletion", "protection"),   ("aws_db_instance", "aws_rds"), "backup"),
)


def _infer_rule_category(finding: Finding) -> str | None:
    """If ``finding.category == "ai-analysis"``, try to infer the equivalent
    rule-engine category from the title + resource type. Returns the inferred
    category string, or ``None`` if no inference applies (caller falls back
    to the LLM).

    Conservative: requires ALL title keywords to be present and (when set) a
    resource-prefix match. Designed to never misroute — if in doubt, return
    None and let the LLM handle it.
    """
    if finding.category != "ai-analysis":
        return None
    title_lower = (finding.title or "").lower()
    resource = (finding.resource or "").strip()
    rtype = resource.partition(".")[0]
    for keywords, resource_prefixes, target_cat in _AI_CATEGORY_INFERENCE:
        if not all(kw in title_lower for kw in keywords):
            continue
        if resource_prefixes and not any(rtype.startswith(p) for p in resource_prefixes):
            continue
        return target_cat
    return None


def _looks_like_file_path(resource: str) -> bool:
    """True if the resource string looks like a Helm template path or a
    file path rather than a Kubernetes resource name.

    The LLM occasionally emits ``my-chart/templates/deployment.yaml`` or
    similar in the resource field — those are template source paths, not
    runtime resources. The bundle the user uploaded contains the
    *rendered* YAML (post-helm), so the template path won't locate
    anything via the standard ``Kind/namespace/name`` matcher.
    """
    if not resource:
        return False
    r = resource.strip().lower()
    file_extensions = (".yaml", ".yml", ".json", ".tf", ".hcl", ".tgz")
    if any(r.endswith(ext) for ext in file_extensions):
        return True
    # Helm template idiom: chart-name/templates/file.yaml. Match any path
    # segment containing "templates/" since that's the convention.
    if "/templates/" in r:
        return True
    # LLM-emitted "filename.ext (annotation)" shape — common when the
    # Helm-rendered manifest source path is annotated with the chart
    # name in parens, e.g. "deployment.yaml (good-chart)" or
    # "serviceaccount.yaml (chart-1.0.0)".
    if " (" in r and r.endswith(")"):
        prefix = r.split(" (", 1)[0].strip()
        if any(prefix.endswith(ext) for ext in file_extensions):
            return True
        if "/templates/" in prefix:
            return True
    return False


def _locate_file_for_finding(
    finding: Finding, file_contents: dict[str, str]
) -> tuple[str, str, str]:
    """Find which uploaded file holds the resource the finding is about.

    Returns ``(filename, kind, content)`` where ``kind`` is one of
    ``kubernetes_yaml`` / ``terraform_hcl`` / ``terraform_json``.

    Raises ``NonPatchableFinding`` if the finding is advisory (resource is
    "N/A", "infrastructure", empty, etc.) — these can't be auto-remediated.
    Raises ``RemediationError`` if no file matches a real resource.

    Matching strategy:
    - Terraform finding (``resource`` looks like ``aws_*.<name>``,
      ``azurerm_*.<name>``, or ``google_*.<name>``): re-parse all
      ``.tf``/``.hcl``/``.json`` files and locate the one with that resource.
    - Kubernetes finding (``resource`` looks like ``Kind/.../name`` or just
      a bare resource name): re-parse all ``.yaml``/``.yml`` files and locate
      the one whose document(s) contain a matching name.
    - File-path-shaped resource strings (``my-chart/templates/deployment.yaml``,
      ``some-file.yaml``): the LLM emitted a Helm-template path or
      filename instead of a runtime resource name. We treat these as
      non-patchable because we cannot reliably round-trip a template
      through Helm to apply a fix. The user gets a clear message.
    """
    resource = (finding.resource or "").strip()
    if not resource:
        raise NonPatchableFinding(
            "This finding has no associated resource — it's an advisory "
            "that cannot be fixed by editing a single file."
        )
    if is_non_patchable(finding):
        raise NonPatchableFinding(
            f"This is an advisory finding (resource: {finding.resource!r}) — "
            "it describes a whole-infrastructure or purchasing decision "
            "that cannot be fixed by a code patch."
        )
    if _looks_like_file_path(resource):
        raise NonPatchableFinding(
            f"Resource {finding.resource!r} looks like a file or Helm "
            "template path, not a runtime resource. The platform analyzes "
            "rendered output, so source templates cannot be patched here. "
            "Find the rendered finding for the same workload to remediate."
        )
    if _is_advisory_language(finding):
        # The LLM produced a decision/research finding, not a concrete fix.
        # Examples: "Analyze historical throughput to decide between
        # PAY_PER_REQUEST and Provisioned Capacity", "Consider Reserved
        # Instances for stable workloads", "Monitor actual CPU usage and
        # adjust limits". The platform doesn't have the workload data needed
        # to make these decisions, so we surface them as advisories instead
        # of wasting LLM cycles trying to remediate them.
        raise NonPatchableFinding(
            f"This is an advisory finding — its recommendation begins with "
            f"a decision verb (\"{finding.recommendation.split(maxsplit=1)[0]}\"), "
            "meaning it asks you to evaluate or analyze something, not to "
            "apply a specific code change. Auto-remediation can't make that "
            "decision for you."
        )

    # Heuristic: TF resources start with a known provider prefix
    tf_prefixes = (
        "aws_", "azurerm_", "google_", "azuread_", "googleworkspace_",
        "kubernetes_", "helm_", "random_", "tls_",
    )
    is_tf_like = any(resource.startswith(p) for p in tf_prefixes)

    if is_tf_like:
        return _locate_terraform_file(resource, file_contents)

    return _locate_kubernetes_file(resource, file_contents)


def _locate_terraform_file(
    resource: str, file_contents: dict[str, str]
) -> tuple[str, str, str]:
    """Locate the .tf/.hcl/.json file containing ``aws_foo.bar``."""
    if "." not in resource:
        raise RemediationError(
            f"Terraform-like resource '{resource}' missing dotted local name."
        )
    rtype, _, rname = resource.partition(".")
    # Some findings include nested attributes like ``aws_iam_policy.foo.policy``;
    # we only need the first segment after the type.
    rname = rname.split(".", 1)[0]

    for filename, content in file_contents.items():
        kind = _filename_kind(filename)
        if kind not in ("terraform_hcl", "terraform_json"):
            continue
        try:
            if kind == "terraform_hcl":
                parsed = parse_terraform(content)
            else:
                parsed = json.loads(content)
                # Skip JSON files that aren't Terraform JSON
                if not isinstance(parsed, dict) or not (
                    parsed.get("resource") or parsed.get("terraform")
                ):
                    continue
            resources = extract_tf_resources(parsed)
        except Exception:
            continue
        for r in resources:
            if r.get("type") == rtype and r.get("name") == rname:
                return filename, kind, content

    raise RemediationError(
        f"Could not locate Terraform resource '{resource}' in any uploaded file."
    )


def _locate_kubernetes_file(
    resource: str, file_contents: dict[str, str]
) -> tuple[str, str, str]:
    """Locate the .yaml/.yml file containing the named K8s resource.

    The canonical resource shape is ``Kind/namespace/name`` (set by
    ``get_resource_name`` in app/parsers/kubernetes.py). The LLM
    occasionally emits other shapes — ``Kind/name`` (no namespace) or
    chart-style names like ``Deployment/my-chart`` against rendered
    workloads named ``release-my-chart``. We tolerate these via a
    layered match strategy:

    1. **Exact 3-segment** — Kind, namespace, AND name all match
    2. **Exact 2-segment** — Kind + name match, any namespace
    3. **Substring within Kind** — name is a substring (or super-string)
       of exactly one workload of the same Kind in the bundle
    4. **Single-workload-of-Kind fallback** — bundle has exactly one
       workload of the target Kind; use it regardless of name

    The fallbacks only fire when the match is **unambiguous** — never
    pick one of multiple candidates silently.
    """
    parts = resource.split("/")
    if len(parts) == 3:
        target_kind, target_namespace, target_name = parts
    elif len(parts) == 2:
        target_kind, target_namespace, target_name = parts[0], None, parts[1]
    elif len(parts) == 1:
        target_kind, target_namespace, target_name = None, None, parts[0]
    else:
        # Unusual — too many segments. Keep last as name, first as kind.
        target_kind, target_namespace, target_name = parts[0], None, parts[-1]

    # Pre-walk: gather every K8s document in the bundle, indexed for fuzzy
    # matching across files. We need the full picture to decide whether a
    # fallback match is unambiguous.
    walked: list[tuple[str, str, str, dict]] = []  # (filename, kind_label, content, doc)
    for filename, content in file_contents.items():
        fkind = _filename_kind(filename)
        if fkind == "kubernetes_yaml":
            try:
                docs = parse_kubernetes_yaml(content)
            except Exception:
                continue
            for d in docs:
                if isinstance(d, dict):
                    walked.append((filename, "kubernetes_yaml", content, d))
        elif fkind == "terraform_json":
            # K8s JSON manifests may be uploaded with .json extension
            try:
                doc = json.loads(content)
            except Exception:
                continue
            if isinstance(doc, dict) and doc.get("kind") and doc.get("apiVersion"):
                walked.append((filename, "kubernetes_json", content, doc))

    if not walked:
        raise RemediationError(
            f"Could not locate Kubernetes resource '{resource}' — no Kubernetes "
            "files in the upload."
        )

    def _doc_kind(d: dict) -> Optional[str]:
        return d.get("kind")

    def _doc_name(d: dict) -> Optional[str]:
        return (d.get("metadata") or {}).get("name")

    def _doc_namespace(d: dict) -> Optional[str]:
        return (d.get("metadata") or {}).get("namespace")

    # Layer 1: exact 3-segment
    if target_kind and target_namespace and target_name:
        for filename, kind_label, content, d in walked:
            if (
                _doc_kind(d) == target_kind
                and (_doc_namespace(d) or "default") == target_namespace
                and _doc_name(d) == target_name
            ):
                return filename, kind_label, content

    # Layer 2: exact 2-segment (Kind + name, any namespace)
    if target_kind and target_name:
        candidates = [
            (filename, kind_label, content)
            for filename, kind_label, content, d in walked
            if _doc_kind(d) == target_kind and _doc_name(d) == target_name
        ]
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            # Same Kind+name in multiple files/namespaces. Prefer the one
            # whose namespace matches if a namespace was specified;
            # otherwise this is genuinely ambiguous.
            if target_namespace:
                ns_candidates = [
                    (filename, kind_label, content)
                    for filename, kind_label, content, d in walked
                    if _doc_kind(d) == target_kind
                    and _doc_name(d) == target_name
                    and (_doc_namespace(d) or "default") == target_namespace
                ]
                if len(ns_candidates) == 1:
                    return ns_candidates[0]
            raise RemediationError(
                f"Resource '{resource}' is ambiguous — {len(candidates)} "
                "matching documents in the upload."
            )

    # Layer 3: substring within Kind. The LLM sometimes uses chart-style
    # names ("my-chart") against rendered workloads ("release-my-chart").
    if target_kind and target_name:
        substr_candidates = [
            (filename, kind_label, content)
            for filename, kind_label, content, d in walked
            if _doc_kind(d) == target_kind
            and _doc_name(d)
            and (
                target_name in _doc_name(d)
                or _doc_name(d) in target_name
            )
        ]
        if len(substr_candidates) == 1:
            return substr_candidates[0]
        # Multiple substring matches: don't guess; fall through to layer 4.

    # Layer 4: single-workload-of-Kind fallback. Bundle has exactly one
    # workload of the target Kind — assume the LLM means that one.
    if target_kind:
        kind_only = [
            (filename, kind_label, content)
            for filename, kind_label, content, d in walked
            if _doc_kind(d) == target_kind
        ]
        if len(kind_only) == 1:
            return kind_only[0]

    # Layer 5 (last resort): exact name match across all Kinds. Catches
    # 1-segment "release-my-chart" findings.
    if target_name and not target_kind:
        name_candidates = [
            (filename, kind_label, content)
            for filename, kind_label, content, d in walked
            if _doc_name(d) == target_name
        ]
        if len(name_candidates) == 1:
            return name_candidates[0]

    raise RemediationError(
        f"Could not locate Kubernetes resource '{resource}' in any uploaded file."
    )


# ---------------------------------------------------------------------------
# Validation — every patch must re-parse cleanly
# ---------------------------------------------------------------------------


def _validate_patch(filename: str, kind: str, patched: str) -> None:
    """Re-parse the patched output. Raise PatchValidationError if it fails."""
    if not patched.strip():
        raise PatchValidationError("Patched content is empty.")
    try:
        if kind == "kubernetes_yaml":
            docs = parse_kubernetes_yaml(patched)
            if not docs:
                raise PatchValidationError("Patched YAML has no documents.")
        elif kind == "kubernetes_json":
            doc = json.loads(patched)
            if not isinstance(doc, dict) or not doc.get("kind"):
                raise PatchValidationError("Patched K8s JSON is malformed.")
        elif kind == "terraform_hcl":
            parse_terraform(patched)
        elif kind == "terraform_json":
            obj = json.loads(patched)
            if not isinstance(obj, dict):
                raise PatchValidationError("Patched Terraform JSON is not an object.")
        else:
            # Unknown kind — accept without validation
            return
    except PatchValidationError:
        raise
    except Exception as e:
        raise PatchValidationError(f"Patched content failed to parse: {e}")


def _count_resources(content: str, kind: str) -> int:
    """Count the number of top-level resources in a patched file.

    Used by :func:`_verify_no_resources_dropped` as a structural-preservation
    safety check after LLM-generated patches. Local LLMs (and even cloud
    LLMs occasionally) sometimes drop documents from multi-resource files
    while focused on adding/editing one specific thing — this is the
    silent-data-loss failure mode we caught in the wild on
    ``samples/critical-security-failure.yaml`` (LLM kept the Deployment,
    deleted the Service AND the ClusterRoleBinding).

    Returns -1 if counting fails for any reason — callers must handle
    this as "unknown, can't verify" rather than treating it as zero.
    """
    if not content or not content.strip():
        return 0
    try:
        if kind == "kubernetes_yaml":
            docs = parse_kubernetes_yaml(content)
            return sum(1 for d in docs if isinstance(d, dict) and d.get("kind"))
        if kind == "kubernetes_json":
            obj = json.loads(content)
            if isinstance(obj, dict) and obj.get("kind"):
                return 1
            if isinstance(obj, list):
                return sum(1 for d in obj if isinstance(d, dict) and d.get("kind"))
            # K8s List shape
            if isinstance(obj, dict) and obj.get("items"):
                return sum(1 for d in obj["items"] if isinstance(d, dict) and d.get("kind"))
            return 0
        if kind == "terraform_hcl":
            parsed = parse_terraform(content)
            return len(extract_tf_resources(parsed))
        if kind == "terraform_json":
            obj = json.loads(content)
            if not isinstance(obj, dict):
                return -1
            res = obj.get("resource") or {}
            if not isinstance(res, dict):
                return -1
            # Count (type, name) pairs across the resource section
            total = 0
            for _rtype, instances in res.items():
                if isinstance(instances, dict):
                    total += len(instances)
                elif isinstance(instances, list):
                    total += sum(len(b) for b in instances if isinstance(b, dict))
            return total
    except Exception:
        return -1
    return -1


def _verify_no_resources_dropped(
    original: str, patched: str, kind: str
) -> None:
    """Raise :class:`PatchValidationError` if the patch removed top-level
    resources from the file.

    This is the structural-preservation safety net for LLM-generated
    patches. Adding resources is allowed (e.g., LLM appends an HPA
    companion). Removing resources is REJECTED — except for the rare
    case where both counts are unknown (-1), which we treat as
    inconclusive and let through (the parser-level ``_validate_patch``
    is a separate safety layer).

    Why this matters: ``_validate_patch`` only checks "does this parse?"
    A patch that drops two of three documents from a multi-doc YAML
    still parses cleanly — leaving a confidence-collapse vector where
    the user trusts the patch and silently loses production resources.
    """
    before = _count_resources(original, kind)
    after = _count_resources(patched, kind)
    # Either count failed: skip the check (don't false-fail on edge cases)
    if before < 0 or after < 0:
        return
    if after < before:
        raise PatchValidationError(
            f"LLM patch dropped {before - after} resource(s) from your file "
            f"(was {before}, now {after}). Refusing to apply — this would "
            "silently delete resources from your cluster on apply. "
            "Re-generate the fix or apply the change manually."
        )


# ---------------------------------------------------------------------------
# Diff generation
# ---------------------------------------------------------------------------


def _make_unified_diff(filename: str, original: str, patched: str) -> str:
    """Return a unified-diff string. Empty if the contents are identical."""
    if original == patched:
        return ""
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            n=3,
        )
    )


# ---------------------------------------------------------------------------
# Whitespace-tolerant filter for LLM patches
#
# Local LLMs (Gemma, Llama, etc.) sometimes reformat horizontal-rule comments
# like ``# ----------------`` — emitting fewer or more dashes than the
# original. The IaC parses fine, but the unified diff fills with cosmetic
# hunks that drown out the real edit. We post-process the LLM output by
# diffing against the original line-by-line and reverting any line that
# differs ONLY in cosmetic whitespace / dash-count drift on a comment line
# (or pure trailing-whitespace drift on any line).
# ---------------------------------------------------------------------------


def _is_cosmetic_drift(orig_line: str, new_line: str) -> bool:
    """Return True iff the difference between the two lines is cosmetic only:

    - Pure trailing-whitespace change (any line)
    - A comment line (``#`` or ``//``) that is just dashes / underscores /
      equals / asterisks where the count differs but the kind of decoration
      doesn't change

    Returns False if either line has substantive content that differs.
    """
    if orig_line == new_line:
        return False  # not drift — it's identical

    # Trailing whitespace only (handles "\n" vs " \n" and "x" vs "x  ")
    if orig_line.rstrip() == new_line.rstrip():
        return True

    o = orig_line.strip()
    n = new_line.strip()
    # Both must be comments
    if not (o.startswith(("#", "//")) and n.startswith(("#", "//"))):
        return False
    # Strip the comment marker
    o_body = o.lstrip("#").lstrip("/").strip()
    n_body = n.lstrip("#").lstrip("/").strip()
    # Both bodies must be made entirely of decoration characters
    deco_chars = set("-_=*~ ")
    if not o_body or not n_body:
        # Empty-body comment ("#") on both sides — already handled by rstrip
        # equality above; falling here means one is empty and one is decoration,
        # which is genuine content change. Don't treat as cosmetic.
        return False
    if not (set(o_body) <= deco_chars and set(n_body) <= deco_chars):
        return False
    # Same set of decoration characters used (don't let "----" become "====")
    return set(o_body) == set(n_body)


def _strip_cosmetic_drift(original: str, patched: str) -> str:
    """Walk original/patched in lockstep and revert lines that differ only
    cosmetically. Returns the cleaned patched content.

    Uses ``difflib.SequenceMatcher`` so insertions, deletions, and real edits
    flow through unchanged — only the "replace" opcodes get the cosmetic
    filter applied to each pair of replaced lines.
    """
    if original == patched:
        return patched

    orig_lines = original.splitlines(keepends=True)
    new_lines = patched.splitlines(keepends=True)
    out: list[str] = []
    matcher = difflib.SequenceMatcher(a=orig_lines, b=new_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            out.extend(orig_lines[i1:i2])
            continue
        if tag == "replace" and (i2 - i1) == (j2 - j1):
            # 1:1 replacement — revert any cosmetically-equivalent pair
            for k in range(i2 - i1):
                o = orig_lines[i1 + k]
                n = new_lines[j1 + k]
                out.append(o if _is_cosmetic_drift(o, n) else n)
            continue
        # delete / insert / asymmetric replace — preserve LLM's choice
        out.extend(new_lines[j1:j2])
    return "".join(out)


# ---------------------------------------------------------------------------
# Deterministic K8s fixers
# ---------------------------------------------------------------------------


def _new_ruamel_yaml():
    """Return a configured ruamel YAML round-trip handler.

    Round-trip mode preserves quotes, indentation, comments, flow style,
    and key order from the original document. Without this, PyYAML's
    ``safe_dump_all`` would normalize everything (strip quotes, change
    indentation, drop ``# Source:`` comments, alter flow style) and produce
    huge cosmetic diffs for a single-line edit.

    Created fresh per call so concurrent fixers don't share state.
    """
    from ruamel.yaml import YAML  # lazy import to avoid hard import-time dep
    y = YAML(typ="rt")  # round-trip
    y.preserve_quotes = True
    y.width = 4096       # avoid line-wrapping that introduces fake diff hunks
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _ruamel_load_docs(content: str) -> list:
    """Load multi-document YAML preserving formatting. Returns a list of
    ruamel-typed mappings/sequences (CommentedMap, CommentedSeq) that we
    mutate in place; subsequent ``_ruamel_dump_docs`` re-emits them with
    the original formatting where possible."""
    y = _new_ruamel_yaml()
    docs = list(y.load_all(content))
    # ruamel sometimes yields a trailing None for files ending in '---\n'
    return [d for d in docs if d is not None]


def _ruamel_dump_docs(docs: list, original_content: str) -> str:
    """Serialize back to multi-document YAML using ruamel round-trip mode.

    We use a single YAML handler instance and stream into a StringIO so
    multi-doc separators are emitted by ruamel itself.

    The leading ``---`` document marker on the first document is added
    only if the original content started with one, to match input
    formatting.
    """
    import io as _io
    y = _new_ruamel_yaml()
    y.explicit_start = original_content.lstrip().startswith("---")
    out = _io.StringIO()
    if len(docs) == 1:
        y.dump(docs[0], out)
    else:
        y.dump_all(docs, out)
    return out.getvalue()


def _yaml_dump_docs(docs: list[dict]) -> str:
    """Backwards-compat wrapper. New code should prefer
    :func:`_ruamel_dump_docs` with the original content for round-trip
    preservation. This shim is kept only because tests exercise it
    directly with plain Python dicts (no original to round-trip from).
    """
    return yaml.safe_dump_all(docs, sort_keys=False, default_flow_style=False)


def _detect_json_indent(content: str) -> int:
    """Sniff the indent width of the source JSON so we round-trip with
    the same shape the user uploaded. Defaults to 2 (the K8s convention).
    """
    for line in content.splitlines():
        stripped = line.lstrip(" ")
        if stripped and stripped != line:
            indent = len(line) - len(stripped)
            if indent in (2, 4):
                return indent
    return 2


def _dump_docs_for_kind(docs: list, original_content: str, file_kind: str) -> str:
    """Serialize patched docs back to the *same* format as the source.

    - ``kubernetes_json`` → ``json.dumps`` with the same indent the source
      used. Preserves trailing newline if present.
    - any other kind → ruamel.yaml round-trip.
    """
    if file_kind == "kubernetes_json":
        # K8s JSON manifests are always single-document — emit just the
        # first doc as a JSON object (not an array).
        if len(docs) == 1:
            payload = docs[0]
        else:
            # Defensive: if somehow we have multiple docs from a JSON
            # file, emit a JSON array. K8s tools rarely use this shape
            # but better than dropping data.
            payload = list(docs)
        indent = _detect_json_indent(original_content)
        out = json.dumps(payload, indent=indent, ensure_ascii=False)
        if original_content.endswith("\n"):
            out += "\n"
        return out
    return _ruamel_dump_docs(docs, original_content)


def _find_workload_doc(docs: list[dict], target_name: str, target_kind: Optional[str]) -> Optional[dict]:
    """Find a workload document matching target_name (and optionally target_kind).

    Layered match — same philosophy as _locate_kubernetes_file:
    1. Exact name match (with kind constraint if given)
    2. Substring match within target_kind (chart-style "my-chart" against
       rendered "release-my-chart"), but only if exactly one candidate
    3. Single-workload-of-Kind fallback when target_kind is set and only
       one such workload exists in the file
    """
    workload_kinds = ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod")

    # Layer 1: exact match
    for d in docs:
        if not isinstance(d, dict):
            continue
        if target_kind and d.get("kind") != target_kind:
            continue
        if d.get("kind") not in workload_kinds and target_kind is None:
            continue
        if d.get("metadata", {}).get("name") == target_name:
            return d

    # Layer 2: substring match (only meaningful when both kind and name are
    # provided, and there's exactly one candidate)
    if target_kind and target_name:
        substr_candidates = [
            d for d in docs
            if isinstance(d, dict)
            and d.get("kind") == target_kind
            and d.get("metadata", {}).get("name")
            and (
                target_name in d["metadata"]["name"]
                or d["metadata"]["name"] in target_name
            )
        ]
        if len(substr_candidates) == 1:
            return substr_candidates[0]

    # Layer 3: single-workload-of-Kind fallback
    if target_kind in workload_kinds:
        kind_only = [
            d for d in docs
            if isinstance(d, dict) and d.get("kind") == target_kind
        ]
        if len(kind_only) == 1:
            return kind_only[0]

    return None


def _ensure_pod_spec(workload: dict) -> dict:
    """Return the mutable pod spec dict for any workload kind."""
    kind = workload.get("kind", "")
    spec = workload.setdefault("spec", {})
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
        return spec.setdefault("template", {}).setdefault("spec", {})
    if kind == "CronJob":
        return (
            spec.setdefault("jobTemplate", {})
                .setdefault("spec", {})
                .setdefault("template", {})
                .setdefault("spec", {})
        )
    # Pod
    return spec


def _iter_containers(pod_spec: dict) -> list[dict]:
    out = []
    out.extend(pod_spec.get("containers", []) or [])
    out.extend(pod_spec.get("initContainers", []) or [])
    return out


def _k8s_container_match(container: dict, finding: Finding) -> bool:
    """Heuristic: the rule findings include the container name in the
    description as ``Container 'X' in Y has...``. Match by that."""
    desc = finding.description or ""
    m = re.search(r"Container '([^']+)'", desc)
    if m:
        return container.get("name") == m.group(1)
    return True  # If we can't tell, fall through to first container


def _fix_k8s(finding: Finding, content: str, file_kind: str = "kubernetes_yaml") -> tuple[str, str, list[str]]:
    """Apply a deterministic K8s fix. Returns (patched_content, explanation, warnings).

    Raises ``RemediationError`` when no fixer matches the category.

    Behaviour by ``file_kind``:

    - ``kubernetes_yaml`` (default): load with ruamel.yaml round-trip,
      mutate, dump with ruamel. Preserves quote style, indentation,
      comments (e.g. helm ``# Source:`` lines), flow style, and key
      order. The diff for a single env-var change touches only the
      line(s) actually edited.
    - ``kubernetes_json``: the user uploaded a ``.json`` file containing
      a Kubernetes manifest. Load with ``json.loads`` and dump back via
      ``json.dumps`` — emitting YAML here would break downstream tooling
      (kubectl, gitops pipelines) that expects the same file shape it
      ingested.
    """
    if file_kind == "kubernetes_json":
        try:
            obj = json.loads(content)
        except Exception as e:
            raise RemediationError(f"K8s JSON file failed to parse: {e}")
        if not isinstance(obj, dict) or not obj.get("kind"):
            raise RemediationError("K8s JSON file is not a valid manifest.")
        docs: list = [obj]
    else:
        docs = _ruamel_load_docs(content)
        if not docs:
            raise RemediationError("File is empty or has no YAML documents.")

    parts = (finding.resource or "").split("/")
    target_name = parts[-1] if parts else ""
    target_kind = parts[0] if len(parts) >= 2 else None

    category = finding.category
    warnings: list[str] = []

    # ------------------------------------------------------------------
    # Workload-targeting categories
    # ------------------------------------------------------------------
    if category in (
        "privileged", "run-as-root", "filesystem", "resource-limits",
        "image-tag", "host-namespace",
    ):
        workload = _find_workload_doc(docs, target_name, target_kind)
        if not workload:
            raise RemediationError(
                f"Could not find workload {target_kind or '?'}/{target_name} in {finding.resource}."
            )
        pod_spec = _ensure_pod_spec(workload)

        if category == "host-namespace":
            # Title is "hostPID enabled" / "hostNetwork enabled" / "hostIPC enabled"
            for ns in ("hostPID", "hostNetwork", "hostIPC"):
                if ns in (finding.title or ""):
                    pod_spec.pop(ns, None)
                    return _dump_docs_for_kind(docs, content, file_kind), f"Removed {ns} from pod spec.", warnings
            raise RemediationError("Could not infer host namespace flag from finding title.")

        containers = _iter_containers(pod_spec)
        if not containers:
            raise RemediationError("Workload has no containers to patch.")
        target_container = next((c for c in containers if _k8s_container_match(c, finding)), containers[0])

        if category == "privileged":
            sec = target_container.setdefault("securityContext", {})
            sec["privileged"] = False
            return _dump_docs_for_kind(docs, content, file_kind), f"Set securityContext.privileged=false on container '{target_container.get('name')}'.", warnings

        if category == "run-as-root":
            sec = target_container.setdefault("securityContext", {})
            sec["runAsNonRoot"] = True
            sec.setdefault("runAsUser", 1000)
            return _dump_docs_for_kind(docs, content, file_kind), f"Set runAsNonRoot=true (and runAsUser=1000) on container '{target_container.get('name')}'.", warnings

        if category == "filesystem":
            sec = target_container.setdefault("securityContext", {})
            sec["readOnlyRootFilesystem"] = True
            warnings.append(
                "Workloads that write to disk (logs, caches) will need an emptyDir or PVC volume mount."
            )
            return _dump_docs_for_kind(docs, content, file_kind), f"Set readOnlyRootFilesystem=true on container '{target_container.get('name')}'.", warnings

        if category == "resource-limits":
            res = target_container.setdefault("resources", {})
            res.setdefault("requests", {}).setdefault("cpu", "100m")
            res["requests"].setdefault("memory", "128Mi")
            res.setdefault("limits", {}).setdefault("cpu", "500m")
            res["limits"].setdefault("memory", "512Mi")
            warnings.append("Default values 500m/512Mi added — tune to actual workload load.")
            return _dump_docs_for_kind(docs, content, file_kind), f"Added CPU/memory requests + limits on container '{target_container.get('name')}'.", warnings

        if category == "image-tag":
            image = target_container.get("image", "")
            # Strip ':latest' or no-tag and pin a placeholder. User must edit.
            base = image.split(":", 1)[0] if ":" in image else image
            new_image = f"{base}:CHANGE_ME_PIN_DIGEST_OR_VERSION"
            target_container["image"] = new_image
            warnings.append(
                "Image tag replaced with a CHANGE_ME placeholder — replace with a specific version or @sha256 digest."
            )
            return _dump_docs_for_kind(docs, content, file_kind), f"Replaced floating tag on container '{target_container.get('name')}'.", warnings

    # ------------------------------------------------------------------
    # RBAC / Service / hardcoded-secret categories — touch the doc directly
    # ------------------------------------------------------------------
    if category == "public-exposure" and (target_kind == "Service" or "LoadBalancer service" in (finding.title or "")):
        # Convert LoadBalancer -> ClusterIP
        for d in docs:
            if d.get("kind") == "Service" and d.get("metadata", {}).get("name") == target_name:
                spec = d.setdefault("spec", {})
                spec["type"] = "ClusterIP"
                warnings.append(
                    "Service downgraded to ClusterIP — add an Ingress controller for external traffic."
                )
                return _dump_docs_for_kind(docs, content, file_kind), f"Changed Service '{target_name}' from LoadBalancer to ClusterIP.", warnings
        raise RemediationError("Could not find target Service.")

    if category == "rbac":
        # cluster-admin binding -> downgrade to a placeholder named role
        if "cluster-admin" in (finding.title or ""):
            for d in docs:
                kind = d.get("kind")
                if kind not in ("ClusterRoleBinding", "RoleBinding"):
                    continue
                if d.get("metadata", {}).get("name") != target_name:
                    continue
                rr = d.setdefault("roleRef", {})
                if rr.get("name") == "cluster-admin":
                    rr["name"] = "CHANGE_ME_LEAST_PRIVILEGE_ROLE"
                    rr["kind"] = "Role" if kind == "RoleBinding" else "ClusterRole"
                    warnings.append(
                        "RoleRef renamed to CHANGE_ME_LEAST_PRIVILEGE_ROLE — define and reference a least-privilege Role/ClusterRole."
                    )
                    return _dump_docs_for_kind(docs, content, file_kind), "Replaced cluster-admin binding with a placeholder least-privilege role.", warnings
            raise RemediationError("Could not find target binding.")
        # Wildcard rules → narrow them
        if "Wildcard" in (finding.title or ""):
            for d in docs:
                kind = d.get("kind")
                if kind not in ("ClusterRole", "Role"):
                    continue
                if d.get("metadata", {}).get("name") != target_name:
                    continue
                rules = d.get("rules", []) or []
                changed = False
                for rule in rules:
                    if "*" in (rule.get("verbs") or []):
                        rule["verbs"] = ["get", "list", "watch"]
                        changed = True
                    if "*" in (rule.get("resources") or []):
                        rule["resources"] = ["CHANGE_ME_SPECIFIC_RESOURCES"]
                        changed = True
                if changed:
                    warnings.append(
                        "Wildcard verbs replaced with read-only set; resources set to a CHANGE_ME placeholder."
                    )
                    return _dump_docs_for_kind(docs, content, file_kind), f"Narrowed wildcard rules on {kind} '{target_name}'.", warnings

    if category == "hardcoded-secret":
        # Replace inline env value with a valueFrom secretKeyRef placeholder
        workload = _find_workload_doc(docs, target_name, target_kind)
        if not workload:
            raise RemediationError("Could not locate workload for hardcoded-secret fix.")
        pod_spec = _ensure_pod_spec(workload)
        containers = _iter_containers(pod_spec)
        m = re.search(r"secret '([^']+)'", finding.description or "")
        target_env_name = m.group(1) if m else None
        for c in containers:
            envs = c.get("env", []) or []
            for env in envs:
                name = env.get("name")
                if env.get("value") and "valueFrom" not in env:
                    if target_env_name and name != target_env_name:
                        continue
                    env.pop("value", None)
                    env["valueFrom"] = {
                        "secretKeyRef": {
                            "name": "CHANGE_ME_SECRET_NAME",
                            "key": "CHANGE_ME_SECRET_KEY",
                        }
                    }
                    warnings.append(
                        "Inline env value replaced with secretKeyRef placeholder — create the matching Secret resource."
                    )
                    return _dump_docs_for_kind(docs, content, file_kind), f"Moved hardcoded env '{name}' to secretKeyRef.", warnings
        raise RemediationError("Could not locate the hardcoded env entry.")

    # ------------------------------------------------------------------
    # Update strategy — Reliability Agent's "No update strategy specified".
    # Inject a RollingUpdate block at deployment-spec level. Only valid
    # for Deployment / StatefulSet (Pods, Jobs, etc. don't have strategy).
    # ------------------------------------------------------------------
    if category == "strategy":
        # Strategy lives at deployment.spec, NOT pod.spec. Re-find the
        # workload doc itself so we can mutate spec directly.
        if target_kind not in ("Deployment", "StatefulSet"):
            raise RemediationError(
                f"Update-strategy fix only applies to Deployment / StatefulSet, "
                f"not {target_kind!r}."
            )
        workload = _find_workload_doc(docs, target_name, target_kind)
        if not workload:
            raise RemediationError(
                f"Could not find {target_kind} '{target_name}' to add update strategy."
            )
        spec = workload.setdefault("spec", {})
        # Don't clobber an existing strategy — surface as a clean no-op.
        if "strategy" in spec or "updateStrategy" in spec:
            raise RemediationError(
                f"{target_kind} '{target_name}' already has an update strategy "
                "configured; nothing to add."
            )
        if target_kind == "Deployment":
            spec["strategy"] = {
                "type": "RollingUpdate",
                "rollingUpdate": {
                    "maxSurge": "25%",
                    "maxUnavailable": 0,
                },
            }
        else:  # StatefulSet
            spec["updateStrategy"] = {
                "type": "RollingUpdate",
                "rollingUpdate": {
                    "partition": 0,
                },
            }
        warnings.append(
            "Default RollingUpdate values (maxSurge=25%, maxUnavailable=0) "
            "added — tune to your traffic and capacity headroom."
        )
        return (
            _dump_docs_for_kind(docs, content, file_kind),
            f"Added RollingUpdate strategy to {target_kind} '{target_name}'.",
            warnings,
        )

    # ------------------------------------------------------------------
    # Termination grace period — LLM-emitted "Missing Termination Grace
    # Period" advisory. Pure scalar injection at pod-spec level.
    # Detected by title/recommendation since the category is usually
    # ``ai-analysis`` (LLM-emitted), not a rule-engine category.
    # ------------------------------------------------------------------
    _trigger = (
        "termination grace period" in (finding.title or "").lower()
        or "terminationgraceperiodseconds" in (finding.recommendation or "").lower()
    )
    if _trigger:
        if target_kind not in ("Deployment", "StatefulSet", "DaemonSet", "Job", "Pod", "CronJob"):
            raise RemediationError(
                f"terminationGracePeriodSeconds fix requires a workload kind, "
                f"not {target_kind!r}."
            )
        workload = _find_workload_doc(docs, target_name, target_kind)
        if not workload:
            raise RemediationError(
                f"Could not find {target_kind} '{target_name}' for "
                "terminationGracePeriodSeconds fix."
            )
        pod_spec = _ensure_pod_spec(workload)
        if "terminationGracePeriodSeconds" in pod_spec:
            raise RemediationError(
                f"{target_kind} '{target_name}' already has "
                "terminationGracePeriodSeconds set; nothing to change."
            )
        pod_spec["terminationGracePeriodSeconds"] = 30
        warnings.append(
            "Default value of 30 seconds added — tune if your application "
            "needs longer to drain connections gracefully."
        )
        return (
            _dump_docs_for_kind(docs, content, file_kind),
            f"Added terminationGracePeriodSeconds=30 to {target_kind} '{target_name}'.",
            warnings,
        )

    raise RemediationError(f"No deterministic K8s fixer for category '{category}'.")


# ---------------------------------------------------------------------------
# Deterministic Terraform fixers
# ---------------------------------------------------------------------------


_TF_BLOCK_HEADER_RE = re.compile(
    r'^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{', re.MULTILINE
)


def _find_tf_block_span(content: str, rtype: str, rname: str) -> Optional[tuple[int, int]]:
    """Locate the byte span ``[start, end)`` of a Terraform resource block in
    HCL source. Returns None if not found.

    Walks the source brace-by-brace from the matching header.
    """
    for m in _TF_BLOCK_HEADER_RE.finditer(content):
        if m.group("type") != rtype or m.group("name") != rname:
            continue
        start = m.start()
        # Find opening brace
        i = m.end() - 1  # the matched '{'
        depth = 0
        in_str = False
        str_char = ""
        in_line_comment = False
        in_block_comment = False
        while i < len(content):
            ch = content[i]
            nxt = content[i + 1] if i + 1 < len(content) else ""
            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
            elif in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 1
            elif in_str:
                if ch == "\\":
                    i += 1
                elif ch == str_char:
                    in_str = False
            else:
                if ch == "#":
                    in_line_comment = True
                elif ch == "/" and nxt == "/":
                    in_line_comment = True
                elif ch == "/" and nxt == "*":
                    in_block_comment = True
                    i += 1
                elif ch in ('"', "'"):
                    in_str = True
                    str_char = ch
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return (start, i + 1)
            i += 1
    return None


def _tf_replace_block(content: str, rtype: str, rname: str, replacement: str) -> str:
    span = _find_tf_block_span(content, rtype, rname)
    if not span:
        raise RemediationError(f"Could not locate HCL block for {rtype}.{rname}.")
    s, e = span
    return content[:s] + replacement + content[e:]


def _tf_inject_argument_in_block(content: str, rtype: str, rname: str, argument_lines: str) -> str:
    """Insert ``argument_lines`` (one or more lines, no trailing newline) just
    before the closing ``}`` of the matching resource block. Each line is
    indented by two spaces."""
    span = _find_tf_block_span(content, rtype, rname)
    if not span:
        raise RemediationError(f"Could not locate HCL block for {rtype}.{rname}.")
    s, e = span
    block = content[s:e]
    # Insert before the final '}'
    closing = block.rfind("}")
    if closing == -1:
        raise RemediationError("Malformed HCL block: no closing brace.")
    indented_lines = []
    for ln in argument_lines.splitlines():
        ln = ln.rstrip()
        if ln:
            indented_lines.append("  " + ln)
        else:
            indented_lines.append("")
    indented = "\n".join(indented_lines) + "\n"
    new_block = block[:closing] + indented + block[closing:]
    return content[:s] + new_block + content[e:]


def _tf_remove_argument_in_block(content: str, rtype: str, rname: str, key_regex: str) -> str:
    """Remove all lines in the block that match ``key_regex`` at the start
    (whitespace-stripped). Returns the new content."""
    span = _find_tf_block_span(content, rtype, rname)
    if not span:
        raise RemediationError(f"Could not locate HCL block for {rtype}.{rname}.")
    s, e = span
    block = content[s:e]
    lines = block.splitlines(keepends=True)
    keep = []
    pattern = re.compile(rf"^\s*{key_regex}\s*=")
    for ln in lines:
        if pattern.match(ln):
            continue
        keep.append(ln)
    new_block = "".join(keep)
    return content[:s] + new_block + content[e:]


def _tf_set_argument_in_block(
    content: str, rtype: str, rname: str, key: str, new_value_literal: str
) -> str:
    """If ``key`` exists in the block, replace its value with ``new_value_literal``.
    Otherwise, append ``key = new_value_literal``.

    ``new_value_literal`` is inserted verbatim (already-quoted strings, booleans, etc.).
    """
    span = _find_tf_block_span(content, rtype, rname)
    if not span:
        raise RemediationError(f"Could not locate HCL block for {rtype}.{rname}.")
    s, e = span
    block = content[s:e]
    pattern = re.compile(rf"(^\s*{re.escape(key)}\s*=\s*)([^\n]*)", re.MULTILINE)
    if pattern.search(block):
        new_block = pattern.sub(rf"\g<1>{new_value_literal}", block, count=1)
    else:
        # Inject just before the closing brace
        closing = block.rfind("}")
        if closing == -1:
            raise RemediationError("Malformed HCL block: no closing brace.")
        new_block = block[:closing] + f"  {key} = {new_value_literal}\n" + block[closing:]
    return content[:s] + new_block + content[e:]


def _fix_tf(finding: Finding, content: str) -> tuple[str, str, list[str]]:
    """Apply a deterministic Terraform fix. Returns (patched, explanation, warnings).

    Raises RemediationError when no fixer matches.
    """
    resource = finding.resource or ""
    if "." not in resource:
        raise RemediationError("Terraform finding missing dotted resource name.")
    rtype, _, rname = resource.partition(".")
    rname = rname.split(".", 1)[0]
    title = finding.title or ""
    cat = finding.category
    warnings: list[str] = []

    # ----- Network: 0.0.0.0/0 ingress / egress / firewall -----
    if cat == "network":
        title_lower = title.lower()
        sg_match = (
            rtype == "aws_security_group"
            and (
                "0.0.0.0/0" in title
                or "permissive" in title_lower  # "Overly Permissive Egress on Security Group"
                or "egress" in title_lower
                or "ingress" in title_lower
            )
        )
        if sg_match:
            # Rewrite cidr_blocks references inside ingress AND egress blocks.
            # The regex is block-agnostic — any "cidr_blocks = [\"0.0.0.0/0\"]"
            # gets replaced. We don't add a trailing # comment because inline
            # blocks would treat it as the rest-of-line marker and break the
            # closing brace.
            span = _find_tf_block_span(content, rtype, rname)
            if not span:
                raise RemediationError("aws_security_group block not found.")
            s, e = span
            block = content[s:e]
            new_block, count = re.subn(
                r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                'cidr_blocks = ["10.0.0.0/8"]',
                block,
            )
            if count == 0:
                # The SG block has no literal 0.0.0.0/0 to swap — let the LLM
                # try a more nuanced edit (e.g. split egress into specific
                # rules, or remove protocol = "-1").
                raise RemediationError(
                    "aws_security_group has no literal 0.0.0.0/0 cidr to replace."
                )
            warnings.append("Replaced 0.0.0.0/0 with 10.0.0.0/8 placeholder — set to your actual trusted CIDR(s).")
            direction = "egress" if "egress" in title_lower or "permissive" in title_lower else "ingress"
            return content[:s] + new_block + content[e:], f"Restricted {direction} CIDR on {rtype}.{rname}.", warnings
        if rtype == "google_compute_firewall" and "0.0.0.0/0" in title:
            span = _find_tf_block_span(content, rtype, rname)
            if not span:
                raise RemediationError("google_compute_firewall block not found.")
            s, e = span
            block = content[s:e]
            new_block = re.sub(
                r'source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                'source_ranges = ["10.0.0.0/8"]',
                block,
            )
            warnings.append("Replaced 0.0.0.0/0 with placeholder — set to your trusted CIDR.")
            return content[:s] + new_block + content[e:], f"Restricted source_ranges on {rtype}.{rname}.", warnings
        if rtype == "azurerm_network_security_rule":
            patched = _tf_set_argument_in_block(
                content, rtype, rname, "source_address_prefix", '"10.0.0.0/8"'
            )
            warnings.append("source_address_prefix set to placeholder 10.0.0.0/8 — replace with your trusted CIDR.")
            return patched, f"Restricted source_address_prefix on {rtype}.{rname}.", warnings
        # AKS / GKE network policy missing
        if rtype == "azurerm_kubernetes_cluster" and "network policy" in title.lower():
            warnings.append(
                "AKS network_policy is nested inside network_profile; manual edit may be needed if "
                "network_profile already has other settings."
            )
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'network_profile {\n'
                '  network_policy = "azure"  # CHANGE_ME — adjust if you already have a network_profile block\n'
                '}'
            )
            return patched, f"Added network_policy=azure to {rtype}.{rname}.", warnings
        if rtype == "google_container_cluster" and "network policy" in title.lower():
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'network_policy {\n'
                '  enabled  = true\n'
                '  provider = "CALICO"  # CHANGE_ME — verify provider\n'
                '}'
            )
            return patched, f"Added network_policy block to {rtype}.{rname}.", warnings
        if rtype == "google_container_cluster" and "private" in title.lower():
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'private_cluster_config {\n'
                '  enable_private_nodes    = true\n'
                '  enable_private_endpoint = false\n'
                '  master_ipv4_cidr_block  = "172.16.0.0/28"  # CHANGE_ME\n'
                '}'
            )
            return patched, f"Added private_cluster_config to {rtype}.{rname}.", warnings
        if rtype == "google_container_cluster" and "master authorized" in title.lower():
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'master_authorized_networks_config {\n'
                '  cidr_blocks {\n'
                '    cidr_block   = "10.0.0.0/8"  # CHANGE_ME\n'
                '    display_name = "internal"\n'
                '  }\n'
                '}'
            )
            return patched, f"Added master_authorized_networks_config to {rtype}.{rname}.", warnings
        if rtype == "aws_lambda_function" and "VPC" in title:
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'vpc_config {\n'
                '  subnet_ids         = []  # CHANGE_ME — fill in subnets\n'
                '  security_group_ids = []  # CHANGE_ME — fill in SGs\n'
                '}'
            )
            return patched, f"Added vpc_config block to {rtype}.{rname}.", warnings

    # ----- Encryption -----
    if cat == "encryption":
        if rtype == "aws_s3_bucket":
            companion = (
                f'\nresource "aws_s3_bucket_server_side_encryption_configuration" "{rname}" {{\n'
                f'  bucket = aws_s3_bucket.{rname}.id\n'
                f'  rule {{\n'
                f'    apply_server_side_encryption_by_default {{\n'
                f'      sse_algorithm = "AES256"\n'
                f'    }}\n'
                f'  }}\n'
                f'}}\n'
            )
            return content + companion, f"Added aws_s3_bucket_server_side_encryption_configuration for {rname}.", warnings
        if rtype == "aws_db_instance":
            patched = _tf_set_argument_in_block(content, rtype, rname, "storage_encrypted", "true")
            return patched, f"Set storage_encrypted=true on {rtype}.{rname}.", warnings
        if rtype == "aws_ebs_volume":
            patched = _tf_set_argument_in_block(content, rtype, rname, "encrypted", "true")
            return patched, f"Set encrypted=true on {rtype}.{rname}.", warnings
        if rtype == "aws_kms_key":
            patched = _tf_set_argument_in_block(content, rtype, rname, "enable_key_rotation", "true")
            return patched, f"Enabled key rotation on {rtype}.{rname}.", warnings
        if rtype == "azurerm_key_vault":
            if "purge protection" in title.lower():
                patched = _tf_set_argument_in_block(content, rtype, rname, "purge_protection_enabled", "true")
                return patched, f"Enabled purge_protection on {rtype}.{rname}.", warnings
            if "soft delete" in title.lower():
                patched = _tf_set_argument_in_block(content, rtype, rname, "soft_delete_retention_days", "90")
                return patched, f"Set soft_delete_retention_days=90 on {rtype}.{rname}.", warnings
        if rtype == "azurerm_managed_disk":
            warnings.append("disk_encryption_set_id requires an existing azurerm_disk_encryption_set resource.")
            patched = _tf_set_argument_in_block(
                content, rtype, rname, "disk_encryption_set_id",
                'azurerm_disk_encryption_set.CHANGE_ME.id'
            )
            return patched, f"Added disk_encryption_set_id to {rtype}.{rname}.", warnings

    # ----- Encryption in transit -----
    if cat == "encryption-in-transit":
        if rtype in ("aws_lb_listener", "aws_alb_listener"):
            patched = _tf_set_argument_in_block(content, rtype, rname, "protocol", '"HTTPS"')
            patched = _tf_set_argument_in_block(patched, rtype, rname, "port", "443")
            warnings.append("Listener flipped to HTTPS:443. Make sure 'certificate_arn' references a valid ACM cert.")
            return patched, f"Switched {rtype}.{rname} to HTTPS:443.", warnings
        if rtype == "azurerm_storage_account":
            if "non-HTTPS" in title:
                patched = _tf_set_argument_in_block(content, rtype, rname, "enable_https_traffic_only", "true")
                return patched, f"Enforced HTTPS-only on {rtype}.{rname}.", warnings
            if "weak TLS" in title:
                patched = _tf_set_argument_in_block(content, rtype, rname, "min_tls_version", '"TLS1_2"')
                return patched, f"Set min_tls_version=TLS1_2 on {rtype}.{rname}.", warnings

    # ----- Public exposure -----
    if cat == "public-exposure":
        if rtype == "aws_s3_bucket":
            if "ACL" in title or "Public" in title:
                patched = _tf_set_argument_in_block(content, rtype, rname, "acl", '"private"')
                return patched, f"Set ACL=private on {rtype}.{rname}.", warnings
            if "public access block" in title.lower():
                companion = (
                    f'\nresource "aws_s3_bucket_public_access_block" "{rname}" {{\n'
                    f'  bucket                  = aws_s3_bucket.{rname}.id\n'
                    f'  block_public_acls       = true\n'
                    f'  block_public_policy     = true\n'
                    f'  ignore_public_acls      = true\n'
                    f'  restrict_public_buckets = true\n'
                    f'}}\n'
                )
                return content + companion, f"Added aws_s3_bucket_public_access_block for {rname}.", warnings
        if rtype == "aws_db_instance":
            patched = _tf_set_argument_in_block(content, rtype, rname, "publicly_accessible", "false")
            return patched, f"Set publicly_accessible=false on {rtype}.{rname}.", warnings
        if rtype == "google_sql_database_instance":
            warnings.append(
                "ipv4_enabled is nested in settings.ip_configuration; this fixer appends a new "
                "settings block — confirm there is no duplicate and merge manually if so."
            )
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'settings {\n'
                '  ip_configuration {\n'
                '    ipv4_enabled = false  # CHANGE_ME — merge with existing settings if present\n'
                '  }\n'
                '}'
            )
            return patched, f"Disabled public IP on {rtype}.{rname}.", warnings
        if rtype == "google_storage_bucket":
            patched = _tf_set_argument_in_block(content, rtype, rname, "uniform_bucket_level_access", "true")
            return patched, f"Enabled uniform_bucket_level_access on {rtype}.{rname}.", warnings

    # ----- Instance-metadata -----
    if cat == "instance-metadata":
        if rtype in ("aws_instance", "aws_launch_template"):
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'metadata_options {\n'
                '  http_tokens   = "required"\n'
                '  http_endpoint = "enabled"\n'
                '}'
            )
            return patched, f"Required IMDSv2 on {rtype}.{rname}.", warnings
        if rtype == "google_compute_instance":
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'shielded_instance_config {\n'
                '  enable_secure_boot          = true\n'
                '  enable_vtpm                 = true\n'
                '  enable_integrity_monitoring = true\n'
                '}'
            )
            return patched, f"Enabled shielded VM on {rtype}.{rname}.", warnings

    # ----- Logging -----
    if cat == "logging":
        if rtype == "aws_cloudtrail":
            patched = content
            if "logging disabled" in title.lower():
                patched = _tf_set_argument_in_block(patched, rtype, rname, "enable_logging", "true")
            if "multi-region" in title.lower():
                patched = _tf_set_argument_in_block(patched, rtype, rname, "is_multi_region_trail", "true")
            if "log validation" in title.lower():
                patched = _tf_set_argument_in_block(patched, rtype, rname, "enable_log_file_validation", "true")
            if patched == content:
                raise RemediationError("Could not infer cloudtrail fix from finding title.")
            return patched, f"Hardened {rtype}.{rname} logging.", warnings
        if rtype == "aws_vpc" and "flow logs" in title.lower():
            companion = (
                f'\nresource "aws_flow_log" "{rname}_flow_log" {{\n'
                f'  vpc_id          = aws_vpc.{rname}.id\n'
                f'  traffic_type    = "ALL"\n'
                f'  log_destination = "CHANGE_ME_S3_OR_LOG_GROUP_ARN"\n'
                f'  log_destination_type = "s3"  # or "cloud-watch-logs"\n'
                f'}}\n'
            )
            warnings.append("log_destination needs a real S3 bucket ARN or CloudWatch log group.")
            return content + companion, f"Added aws_flow_log for VPC {rname}.", warnings

    # ----- Hardcoded secret -----
    if cat == "hardcoded-secret":
        # Replace plain-text password with a var reference. We can't introspect the
        # exact key safely, so we set it to var.db_password and warn about it.
        password_keys = ("password", "administrator_login_password", "master_password")
        for key in password_keys:
            try:
                # Probe: is this key present?
                span = _find_tf_block_span(content, rtype, rname)
                if not span:
                    continue
                s, e = span
                if re.search(rf"^\s*{key}\s*=\s*\".*?\"", content[s:e], re.MULTILINE):
                    patched = _tf_set_argument_in_block(content, rtype, rname, key, "var.db_password")
                    warnings.append(
                        "Replaced inline password with var.db_password — declare the variable as sensitive=true and pass via TF_VAR_db_password."
                    )
                    return patched, f"Externalized password on {rtype}.{rname}.", warnings
            except Exception:
                continue
        raise RemediationError("Could not locate plaintext password attribute.")

    # ----- IAM overly permissive -----
    if cat == "iam":
        if rtype in ("aws_iam_policy", "aws_iam_role_policy"):
            warnings.append(
                "Policy document with wildcards requires manual scoping. This patch leaves a TODO comment "
                "above the resource — a safe deterministic narrow isn't possible without knowing intent."
            )
            span = _find_tf_block_span(content, rtype, rname)
            if not span:
                raise RemediationError("aws_iam_policy block not found.")
            s, e = span
            todo = (
                f'# TODO(governance): IAM policy {rname} uses wildcards. Replace Action: "*" / Resource: "*"\n'
                f'#   with explicit lists. See finding "{title}".\n'
            )
            return content[:s] + todo + content[s:], f"Annotated {rtype}.{rname} with TODO for manual scoping.", warnings
        if rtype in ("google_project_iam_binding", "google_project_iam_member"):
            span = _find_tf_block_span(content, rtype, rname)
            if not span:
                raise RemediationError("GCP IAM block not found.")
            s, e = span
            block = content[s:e]
            new_block = re.sub(
                r'"(allUsers|allAuthenticatedUsers)"',
                '"serviceAccount:CHANGE_ME@PROJECT.iam.gserviceaccount.com"',
                block,
            )
            warnings.append("Replaced public principal with a service-account placeholder — set to a real SA.")
            return content[:s] + new_block + content[e:], f"Removed public IAM principal on {rtype}.{rname}.", warnings

    # ----- Privileged (ECS) -----
    if cat == "privileged" and rtype == "aws_ecs_task_definition":
        warnings.append(
            "ECS container_definitions is a JSON-encoded string; the patch only flips the obvious "
            '"privileged":true literal. Verify by re-rendering the JSON.'
        )
        new_content = re.sub(r'"privileged"\s*:\s*true', '"privileged": false', content)
        return new_content, f"Set privileged=false in ECS task {rname}.", warnings

    # ----- RBAC for AKS / cluster -----
    if cat == "rbac" and rtype == "azurerm_kubernetes_cluster":
        if "RBAC" in title and "Azure AD" not in title:
            patched = _tf_set_argument_in_block(content, rtype, rname, "role_based_access_control_enabled", "true")
            return patched, f"Enabled RBAC on {rtype}.{rname}.", warnings
        if "Azure AD" in title:
            patched = _tf_inject_argument_in_block(
                content, rtype, rname,
                'azure_active_directory_role_based_access_control {\n'
                '  managed            = true\n'
                '  azure_rbac_enabled = true  # CHANGE_ME\n'
                '}'
            )
            return patched, f"Added Azure AD RBAC on {rtype}.{rname}.", warnings

    # ----- High availability / resilience (deterministic single-attribute flips) -----
    if cat == "high-availability":
        # Azure SQL database zone redundancy
        if rtype == "azurerm_mssql_database" and "zone" in title.lower():
            patched = _tf_set_argument_in_block(content, rtype, rname, "zone_redundant", "true")
            return patched, f"Set zone_redundant=true on {rtype}.{rname}.", warnings
        # AWS RDS Multi-AZ
        if rtype in ("aws_db_instance", "aws_rds_cluster") and "multi-az" in title.lower():
            patched = _tf_set_argument_in_block(content, rtype, rname, "multi_az", "true")
            return patched, f"Enabled multi_az on {rtype}.{rname}.", warnings
        # Azure VM without an availability zone — needs a value the user must
        # choose; use a CHANGE_ME placeholder so the file still parses.
        if rtype in ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine"):
            warnings.append('zone must be one of "1"/"2"/"3" for your region — CHANGE_ME.')
            patched = _tf_set_argument_in_block(content, rtype, rname, "zone", '"1"')
            return patched, f"Set availability zone on {rtype}.{rname}.", warnings

    # ----- Backup / recoverability -----
    if cat in ("backup", "recoverability"):
        if rtype == "azurerm_key_vault" and ("purge" in title.lower() or "deletion protection" in title.lower()):
            patched = _tf_set_argument_in_block(content, rtype, rname, "purge_protection_enabled", "true")
            return patched, f"Enabled purge_protection on {rtype}.{rname}.", warnings
        if rtype == "azurerm_key_vault" and "soft delete" in title.lower():
            patched = _tf_set_argument_in_block(content, rtype, rname, "soft_delete_retention_days", "90")
            return patched, f"Set soft_delete_retention_days=90 on {rtype}.{rname}.", warnings
        if rtype in ("aws_db_instance", "aws_rds_cluster") and ("deletion protection" in title.lower()):
            patched = _tf_set_argument_in_block(content, rtype, rname, "deletion_protection", "true")
            return patched, f"Enabled deletion_protection on {rtype}.{rname}.", warnings

    raise RemediationError(f"No deterministic Terraform fixer for category='{cat}', resource='{resource}'.")


# ---------------------------------------------------------------------------
# Deterministic Terraform JSON fixers
#
# Mirror of _fix_tf but for the Terraform JSON syntax:
#
#   {"resource": {"aws_s3_bucket": {"uploads": {"bucket": "x"}}}}
#
# Same categories supported. Operates on the parsed JSON tree (json.loads),
# mutates in place, re-emits via json.dumps(indent=2). Companion-resource
# additions (S3 SSE, S3 PAB, VPC flow-log, etc.) inject a new entry into
# parsed["resource"][<companion-type>] = {<name>: {...}}.
#
# We avoid the LLM for categories with a known transformation because:
# - LLM JSON output on multi-hundred-line files is unreliable (the original
#   bug — "Invalid control character at: line 60 column 182").
# - JSON tree mutation is precise — no parser drift, no cosmetic noise.
# ---------------------------------------------------------------------------


def _tfjson_get_resource_block(parsed: dict, rtype: str, rname: str) -> dict:
    """Return the per-resource config dict from parsed Terraform JSON.

    Shape: ``parsed["resource"][rtype][rname]`` is the config object.
    Raises RemediationError if any link is missing.
    """
    res_section = parsed.get("resource")
    if not isinstance(res_section, dict):
        raise RemediationError("Terraform JSON has no 'resource' section.")
    type_section = res_section.get(rtype)
    if not isinstance(type_section, dict):
        raise RemediationError(f"Resource type '{rtype}' not found in JSON.")
    config = type_section.get(rname)
    if not isinstance(config, dict):
        raise RemediationError(f"Resource '{rtype}.{rname}' not found in JSON.")
    return config


def _tfjson_add_companion_resource(
    parsed: dict, rtype: str, rname: str, config: dict
) -> None:
    """Add a new entry under parsed["resource"][rtype][rname] = config.

    Creates the type dict if absent. Raises if the (rtype, rname) pair
    already exists — refuses to silently overwrite.
    """
    res_section = parsed.setdefault("resource", {})
    if not isinstance(res_section, dict):
        raise RemediationError("Terraform JSON 'resource' is not an object.")
    type_section = res_section.setdefault(rtype, {})
    if not isinstance(type_section, dict):
        raise RemediationError(f"'resource.{rtype}' is not an object.")
    if rname in type_section:
        raise RemediationError(
            f"Companion resource {rtype}.{rname} already exists; refusing to overwrite."
        )
    type_section[rname] = config


def _tfjson_dump(parsed: dict, original: str) -> str:
    """Re-emit parsed Terraform JSON, preserving the original indent and
    trailing-newline convention so the diff is clean."""
    indent = _detect_json_indent(original)
    out = json.dumps(parsed, indent=indent, ensure_ascii=False)
    if original.endswith("\n"):
        out += "\n"
    return out


def _fix_tf_json(finding: Finding, content: str) -> tuple[str, str, list[str]]:
    """Apply a deterministic fix to a Terraform JSON file.

    Same category coverage as :func:`_fix_tf` for the categories that have
    a known JSON-tree transformation. Raises ``RemediationError`` for
    categories without a deterministic fixer; the caller falls back to LLM.
    """
    try:
        parsed = json.loads(content)
    except Exception as e:
        raise RemediationError(f"Terraform JSON failed to parse: {e}")
    if not isinstance(parsed, dict):
        raise RemediationError("Terraform JSON root is not an object.")

    resource = finding.resource or ""
    if "." not in resource:
        raise RemediationError("Terraform finding missing dotted resource name.")
    rtype, _, rname = resource.partition(".")
    rname = rname.split(".", 1)[0]
    title = finding.title or ""
    cat = finding.category
    warnings: list[str] = []

    # ----- Encryption: S3 server-side encryption companion -----
    if cat == "encryption" and rtype == "aws_s3_bucket":
        companion_name = rname
        _tfjson_add_companion_resource(
            parsed,
            "aws_s3_bucket_server_side_encryption_configuration",
            companion_name,
            {
                "bucket": "${aws_s3_bucket." + rname + ".id}",
                "rule": {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "AES256"
                    }
                },
            },
        )
        return (
            _tfjson_dump(parsed, content),
            f"Added aws_s3_bucket_server_side_encryption_configuration for {rname}.",
            warnings,
        )

    # ----- Encryption: scalar set on the resource itself -----
    if cat == "encryption":
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        if rtype == "aws_db_instance":
            config["storage_encrypted"] = True
            return _tfjson_dump(parsed, content), f"Set storage_encrypted=true on {rtype}.{rname}.", warnings
        if rtype == "aws_ebs_volume":
            config["encrypted"] = True
            return _tfjson_dump(parsed, content), f"Set encrypted=true on {rtype}.{rname}.", warnings
        if rtype == "aws_kms_key":
            config["enable_key_rotation"] = True
            return _tfjson_dump(parsed, content), f"Enabled key rotation on {rtype}.{rname}.", warnings
        if rtype == "azurerm_key_vault":
            if "purge protection" in title.lower():
                config["purge_protection_enabled"] = True
                return _tfjson_dump(parsed, content), f"Enabled purge_protection on {rtype}.{rname}.", warnings
            if "soft delete" in title.lower():
                config["soft_delete_retention_days"] = 90
                return _tfjson_dump(parsed, content), f"Set soft_delete_retention_days=90 on {rtype}.{rname}.", warnings
        if rtype == "azurerm_managed_disk":
            warnings.append("disk_encryption_set_id requires an existing azurerm_disk_encryption_set resource.")
            config["disk_encryption_set_id"] = "azurerm_disk_encryption_set.CHANGE_ME.id"
            return _tfjson_dump(parsed, content), f"Added disk_encryption_set_id to {rtype}.{rname}.", warnings

    # ----- Encryption in transit -----
    if cat == "encryption-in-transit":
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        if rtype in ("aws_lb_listener", "aws_alb_listener"):
            config["protocol"] = "HTTPS"
            config["port"] = 443
            warnings.append("Listener flipped to HTTPS:443. Verify certificate_arn references a valid ACM cert.")
            return _tfjson_dump(parsed, content), f"Switched {rtype}.{rname} to HTTPS:443.", warnings
        if rtype == "azurerm_storage_account":
            if "non-HTTPS" in title:
                config["enable_https_traffic_only"] = True
                return _tfjson_dump(parsed, content), f"Enforced HTTPS-only on {rtype}.{rname}.", warnings
            if "weak TLS" in title:
                config["min_tls_version"] = "TLS1_2"
                return _tfjson_dump(parsed, content), f"Set min_tls_version=TLS1_2 on {rtype}.{rname}.", warnings

    # ----- Public exposure -----
    if cat == "public-exposure":
        if rtype == "aws_s3_bucket":
            if "ACL" in title or "Public S3" in title:
                config = _tfjson_get_resource_block(parsed, rtype, rname)
                config["acl"] = "private"
                return _tfjson_dump(parsed, content), f"Set ACL=private on {rtype}.{rname}.", warnings
            if "public access block" in title.lower():
                _tfjson_add_companion_resource(
                    parsed,
                    "aws_s3_bucket_public_access_block",
                    rname,
                    {
                        "bucket": "${aws_s3_bucket." + rname + ".id}",
                        "block_public_acls": True,
                        "block_public_policy": True,
                        "ignore_public_acls": True,
                        "restrict_public_buckets": True,
                    },
                )
                return (
                    _tfjson_dump(parsed, content),
                    f"Added aws_s3_bucket_public_access_block for {rname}.",
                    warnings,
                )
        if rtype == "aws_db_instance":
            config = _tfjson_get_resource_block(parsed, rtype, rname)
            config["publicly_accessible"] = False
            return _tfjson_dump(parsed, content), f"Set publicly_accessible=false on {rtype}.{rname}.", warnings
        if rtype == "google_storage_bucket":
            config = _tfjson_get_resource_block(parsed, rtype, rname)
            config["uniform_bucket_level_access"] = True
            return _tfjson_dump(parsed, content), f"Enabled uniform_bucket_level_access on {rtype}.{rname}.", warnings

    # ----- Instance metadata (IMDSv2 / shielded VM) -----
    if cat == "instance-metadata":
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        if rtype in ("aws_instance", "aws_launch_template"):
            config["metadata_options"] = {
                "http_tokens": "required",
                "http_endpoint": "enabled",
            }
            return _tfjson_dump(parsed, content), f"Required IMDSv2 on {rtype}.{rname}.", warnings
        if rtype == "google_compute_instance":
            config["shielded_instance_config"] = {
                "enable_secure_boot": True,
                "enable_vtpm": True,
                "enable_integrity_monitoring": True,
            }
            return _tfjson_dump(parsed, content), f"Enabled shielded VM on {rtype}.{rname}.", warnings

    # ----- Logging (CloudTrail scalars, VPC flow log companion) -----
    if cat == "logging":
        if rtype == "aws_cloudtrail":
            config = _tfjson_get_resource_block(parsed, rtype, rname)
            changed = False
            if "logging disabled" in title.lower():
                config["enable_logging"] = True
                changed = True
            if "multi-region" in title.lower():
                config["is_multi_region_trail"] = True
                changed = True
            if "log validation" in title.lower():
                config["enable_log_file_validation"] = True
                changed = True
            if not changed:
                raise RemediationError("Could not infer cloudtrail fix from finding title.")
            return _tfjson_dump(parsed, content), f"Hardened {rtype}.{rname} logging.", warnings
        if rtype == "aws_vpc" and "flow logs" in title.lower():
            warnings.append("log_destination needs a real S3 bucket ARN or CloudWatch log group.")
            _tfjson_add_companion_resource(
                parsed, "aws_flow_log", f"{rname}_flow_log",
                {
                    "vpc_id": "${aws_vpc." + rname + ".id}",
                    "traffic_type": "ALL",
                    "log_destination": "CHANGE_ME_S3_OR_LOG_GROUP_ARN",
                    "log_destination_type": "s3",
                },
            )
            return _tfjson_dump(parsed, content), f"Added aws_flow_log for VPC {rname}.", warnings

    # ----- Reliability / cost: scalar nudges on the same resource -----
    if cat == "high-availability" and rtype == "aws_db_instance" and "Multi-AZ" in title:
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        config["multi_az"] = True
        return _tfjson_dump(parsed, content), f"Enabled Multi-AZ on {rtype}.{rname}.", warnings
    if cat == "high-availability" and rtype == "azurerm_mssql_database" and "zone" in title.lower():
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        config["zone_redundant"] = True
        return _tfjson_dump(parsed, content), f"Set zone_redundant=true on {rtype}.{rname}.", warnings
    if cat == "high-availability" and rtype in ("aws_db_instance", "aws_rds_cluster") and "multi-az" in title.lower():
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        config["multi_az"] = True
        return _tfjson_dump(parsed, content), f"Enabled multi_az on {rtype}.{rname}.", warnings
    if cat == "backup" and rtype == "azurerm_key_vault":
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        if "soft delete" in title.lower():
            config["soft_delete_retention_days"] = 90
            return _tfjson_dump(parsed, content), f"Set soft_delete_retention_days=90 on {rtype}.{rname}.", warnings
        config["purge_protection_enabled"] = True
        return _tfjson_dump(parsed, content), f"Enabled purge_protection on {rtype}.{rname}.", warnings
    if cat == "protection" and rtype == "aws_db_instance":
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        config["deletion_protection"] = True
        return _tfjson_dump(parsed, content), f"Enabled deletion_protection on {rtype}.{rname}.", warnings
    if cat == "backup" and rtype == "aws_dynamodb_table":
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        # PITR lives in a nested point_in_time_recovery block in HCL; in JSON
        # it's the same key with an enabled boolean.
        config["point_in_time_recovery"] = {"enabled": True}
        return _tfjson_dump(parsed, content), f"Enabled point_in_time_recovery on {rtype}.{rname}.", warnings
    if cat == "storage" and rtype == "aws_cloudwatch_log_group" and "retention" in title.lower():
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        config["retention_in_days"] = 30
        warnings.append("Set retention_in_days=30 — adjust per compliance / debugging needs.")
        return _tfjson_dump(parsed, content), f"Set retention_in_days=30 on {rtype}.{rname}.", warnings

    # ----- Hardcoded secret -----
    if cat == "hardcoded-secret":
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        for key in ("password", "administrator_login_password", "master_password"):
            if key in config and isinstance(config[key], str) and not config[key].startswith("${"):
                config[key] = "${var.db_password}"
                warnings.append(
                    "Replaced inline password with var.db_password — declare the variable as "
                    "sensitive=true and pass via TF_VAR_db_password."
                )
                return _tfjson_dump(parsed, content), f"Externalized password on {rtype}.{rname}.", warnings
        raise RemediationError("Could not locate plaintext password attribute.")

    # ----- Network: cidr_blocks rewrite (limited; full SG rewrite is HCL-only) -----
    if cat == "network" and rtype == "google_compute_firewall" and "0.0.0.0/0" in title:
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        ranges = config.get("source_ranges")
        if isinstance(ranges, list) and "0.0.0.0/0" in ranges:
            config["source_ranges"] = ["10.0.0.0/8"]
            warnings.append("Replaced 0.0.0.0/0 with 10.0.0.0/8 — set to your trusted CIDR.")
            return _tfjson_dump(parsed, content), f"Restricted source_ranges on {rtype}.{rname}.", warnings

    # ----- Lambda VPC config (LOW-severity nudge — emit a TODO companion) -----
    if cat == "network" and rtype == "aws_lambda_function" and "VPC" in title:
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        config["vpc_config"] = {
            "subnet_ids": ["CHANGE_ME_SUBNET_ID_1", "CHANGE_ME_SUBNET_ID_2"],
            "security_group_ids": ["CHANGE_ME_SECURITY_GROUP_ID"],
        }
        warnings.append("vpc_config added with placeholder subnet/SG IDs — replace before applying.")
        return _tfjson_dump(parsed, content), f"Added vpc_config to {rtype}.{rname}.", warnings

    # ----- Error handling: Lambda DLQ — needs SQS/SNS ARN (TODO) -----
    if cat == "error-handling" and rtype == "aws_lambda_function" and "dead letter" in title.lower():
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        config["dead_letter_config"] = {
            "target_arn": "CHANGE_ME_SQS_OR_SNS_ARN"
        }
        warnings.append(
            "dead_letter_config added with a placeholder ARN — point it at an existing SQS queue "
            "or SNS topic before applying. The Lambda role also needs sqs:SendMessage / "
            "sns:Publish permission for the target."
        )
        return _tfjson_dump(parsed, content), f"Added dead_letter_config to {rtype}.{rname}.", warnings

    raise RemediationError(
        f"No deterministic Terraform-JSON fixer for category='{cat}', resource='{resource}'."
    )


# ---------------------------------------------------------------------------
# LLM fallback — for categories without a deterministic fixer
# ---------------------------------------------------------------------------


_LLM_PATCH_SCHEMA = (
    "Respond using EXACTLY this sentinel format (NOT JSON — do not escape "
    "anything, do not use quotes around the file):\n"
    "<<<PATCHED_FILE>>>\n"
    "<the FULL patched file, verbatim, no truncation, no markdown fences>\n"
    "<<<END_PATCHED_FILE>>>\n"
    "<<<EXPLANATION>>> <one short sentence describing the change>\n"
    "\n"
    "The file goes between the PATCHED_FILE sentinels exactly as it should be "
    "written to disk — with real newlines and real quotes, NOT escaped. Emit "
    "nothing else."
)

# Sentinel markers for the robust (non-JSON) response format. Chosen so they
# can never collide with HCL / YAML / JSON content.
_SENTINEL_FILE_START = "<<<PATCHED_FILE>>>"
_SENTINEL_FILE_END = "<<<END_PATCHED_FILE>>>"
_SENTINEL_EXPLANATION = "<<<EXPLANATION>>>"


def _parse_sentinel_response(text: str) -> Optional[tuple[str, str]]:
    """Extract (patched_content, explanation) from the sentinel format.

    Bulletproof for file bodies full of quotes/newlines because it is a plain
    substring slice — no escaping, no JSON. Returns None if the start sentinel
    is absent (so the caller can fall back to JSON parsing for older prompts).
    """
    start = text.find(_SENTINEL_FILE_START)
    if start == -1:
        return None
    body_start = start + len(_SENTINEL_FILE_START)
    end = text.find(_SENTINEL_FILE_END, body_start)
    if end == -1:
        # Start sentinel but no end — truncated. Take everything after start;
        # the caller re-validates, so a genuinely broken partial is rejected.
        body = text[body_start:]
    else:
        body = text[body_start:end]
    # The body typically starts/ends with the newline that framed the sentinel.
    patched = body.strip("\n")

    explanation = "LLM-generated patch."
    exp_idx = text.find(_SENTINEL_EXPLANATION)
    if exp_idx != -1:
        explanation = text[exp_idx + len(_SENTINEL_EXPLANATION):].strip() or explanation
        # Keep the explanation to a single line.
        explanation = explanation.splitlines()[0].strip() if explanation else "LLM-generated patch."

    if not patched.strip():
        return None
    return patched, explanation



def _parse_llm_json_response(text: str) -> tuple[str, str]:
    """Best-effort extraction of (patched_content, explanation) from a
    local-LLM response.

    Local models (Gemma especially) often emit JSON with literal newlines
    inside string values, which strict ``json.loads`` rejects with
    ``Invalid control character at: line N column M``. This helper tries
    progressively more permissive strategies before giving up:

    1. Strict ``json.loads`` — fastest, works when the model behaved
    2. ``json.loads(strict=False)`` — accepts unescaped tabs/newlines in strings
    3. Regex extraction of the ``patched_content`` JSON-string body, then
       JSON-decode that single string in isolation. Survives extra junk
       around the JSON, embedded markdown fences, etc.
    4. ``yaml.safe_load`` of the response — JSON is a subset of YAML, and
       PyYAML is more permissive about whitespace.
    5. Salvage an UNTERMINATED / truncated ``patched_content`` by anchoring on
       the opening quote (no closing quote required). Recovers responses where
       the model cut off mid-file or emitted a raw ``"`` inside the body. Last
       resort — the recovered text is still re-validated by the caller, so a
       genuinely broken partial file is rejected and retried, not returned.

    Raises ValueError if every strategy fails.
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("LLM response is empty.")

    # Strategy 0 (preferred): sentinel format. Bulletproof for file bodies full
    # of quotes/newlines because it is a plain substring slice. Tried BEFORE any
    # fence-stripping so the markers are matched against the raw response.
    sentinel = _parse_sentinel_response(text)
    if sentinel is not None:
        return sentinel

    # Strip ```json / ``` fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        text = text.rsplit("```", 1)[0]
    text = text.strip()

    first_error: Optional[str] = None

    # Strategy 1: strict JSON
    try:
        data = json.loads(text)
        return _coerce_llm_payload(data)
    except Exception as e:
        first_error = f"strict JSON: {e}"

    # Strategy 2: JSON with control-char tolerance
    try:
        data = json.loads(text, strict=False)
        return _coerce_llm_payload(data)
    except Exception as e:
        if first_error is None:
            first_error = f"lenient JSON: {e}"

    # Strategy 3: regex pluck of "patched_content" body, then re-decode it
    # as a JSON string in isolation. Tolerates newlines inside the value.
    m = re.search(
        r'"patched_content"\s*:\s*"((?:\\.|[^"\\])*)"',
        text,
        re.DOTALL,
    )
    if m:
        raw = '"' + m.group(1) + '"'
        try:
            patched = json.loads(raw, strict=False)
            # Try to also pull out an explanation; not fatal if absent
            em = re.search(
                r'"explanation"\s*:\s*"((?:\\.|[^"\\])*)"', text, re.DOTALL
            )
            explanation = (
                json.loads('"' + em.group(1) + '"', strict=False)
                if em else "LLM-generated patch."
            )
            return patched, explanation
        except Exception as e:
            if first_error is None:
                first_error = f"regex extract: {e}"

    # Strategy 4: YAML-permissive parse (JSON is a subset of YAML and PyYAML
    # tolerates unescaped newlines in plain strings).
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return _coerce_llm_payload(data)
    except Exception as e:
        if first_error is None:
            first_error = f"yaml fallback: {e}"

    # Strategy 5: salvage an UNTERMINATED / truncated patched_content. Local
    # models frequently either (a) cut off mid-file so the closing quote never
    # arrives, or (b) emit a raw ``"`` inside the HCL/YAML body that ends the
    # JSON string early. Strategies 1-4 all require a well-formed closing quote;
    # this one does not. We anchor on the OPENING ``"patched_content": "`` and
    # take everything after it, then strip a recognizable JSON tail if present.
    open_m = re.search(r'"patched_content"\s*:\s*"', text)
    if open_m:
        body = text[open_m.end():]
        # If a well-formed tail exists (", "explanation": "...") OR a closing
        # "} at the very end, cut the body there. Otherwise keep the whole
        # remainder (truncated response — best effort).
        tail_m = re.search(r'"\s*,\s*"explanation"\s*:\s*"((?:\\.|[^"\\])*)"', body, re.DOTALL)
        explanation = "LLM-generated patch (recovered from malformed JSON)."
        if tail_m:
            body = body[:tail_m.start()]
            try:
                explanation = json.loads('"' + tail_m.group(1) + '"', strict=False)
            except Exception:
                pass
        else:
            # Strip a trailing closing quote+brace if the model got that far.
            body = re.sub(r'"\s*}\s*$', "", body)
            body = re.sub(r'"\s*$', "", body)
        # Unescape common JSON escapes that may appear in the salvaged body.
        # We do NOT json.loads it (it may be unterminated); do a targeted
        # unescape of the sequences a model realistically emits.
        salvaged = (
            body.replace('\\n', '\n')
                .replace('\\t', '\t')
                .replace('\\"', '"')
                .replace('\\\\', '\\')
        )
        salvaged = salvaged.strip()
        if salvaged:
            return salvaged, explanation

    raise ValueError(
        f"LLM response could not be parsed ({first_error or 'no recoverable content'})"
    )


def _coerce_llm_payload(data: Any) -> tuple[str, str]:
    """Normalize a parsed LLM payload to (patched_content, explanation)."""
    if not isinstance(data, dict):
        raise ValueError(f"LLM payload is not a JSON object (got {type(data).__name__})")
    patched = data.get("patched_content", "")
    explanation = data.get("explanation", "LLM-generated patch.")
    if not isinstance(patched, str):
        raise ValueError(
            f"patched_content is not a string (got {type(patched).__name__})"
        )
    if not isinstance(explanation, str):
        explanation = str(explanation)
    return patched, explanation


# ---------------------------------------------------------------------------
# Structured-edit LLM fallback (the robust path)
#
# Instead of asking a local model to reproduce a whole file verbatim — which it
# cannot do reliably on large files (it drops resources / truncates) — we ask it
# for a tiny STRUCTURED EDIT describing WHAT to change, and apply it with the
# same deterministic editors the rule-based fixers use. The model only emits a
# handful of tokens, so the failure modes (dropped resources, truncation,
# unescaped quotes) simply cannot occur.
#
# Edit schema (JSON):
#   {"op": "set_attribute", "resource": "<type.name>|<Kind/ns/name>",
#    "attribute": "<name>", "value": "<literal>", "explanation": "..."}
#   {"op": "add_block", "resource": "<type.name>", "block": "<HCL lines>",
#    "explanation": "..."}
# ---------------------------------------------------------------------------

_STRUCTURED_EDIT_SCHEMA = (
    "Respond with a SMALL JSON edit describing ONLY the change — do NOT output "
    "the file. Two shapes are allowed:\n"
    '  {"op": "set_attribute", "resource": "<resource address>", '
    '"attribute": "<attribute name>", "value": "<new value>", '
    '"explanation": "<one sentence>"}\n'
    '  {"op": "add_block", "resource": "<resource address>", '
    '"block": "<one nested block, e.g. metadata_options { http_tokens = \\"required\\" }>", '
    '"explanation": "<one sentence>"}\n'
    "For a Terraform resource the address is `type.name` (e.g. "
    "`azurerm_mssql_database.main`). For booleans use true/false (no quotes); "
    "for strings include the quotes in the value (e.g. \"TLS1_2\"). Prefer "
    "set_attribute. Emit ONLY the JSON, nothing else."
)


def _parse_structured_edit(text: str) -> Optional[dict]:
    """Extract a structured-edit JSON object from an LLM response.

    Returns the dict, or None if no usable edit object is found. Tolerant of
    markdown fences and surrounding prose (the edit is small, so a simple
    brace-matched extraction is reliable).
    """
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        t = t.rsplit("```", 1)[0]
    t = t.strip()
    # Try the whole thing first, then the first {...} object found.
    candidates = [t]
    brace = re.search(r"\{.*\}", t, re.DOTALL)
    if brace:
        candidates.append(brace.group(0))
    for cand in candidates:
        for loader in (lambda s: json.loads(s), lambda s: json.loads(s, strict=False)):
            try:
                obj = loader(cand)
                if isinstance(obj, dict) and obj.get("op") in ("set_attribute", "add_block"):
                    return obj
            except Exception:
                continue
    return None


def _value_to_hcl_literal(value: Any) -> str:
    """Convert a JSON edit value to an HCL literal.

    - Python bool -> true/false
    - already-quoted string ("TLS1_2") -> as-is
    - bare string that looks like a bool/number -> as-is
    - other bare string -> quoted
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value).strip()
    if s.lower() in ("true", "false"):
        return s.lower()
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        return s
    if (s.startswith('"') and s.endswith('"')) or s.startswith(("[", "{")):
        return s  # already a literal / list / object reference
    if "." in s and re.fullmatch(r"[a-z][\w.-]+", s):
        return s  # looks like a resource/var reference (aws_x.y.z)
    return f'"{s}"'


def apply_structured_edit(
    edit: dict, kind: str, content: str
) -> tuple[str, str, list[str]]:
    """Apply a structured edit to file content using the deterministic editors.

    Supports Terraform HCL and Terraform JSON. Returns
    ``(patched, explanation, warnings)``. Raises RemediationError if the edit
    cannot be applied (caller then falls back to the whole-file approach).
    """
    op = edit.get("op")
    resource = str(edit.get("resource", "")).strip()
    explanation = str(edit.get("explanation") or "LLM structured edit.")
    warnings: list[str] = []

    if kind == "terraform_hcl":
        if "." not in resource:
            raise RemediationError(f"Structured edit resource '{resource}' is not a Terraform address.")
        rtype, _, rname = resource.partition(".")
        rname = rname.split(".", 1)[0]
        if op == "set_attribute":
            attr = str(edit.get("attribute", "")).strip()
            if not attr:
                raise RemediationError("set_attribute edit missing 'attribute'.")
            literal = _value_to_hcl_literal(edit.get("value"))
            patched = _tf_set_argument_in_block(content, rtype, rname, attr, literal)
            return patched, explanation, warnings
        if op == "add_block":
            block = str(edit.get("block", "")).strip()
            if not block:
                raise RemediationError("add_block edit missing 'block'.")
            patched = _tf_inject_argument_in_block(content, rtype, rname, block)
            return patched, explanation, warnings
        raise RemediationError(f"Unsupported structured-edit op '{op}'.")

    if kind == "terraform_json":
        if "." not in resource:
            raise RemediationError(f"Structured edit resource '{resource}' is not a Terraform address.")
        rtype, _, rname = resource.partition(".")
        rname = rname.split(".", 1)[0]
        parsed = json.loads(content)
        config = _tfjson_get_resource_block(parsed, rtype, rname)
        if op == "set_attribute":
            attr = str(edit.get("attribute", "")).strip()
            if not attr:
                raise RemediationError("set_attribute edit missing 'attribute'.")
            config[attr] = _json_value_from_edit(edit.get("value"))
            return _tfjson_dump(parsed, content), explanation, warnings
        raise RemediationError(f"Unsupported structured-edit op '{op}' for Terraform JSON.")

    # Kubernetes structured edits are not yet supported here; K8s has strong
    # deterministic coverage already, so we defer to the whole-file path.
    raise RemediationError(f"Structured edits not supported for kind '{kind}'.")


def _json_value_from_edit(value: Any) -> Any:
    """Coerce an edit value into a native JSON value for Terraform-JSON."""
    if isinstance(value, (bool, int, float, list, dict)):
        return value
    s = str(value).strip()
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


async def _fix_with_llm(
    finding: Finding, filename: str, kind: str, content: str, max_attempts: int = 2
) -> tuple[str, str]:
    """Ask the LLM to produce a patched file. Validate by re-parse, retry once.

    Returns (patched_content, explanation).
    """
    if kind in ("kubernetes_yaml", "kubernetes_json"):
        skill_name = "remediator-k8s"
    else:
        skill_name = "remediator-tf"
    try:
        base_prompt = load_skill(skill_name).get("prompt", "")
    except FileNotFoundError:
        base_prompt = ""
    if not base_prompt:
        # Defensive: skill file missing — fall back to a minimal inline prompt
        base_prompt = (
            "You are an Infrastructure Remediation Agent. Given a finding and a file, "
            "produce the FULL patched file content that fixes the finding. Make the smallest "
            "change that resolves the issue. Never invent unrelated changes. Preserve all "
            "comments, formatting, and unrelated resources exactly. "
            "Respond ONLY with valid JSON: "
            '{"patched_content": "<full patched file>", "explanation": "<one sentence>"}'
        )

    finding_block = (
        f"Finding category: {finding.category}\n"
        f"Severity: {finding.severity.value if isinstance(finding.severity, Severity) else finding.severity}\n"
        f"Title: {finding.title}\n"
        f"Resource: {finding.resource}\n"
        f"Description: {finding.description}\n"
        f"Recommendation: {finding.recommendation}\n"
    )

    from langchain_core.messages import HumanMessage, SystemMessage

    # ------------------------------------------------------------------ #
    # Primary path: STRUCTURED EDIT (Terraform only for now).
    #
    # Ask the model for a tiny edit instruction, then apply it with the
    # deterministic editors. The model emits ~a dozen tokens, so it cannot
    # drop resources or truncate the file — the exact failures that plague
    # the whole-file approach on large files with a local model.
    # ------------------------------------------------------------------ #
    if kind in ("terraform_hcl", "terraform_json"):
        edit_last_error = ""
        for _ in range(max_attempts):
            retry = f"\nYour previous edit failed: {edit_last_error}\n" if edit_last_error else ""
            human_text = (
                f"FILE: {filename}\nKIND: {kind}\n\n{finding_block}\n"
                f"------ ORIGINAL FILE ------\n{content}\n------ END ------\n{retry}"
            )
            messages = [
                SystemMessage(content=base_prompt + "\n\n" + _STRUCTURED_EDIT_SCHEMA),
                HumanMessage(content=human_text),
            ]
            try:
                response = await get_llm().ainvoke(messages)
                edit = _parse_structured_edit((response.content or "").strip())
            except Exception as e:  # noqa: BLE001
                edit_last_error = f"LLM error: {e}"
                continue
            if not edit:
                edit_last_error = "no valid structured edit in response"
                continue
            try:
                patched, explanation, _w = apply_structured_edit(edit, kind, content)
            except RemediationError as e:
                edit_last_error = f"could not apply edit: {e}"
                continue
            patched = _strip_cosmetic_drift(content, patched)
            try:
                _validate_patch(filename, kind, patched)
                _verify_no_resources_dropped(content, patched, kind)
            except PatchValidationError as e:
                edit_last_error = str(e)
                continue
            return patched, explanation
        logger.info(
            "Structured-edit path exhausted for %s (%s); falling back to whole-file. Last: %s",
            finding.title, kind, edit_last_error,
        )

    last_error = ""
    for attempt in range(max_attempts):
        # Build the messages directly — bypassing ChatPromptTemplate avoids
        # any curly-brace collisions with HCL/YAML/JSON content embedded in
        # the file body.
        retry_note = (
            f"\nPrevious attempt failed validation: {last_error}\n" if last_error else ""
        )
        human_text = (
            f"FILE: {filename}\nKIND: {kind}\n\n{finding_block}\n"
            f"------ ORIGINAL FILE ------\n{content}\n------ END ------\n"
            f"{retry_note}"
        )
        messages = [
            SystemMessage(content=base_prompt + "\n\n" + _LLM_PATCH_SCHEMA.replace("{{", "{").replace("}}", "}")),
            HumanMessage(content=human_text),
        ]
        try:
            response = await get_llm().ainvoke(messages)
            response_text = (response.content or "").strip()
            patched, explanation = _parse_llm_json_response(response_text)
        except Exception as e:
            last_error = f"LLM response parse error: {e}"
            continue
        if not isinstance(patched, str) or not patched.strip():
            last_error = "LLM returned empty patched_content."
            continue
        # Strip cosmetic drift BEFORE validation so the cleaned output is
        # what we re-parse and return. If the filter accidentally produced
        # something unparseable, validation below catches it and we retry.
        patched = _strip_cosmetic_drift(content, patched)
        try:
            _validate_patch(filename, kind, patched)
        except PatchValidationError as e:
            last_error = str(e)
            continue
        # Structural-preservation safety net — reject LLM patches that
        # silently drop resources from multi-resource files. This protects
        # against the failure mode where the LLM, focused on adding/editing
        # one thing, deletes adjacent documents (real-world bug from
        # samples/critical-security-failure.yaml).
        try:
            _verify_no_resources_dropped(content, patched, kind)
        except PatchValidationError as e:
            last_error = str(e)
            continue
        return patched, explanation
    raise RemediationError(f"LLM remediation failed after {max_attempts} attempts: {last_error}")


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


async def remediate(
    finding: Finding,
    finding_index: int,
    file_contents: dict[str, str],
) -> Patch:
    """Generate a Patch for the given finding against the original bundle.

    Steps:
    1. Short-circuit non-patchable / companion-resource findings up-front
       so we don't waste LLM calls on impossible asks.
    2. Locate the file the finding refers to.
    3. Try the deterministic fixer for the file kind.
    4. On RemediationError from step 3, fall back to the LLM.
    5. Validate by re-parse. Build the unified diff.
    """
    if not file_contents:
        raise RemediationError("Original file bundle is empty.")

    # Phase 3.5 — roll-up / meta findings (compliance framework summaries) are
    # not tied to a single resource and cannot be patched. Refuse cleanly before
    # attempting to locate a file (which would fail with a misleading error).
    if finding.category in _NON_PATCHABLE_CATEGORIES:
        if finding.category == "resilience":
            raise NonPatchableFinding(
                f"'{finding.title}' is an architectural observation (a single point "
                "of failure), not a config defect — there is no single attribute to "
                "patch. Address it by a design change: add redundancy (replicas / "
                "Multi-AZ / a standby or read replica) or decouple the dependents so "
                "this resource's loss does not cascade."
            )
        raise NonPatchableFinding(
            f"'{finding.title}' is a compliance roll-up that summarizes other "
            "findings against a framework — there is no single resource to patch. "
            "Generate fixes on the underlying Security / Reliability / Cost findings "
            "mapped to the failing controls; the framework score rises as those are "
            "resolved."
        )

    # Phase 3.4 — companion-resource findings (HPA, PDB, NetworkPolicy)
    # require creating a NEW Kubernetes resource, not editing the
    # existing one. Detect these BEFORE attempting to locate a file or
    # invoke the LLM (which would either emit a JSON array — invalid
    # for kubectl on a single-doc file — or fail validation entirely).
    if finding.category in _COMPANION_RESOURCE_CATEGORIES:
        template, suggested_filename = _companion_template(finding.category, finding)
        if template:
            raise CompanionResourceRequired(
                message=(
                    f"This finding requires creating a NEW Kubernetes resource "
                    f"({finding.category}) alongside your workload. It cannot be "
                    f"patched into the existing manifest. Create a new file "
                    f"named {suggested_filename!r} with the template below."
                ),
                template=template,
                filename=suggested_filename,
            )

    filename, kind, content = _locate_file_for_finding(finding, file_contents)

    strategy: str
    explanation: str
    warnings: list[str] = []
    patched: str

    # If this is an LLM-emitted finding (category="ai-analysis"), try to
    # infer the equivalent rule-engine category from the title + resource
    # type. When inference succeeds, the deterministic fixer table can
    # handle it instantly instead of round-tripping through a 120s+ LLM
    # call. When inference fails (or the inferred fixer doesn't actually
    # apply), we fall through to the LLM with the ORIGINAL finding.
    fixer_finding = finding
    inferred_cat = _infer_rule_category(finding)
    if inferred_cat is not None:
        fixer_finding = finding.model_copy(update={"category": inferred_cat})

    try:
        if kind in ("kubernetes_yaml", "kubernetes_json"):
            patched, explanation, warnings = _fix_k8s(fixer_finding, content, file_kind=kind)
        elif kind in ("terraform_hcl", "terraform_json"):
            if kind == "terraform_json":
                # Phase 3.4 — try the deterministic JSON-tree fixer first.
                # Falls through to the LLM only for categories without a
                # known JSON transformation. The LLM is unreliable on
                # multi-hundred-line JSON files (the "Invalid control
                # character" failure mode), so we deterministic-first.
                patched, explanation, warnings = _fix_tf_json(fixer_finding, content)
            else:
                patched, explanation, warnings = _fix_tf(fixer_finding, content)
        else:
            raise RemediationError(f"Unsupported file kind '{kind}'.")
        strategy = "deterministic"
    except RemediationError:
        # Fall back to the LLM. If the LLM also fails, surface the error.
        patched, explanation = await _fix_with_llm(finding, filename, kind, content)
        strategy = "llm"
        warnings.append("Patch produced by LLM — review carefully before applying.")

    # Final validation. Deterministic fixers should already be valid, but we
    # double-check so a malformed YAML round-trip can't slip through.
    _validate_patch(filename, kind, patched)
    validation_status = "valid"

    diff = _make_unified_diff(filename, content, patched)
    if not diff:
        # Identical output means the fixer was a no-op — surface as a warning.
        warnings.append("Patch is a no-op (content unchanged). Manual remediation may be needed.")

    return Patch(
        finding_index=finding_index,
        finding_title=finding.title,
        filename=filename,
        original_content=content,
        patched_content=patched,
        unified_diff=diff,
        strategy=strategy,
        validation_status=validation_status,
        explanation=explanation,
        warnings=warnings,
    )


def remediate_sync(
    finding: Finding,
    finding_index: int,
    file_contents: dict[str, str],
) -> Patch:
    """Synchronous wrapper around :func:`remediate` for tests / scripts.

    Spawns a fresh event loop. Don't call from inside an async context.
    """
    return asyncio.run(remediate(finding, finding_index, file_contents))

