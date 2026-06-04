"""Compliance framework mapping (Phase 3.3 — cloud-aware).

Tags every rule-based finding with the compliance controls it implicates,
then computes per-framework compliance scores from the resulting findings,
the universe of mapped controls, and **what clouds were actually present
in the upload**.

Key concepts:
- A control is **assessable** on this upload if at least one rule that maps
  to it has a domain tag that matches a detected cloud (or domain is
  "cross-cloud", which always matches).
- A control is **failed** if any current finding implicates it.
- A control is **passed** if it's assessable AND not failed.
- Score = passed / max(1, passed + failed) * 100, computed only over
  assessable controls. Frameworks with zero assessable controls are
  EXCLUDED from the scorecard entirely.
- A framework is **included** only if at least one of its `requires_any_of`
  clouds was detected.

Why both filters: we need cloud-detection to (a) stop CIS AWS from showing
up on Azure-only uploads, and (b) stop "passed" from being inflated by
controls whose underlying rules never had a chance to fire.

Mappings live in app/data/compliance_mappings.json — edit there, not here.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.models import (
    AnalysisReport,
    ComplianceFrameworkScore,
    ComplianceScorecard,
    Finding,
)

logger = logging.getLogger(__name__)

_MAPPINGS_PATH = Path(__file__).parent.parent / "data" / "compliance_mappings.json"


@lru_cache(maxsize=1)
def load_mappings() -> dict:
    """Load and cache the compliance mappings JSON file."""
    try:
        return json.loads(_MAPPINGS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning(f"Compliance mappings file not found: {_MAPPINGS_PATH}")
        return _empty_mappings()
    except json.JSONDecodeError as e:
        logger.error(f"Invalid compliance mappings JSON: {e}")
        return _empty_mappings()


def _empty_mappings() -> dict:
    return {
        "frameworks": {},
        "rule_mappings": {},
        "title_overrides": {},
        "framework_prefix_map": {},
        "control_descriptions": {},
    }


def _entry_controls(entry) -> list[str]:
    """Extract the controls list from a mapping entry. Tolerates both the
    new {domain, controls} dict shape and the old plain-list shape (in case
    a hand-edited mapping file is still using the legacy format)."""
    if isinstance(entry, dict):
        return list(entry.get("controls", []))
    if isinstance(entry, list):
        return list(entry)
    return []


def _entry_domain(entry) -> str:
    """Extract the domain from a mapping entry. Defaults to 'cross-cloud'
    for legacy entries that don't specify one."""
    if isinstance(entry, dict):
        return entry.get("domain", "cross-cloud")
    return "cross-cloud"


def get_controls_for_finding(finding: Finding) -> list[str]:
    """Return the compliance controls that this finding implicates.

    Lookup priority:
      1. title_overrides[finding.title] — most specific
      2. rule_mappings[finding.agent][finding.category] — default
      3. [] — no mapping known
    """
    mappings = load_mappings()

    title_overrides = mappings.get("title_overrides", {})
    if finding.title in title_overrides:
        return _entry_controls(title_overrides[finding.title])

    rule_mappings = mappings.get("rule_mappings", {})
    agent_mappings = rule_mappings.get(finding.agent, {})
    return _entry_controls(agent_mappings.get(finding.category, []))


def enrich_findings_with_compliance(report: AnalysisReport) -> None:
    """Mutates report in-place: sets `finding.compliance_controls` on every finding."""
    for agent_report in report.agent_reports:
        for finding in agent_report.findings:
            finding.compliance_controls = get_controls_for_finding(finding)


def _classify_control(control_id: str, mappings: dict) -> Optional[str]:
    """Map a control ID (e.g. "CIS-K8s-5.2.1") to its framework_id."""
    prefix_map: dict[str, str] = mappings.get("framework_prefix_map", {})
    # Longest prefix wins so "CIS-K8s-" beats "CIS-" if both ever existed
    for prefix in sorted(prefix_map.keys(), key=len, reverse=True):
        if control_id.startswith(prefix):
            return prefix_map[prefix]
    return None


# ---------------------------------------------------------------------------
# Cloud detection — Phase 3.3 fix
#
# Identify which clouds (kubernetes / aws / azure / gcp) actually appear in
# the uploaded bundle. Used to (a) decide which frameworks to include and
# (b) decide which controls are "assessable" by a rule that could fire on
# this upload.
# ---------------------------------------------------------------------------


# Resource-prefix → cloud lookups. Order matters for substring-style matching
# (prefer longer / more specific prefixes first when in doubt).
_RESOURCE_PREFIX_TO_CLOUD: list[tuple[str, str]] = [
    ("aws_",       "aws"),
    ("azurerm_",   "azure"),
    ("google_",    "gcp"),
]


def _detect_clouds_from_resource(resource: str) -> Optional[str]:
    """Identify the cloud from a single Finding.resource string, or None.

    K8s resources are shaped ``Kind/namespace/name`` (set by
    ``app.parsers.kubernetes.get_resource_name``). Some LLM-emitted findings
    use ``Kind/name`` (two-segment) which we also accept.

    We require the first segment to be a real K8s Kind: CapitalCase,
    alphabetic-only, and at least 3 characters. The previous heuristic
    accepted ANY ``X/...`` string starting with a capital letter, which
    caused LLM-emitted resource fields like ``N/A`` to be falsely
    classified as Kubernetes — leaking CIS Kubernetes framework into
    AWS-only scorecards.

    A short, well-known list of stop-words is also excluded so that LLMs
    that emit things like ``Infrastructure/global/all`` don't slip through.
    """
    if not resource:
        return None
    r = resource.strip().lower()
    for prefix, cloud in _RESOURCE_PREFIX_TO_CLOUD:
        if r.startswith(prefix):
            return cloud

    parts = resource.split("/")
    if len(parts) not in (2, 3):
        return None
    kind = parts[0]
    rest = parts[1:]
    # All segments must be non-empty and contain no whitespace
    if not all(seg and " " not in seg for seg in [kind, *rest]):
        return None
    # Kind must be alphabetic, CapitalCase, and at least 3 characters.
    # Rejects "N" (from "N/A"), "S3", "RDS", "EC2", and similar.
    if not (kind.isalpha() and kind[0].isupper() and len(kind) >= 3):
        return None
    # Real K8s Kinds are mixed-case (Deployment, ConfigMap, ClusterRoleBinding,
    # Pod, Job, etc.) — they always contain at least one lowercase letter after
    # the first character. All-uppercase abbreviations like "RDS", "KMS",
    # "IAM", "VPC" are AWS shorthand the LLM occasionally emits, not K8s.
    if kind[1:].isupper():
        return None
    # Stop-word safety net for ambiguous CapitalCase words the LLM emits as
    # generic resource labels rather than real Kubernetes resources.
    _NON_K8S_STOPWORDS = {
        "Infrastructure", "Cluster", "Network", "Account",
        "Resource", "Application", "Database", "Storage",
    }
    if kind in _NON_K8S_STOPWORDS:
        return None
    return "kubernetes"


def _detect_clouds(
    report: AnalysisReport,
    tf_resources: list | None = None,
) -> dict[str, bool]:
    """Detect which clouds are present in the report.

    Detection signals, in priority order:
      1. Cloud-specific prefixes in `Finding.resource` strings
         (`aws_*`, `azurerm_*`, `google_*`) and K8s `Kind/...` shape
      2. Optional `tf_resources` (parsed Terraform) — primary signal for
         clean uploads with zero findings, where we still need to know
         the cloud to scope frameworks correctly
      3. Fallback: any `.yaml`/`.yml` filename in `files_analyzed` implies
         kubernetes (safe because YAML+findings always reveal K8s-shaped
         resources, but a clean YAML upload has no findings to scan)

    We deliberately do NOT use a bare `.tf`/`.hcl` extension as a signal —
    that was the original Phase 3.3 bug where Azure-only `.tf` uploads got
    classified as AWS. The `tf_resources` list (parsed from the same file)
    carries unambiguous `aws_*`/`azurerm_*`/`google_*` resource types.

    Returns a dict with all four keys, defaulted to False:
        {"kubernetes": bool, "aws": bool, "azure": bool, "gcp": bool}
    """
    detected = {"kubernetes": False, "aws": False, "azure": False, "gcp": False}

    for ar in report.agent_reports:
        for f in ar.findings:
            cloud = _detect_clouds_from_resource(f.resource)
            if cloud and cloud in detected:
                detected[cloud] = True

    # Walk parsed Terraform resources directly — primary signal when there
    # are zero findings yet (clean cloud-specific uploads).
    if tf_resources:
        for res in tf_resources:
            rtype = res.get("type", "") if isinstance(res, dict) else ""
            for prefix, cloud in _RESOURCE_PREFIX_TO_CLOUD:
                if rtype.startswith(prefix):
                    detected[cloud] = True
                    break

    # Fallback: K8s manifests with zero findings still count as kubernetes
    if not any(detected.values()):
        for fname in report.files_analyzed:
            lower = fname.lower()
            if lower.endswith((".yaml", ".yml")):
                detected["kubernetes"] = True
                break

    return detected


# ---------------------------------------------------------------------------
# Scorecard
# ---------------------------------------------------------------------------


def _build_control_assessability(mappings: dict) -> dict[str, set[str]]:
    """Reverse index: control_id -> set of domains that map to it.

    A control is assessable if any of its domains matches a detected cloud
    or is "cross-cloud".
    """
    out: dict[str, set[str]] = {}
    for cat_map in mappings.get("rule_mappings", {}).values():
        for entry in cat_map.values():
            domain = _entry_domain(entry)
            for c in _entry_controls(entry):
                out.setdefault(c, set()).add(domain)
    for entry in mappings.get("title_overrides", {}).values():
        domain = _entry_domain(entry)
        for c in _entry_controls(entry):
            out.setdefault(c, set()).add(domain)
    return out


def _is_control_assessable(
    control_id: str,
    assessability: dict[str, set[str]],
    detected_clouds: dict[str, bool],
) -> bool:
    """A control is assessable iff cross-cloud OR any of its domains is a
    detected cloud."""
    domains = assessability.get(control_id, set())
    if not domains:
        return False
    if "cross-cloud" in domains:
        return True
    return any(detected_clouds.get(d, False) for d in domains)


def compute_compliance_scorecard(
    report: AnalysisReport,
    infra_type: str = "",          # kept for back-compat; no longer the primary signal
    tf_resources: list | None = None,
) -> ComplianceScorecard:
    """Compute per-framework compliance scores for a report.

    Phase 3.3 fix: cloud-aware scoping.
    1. Detect which clouds (k8s/aws/azure/gcp) are actually present, using
       finding resources as the primary signal and parsed `tf_resources`
       as a fallback for clean uploads with zero findings.
    2. Include a framework only if at least one of its `requires_any_of`
       clouds is detected.
    3. Inside each included framework, only consider controls that are
       *assessable* — i.e. some rule mapping (with a matching domain) could
       have evaluated them. Skip the framework if zero controls are assessable.
    4. Compute pass/fail only over assessable controls.

    `infra_type` is accepted for backwards compatibility with callers but is
    not used; cloud detection from finding resources / tf_resources is more
    accurate.
    """
    mappings = load_mappings()
    frameworks_meta = mappings.get("frameworks", {})

    detected_clouds = _detect_clouds(report, tf_resources=tf_resources)

    # Universe of all controls referenced in any mapping
    control_universe: set[str] = set()
    for cat_map in mappings.get("rule_mappings", {}).values():
        for entry in cat_map.values():
            control_universe.update(_entry_controls(entry))
    for entry in mappings.get("title_overrides", {}).values():
        control_universe.update(_entry_controls(entry))

    control_to_framework: dict[str, Optional[str]] = {
        c: _classify_control(c, mappings) for c in control_universe
    }
    assessability = _build_control_assessability(mappings)

    # Failed: any control mentioned by any finding's compliance_controls
    failed: set[str] = set()
    for ar in report.agent_reports:
        for f in ar.findings:
            failed.update(f.compliance_controls)

    scorecard_entries: list[ComplianceFrameworkScore] = []
    for fw_id, fw_meta in frameworks_meta.items():
        # Framework gate: at least one required cloud must be detected
        required = fw_meta.get("requires_any_of", [])
        if required and not any(detected_clouds.get(c, False) for c in required):
            continue

        # All controls owned by this framework
        fw_controls = [c for c, fid in control_to_framework.items() if fid == fw_id]
        if not fw_controls:
            continue

        # Filter to controls actually assessable on this upload
        assessable_controls = [
            c for c in fw_controls
            if _is_control_assessable(c, assessability, detected_clouds)
        ]
        if not assessable_controls:
            # No rule on this upload could even check this framework — exclude
            continue

        passed = sorted(c for c in assessable_controls if c not in failed)
        failed_list = sorted(c for c in assessable_controls if c in failed)
        denom = len(passed) + len(failed_list)
        score_pct = round(len(passed) / denom * 100, 1) if denom > 0 else 0.0

        scorecard_entries.append(ComplianceFrameworkScore(
            framework_id=fw_id,
            framework_name=fw_meta.get("name", fw_id),
            version=str(fw_meta.get("version", "")),
            score_pct=score_pct,
            controls_passed=passed,
            controls_failed=failed_list,
        ))

    return ComplianceScorecard(frameworks=scorecard_entries)
