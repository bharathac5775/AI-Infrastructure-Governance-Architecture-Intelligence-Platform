---
name: compliance
agent: compliance
agent_name: Compliance Agent
agent_type: rule_based
weight: 0.10
infra_type: all
description: Maps findings to compliance controls (CIS Benchmarks, NIST 800-53) and scores per-framework posture
version: "1.0"
---

# Compliance Agent (Phase 3.5 plugin)

This is the first dynamically-registered plugin agent. It is **rule_based**: no
LLM runs for it. Its execution is a deterministic Python adapter
(`app/core/plugin_loader.py::_compliance_adapter`) that reuses the Phase 3.3
compliance engine (`app/core/compliance.py`) end to end.

## What it does

1. Reads the findings produced by the core agents (Security, Reliability, Cost).
2. Enriches each finding with the compliance controls it implicates
   (`enrich_findings_with_compliance`).
3. Computes per-framework compliance scores, cloud-scoped
   (`compute_compliance_scorecard`) across CIS Kubernetes, CIS AWS, CIS Azure,
   CIS GCP, and NIST 800-53.
4. Reports one finding per framework that has failing controls, with a severity
   that scales with how much of the framework is failing.

## Scoring

The agent's 0-100 score is the mean of the per-framework `score_pct`. When no
framework applies to the uploaded infrastructure the score is 100.0 (a clean or
non-applicable upload is never penalized). This score joins the overall
governance score at the `weight` declared in the frontmatter above.

## Why a plugin

Compliance is orthogonal to security/reliability/cost. Modeling it as a plugin
proves the harness supports `rule_based` agents and lets future compliance
frameworks ship as pure JSON edits (see `app/data/compliance_mappings.json`)
with zero pipeline changes.
