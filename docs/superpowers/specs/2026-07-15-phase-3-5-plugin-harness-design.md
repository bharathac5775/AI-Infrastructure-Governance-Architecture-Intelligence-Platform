# Phase 3.5 — Plugin Harness (Dynamic Agent Registration)

**Date:** 2026-07-15
**Status:** Design approved, pending implementation
**Depends on:** Phase 3.3 (Compliance Framework Mapping — shipped)

## Goal

Drop a new skill file into `skills/` and have it picked up automatically as a
new analysis agent — **no Python code change required for a new LLM agent**.
Compliance (Phase 3.3) becomes the first registered plugin.

## Hard constraints (non-negotiable acceptance gates)

1. **No regression.** The full existing test suite that passes today (505 passed,
   38 skipped in this environment — the 8 `test_llm_provider.py` failures and any
   `ruamel`/cloud-SDK import failures are pre-existing environment gaps unrelated
   to this work) MUST remain green.
2. **Byte-identical scores with zero plugins.** `calculate_overall_score` asserts
   exact values (`88.5`, `100.0`, `85.0`, default weight `0.28`). When no plugin
   agent is registered, the scoring code path and result MUST be identical to today.
3. **No redundancy.** Reuse the existing LLM invoke/parse/dedup/score pattern
   (currently duplicated across `security.py`/`reliability.py`/`cost.py`) rather
   than copy-pasting it. Reuse the existing `app/core/compliance.py` for the
   compliance plugin rather than re-deriving compliance via an LLM.
4. **Respect the Ollama single-stream constraint.** Plugins run sequentially. No
   parallel LangGraph nodes (matches the roadmap's "Explicitly Dropped" note).

## Architecture

### New module: `app/core/plugin_registry.py` (descriptor layer)

- `PluginAgent` pydantic model:
  `name`, `agent_name`, `agent_type` (`rule_based | llm_only | hybrid`),
  `weight: float`, `infra_type`, `skill_name`, `prompt`.
- `discover_plugins() -> list[PluginAgent]`: scans `skills/*.md`. A skill is a
  **registerable plugin only if its frontmatter declares BOTH `agent_type` and
  `weight`.** This gate keeps all existing skills (which declare neither) out of
  the plugin path — the source of the "no behavior change until opt-in" guarantee.
- Invalid frontmatter (bad `agent_type`, non-numeric `weight`, weight out of
  `(0, 1]`) is skipped with a logged warning, never crashes discovery.

### New module: `app/core/plugin_loader.py` (execution layer)

- `RULE_BASED_ADAPTERS: dict[str, Callable]` — registry mapping a plugin
  `name` → a Python callable that returns an `AgentReport`. This is how
  `rule_based` plugins (e.g. compliance) execute without an LLM.
- `async def run_plugin(plugin, file_contents, k8s_resources, tf_resources) -> AgentReport | None`:
  - `llm_only` / `hybrid` → delegate to the shared `run_llm_agent(...)` helper.
  - `rule_based` → look up and call the registered adapter; if none registered,
    log a warning and return `None` (skipped, never crashes the pipeline).
- `async def run_all_plugins(...) -> list[AgentReport]`: sequential execution,
  each failure isolated (one bad plugin cannot break the run).

### Refactor (de-duplication): `app/core/llm_agent.py`

- Extract the LLM invoke → strip code fence → `json.loads` → build `Finding`s →
  dedup vs rule findings → severity-deduction score pattern into a single
  `run_llm_agent(agent_name, system_prompt, human_template, file_contents, rule_findings=...)`.
- `security.py` / `reliability.py` / `cost.py` are **not required** to adopt it
  in this phase (to keep their exact behavior and diffs minimal), but the plugin
  loader uses it so the pattern lives in exactly one place going forward. The
  severity-deduction table is imported from a single source of truth.

### Scoring change: `app/core/report.py`

- `calculate_overall_score(agent_reports, architecture_review=None, plugin_reports=None)`.
- When `plugin_reports` is falsy → **early path identical to today** (same dict,
  same math, same rounding). Guarantees constraint #2.
- When present → each plugin's `weight` joins the weight pool; result stays
  `weighted_sum / total_weight` (additive, normalized).

### Pipeline change: `app/agents/supervisor.py`

- New `AnalysisState` key: `plugin_reports: list[AgentReport]`.
- New node `plugin_agents_node`: runs `run_all_plugins(...)`. **Pass-through when
  the registry is empty** (returns `{"plugin_reports": []}`).
- Edge rewire: `architecture_review → plugin_agents → supervisor`
  (was `architecture_review → supervisor`).
- `supervisor_node`: merges plugin reports into `agent_reports` for the final
  report and passes `plugin_reports` to `calculate_overall_score`.

### First plugin: compliance

- `skills/compliance.md` — frontmatter `agent_type: rule_based`, `weight: 0.10`,
  `infra_type: all`, `name: compliance`, `agent: compliance`. Body documents what
  the agent does (LLM never runs for it; the body is informational).
- Adapter in `plugin_loader.py` (`_compliance_adapter`) builds an `AnalysisReport`
  shell from the current agent findings, calls the existing compliance scorecard
  logic in `app/core/compliance.py`, and returns an `AgentReport` named
  `"Compliance Agent"` whose `score` is the mean framework `score_pct` (100.0 when
  no framework applies, so a clean upload is not penalized). Findings summarize
  failed controls. No LLM, no duplication of 3.3 logic.

### Existing skill migration (discoverability, not behavior)

- Add `agent_type` + `weight` to the existing agent skill frontmatter
  (`security-*`, `reliability-*`, `cost-*`, `architecture-reviewer`) so the
  registry can *describe* them. Their hardcoded execution path in the graph is
  unchanged. The `discover_plugins()` scanner explicitly excludes skill names that
  map to already-hardcoded core agents (`security`, `reliability`, `cost`,
  `architecture-reviewer`, `supervisor`, `remediator`) so migration frontmatter
  never causes double-execution. Compliance is the only skill that is both
  frontmatter-tagged AND not in the core-agent exclusion set → the only one that
  actually registers as a runtime plugin.

## Data flow

```
parse_files → security → reliability → cost → architecture_review
            → plugin_agents (compliance, + any future) → supervisor → END
```

## Error handling

- Discovery: bad frontmatter skipped + warned, never raises.
- Execution: each plugin wrapped; exception → logged, plugin contributes no report.
- Missing adapter for a `rule_based` plugin → warned, skipped.
- LLM plugin JSON parse failure → same graceful fallback as existing agents
  (empty findings, neutral summary) via `run_llm_agent`.

## Testing (`tests/test_plugin_harness.py`)

- Registry gate: skills without `agent_type`/`weight` are not discovered.
- Core-agent exclusion: `security`/`cost`/etc. never register as plugins even if
  tagged.
- Compliance registers as exactly one `rule_based` plugin.
- Weight re-normalization: known math example with a plugin present.
- **Zero-plugin invariance:** `calculate_overall_score(...)` with `plugin_reports=[]`
  or `None` equals the value without the argument (protects the 88.5/100.0/85.0
  assertions).
- Compliance adapter returns a valid `AgentReport` with a sane score.
- `agent_type` validation rejects unknown values.
- Full suite: the 505 currently-passing tests stay green.

## Out of scope (deferred / dropped per roadmap)

- Scheduled scans (no always-on infra).
- Parallel agent execution (Ollama single-stream).
- Migrating the 3 core agents to `run_llm_agent` internally (behavior-risk with
  no functional gain this phase).
