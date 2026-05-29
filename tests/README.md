# Tests

Pytest-based regression suite for the AI Infrastructure Governance Platform.

**Runtime:** ~1 second for 206 tests. Runs without Ollama. CI-safe.

---

## Setup

```bash
pip install -r requirements-dev.txt
```

This installs `pytest` and `pytest-asyncio` on top of the production deps.

---

## Running tests

### The daily-driver command

```bash
pytest
```

**Expected output (last line):**
```
================== 206 passed, 38 skipped, 1 warning in ~1s ==================
```

The 38 "skipped" are intentional — they're parametrized sample tests that don't have specific Phase 2 finding sentinels. Skipped ≠ failed.

### See test names as they run

```bash
pytest -v
```

Watch each test's name and result roll by. Useful for visually confirming Phase 2 sentinels like `test_iam_xray_wildcard_not_flagged`, `test_sqs_named_lambda_dlq_not_flagged`, `test_parse_terraform_json_format` are passing.

### Filter what runs

| Goal | Command |
|---|---|
| Fast tests only (rule + dedup + scoring; no full pipeline) | `pytest -m "not slow"` — 188 tests, ~0.5s |
| Full-pipeline integration tests only | `pytest -m integration` — 18 tests |
| One file | `pytest tests/test_security_rules.py` |
| Tests with a keyword in their name | `pytest -k iam` |
| Multiple keyword patterns | `pytest -k "iam_xray or sqs_dlq"` |
| One specific test | `pytest tests/test_security_rules.py::TestTerraformSecurityRules::test_iam_xray_wildcard_not_flagged` |

### When something fails

| Goal | Command |
|---|---|
| Stop at first failure | `pytest -x` |
| Re-run only what failed last time | `pytest --lf` |
| Run failures first, then the rest | `pytest --ff` |
| Full traceback on failure | `pytest -v --tb=long` |
| Show `print()` output too | `pytest -v --tb=long -s` |

### Discover without running

| Goal | Command |
|---|---|
| List every test (no execution) | `pytest --collect-only` |
| Quieter list | `pytest --collect-only -q` |
| List markers | `pytest --markers` |

### Optional: coverage report

```bash
pip install pytest-cov
pytest --cov=app --cov-report=term-missing
```

Shows which lines of `app/` are executed by tests. `app/agents/*.py` rule logic shows high coverage; LLM-augmented `analyze_*()` functions show partial coverage because the LLM is mocked.

---

## Try breaking a fix on purpose (the satisfying experiment)

This is the best way to *feel* what the harness protects:

**1. Break a Phase 2 fix.** Open `app/agents/reliability.py`, find the SQS DLQ check (~line 322), and change:
```python
is_dlq = any(kw in queue_name for kw in ("dlq", "dead-letter", "deadletter", "dead_letter"))
```
to:
```python
is_dlq = False  # broken on purpose
```

**2. Run the SQS-related tests:**
```bash
pytest -k "sqs"
```

You'll see `test_sqs_named_lambda_dlq_not_flagged` and `test_sqs_named_dead_letter_not_flagged` fail with clear regression messages, plus `test_samples_rules_only.py::test_sample_must_not_have_findings[terraform-production-grade.json]` will fail because that sample's manifest forbids the finding.

**3. Restore the line and re-run:**
```bash
pytest -k "sqs"
```
Green again. You just experienced exactly what the harness protects against.

---

## Cheat sheet

```bash
pytest                                      # full suite (~1s)
pytest -v                                   # verbose, see test names
pytest -m "not slow"                        # fast subset only
pytest -k "iam"                             # filter by name
pytest tests/test_security_rules.py -v      # one file
pytest -x                                   # stop at first fail
pytest --lf                                 # re-run last failures
pytest --collect-only                       # list without running
```

---

## What's covered

| File | What it locks down |
|---|---|
| `test_dedup.py` | `extract_keywords`, `is_duplicate`, `_dedup_cross_cutting_gaps` (multi-domain rules) |
| `test_scoring.py` | `calculate_overall_score` (0.34/0.30/0.21/0.15 weighting), `_calculate_architecture_score` (gap deductions + agent-avg cap) |
| `test_security_rules.py` | K8s + Terraform security rules. **Phase 2 sentinels:** IAM `xray:*` exemption, EC2 ENI exemption, Action wildcard detection, S3 companion-resource awareness |
| `test_reliability_rules.py` | K8s + Terraform reliability rules. **Phase 2 sentinels:** SQS DLQ name skip, Lambda DLQ rule, DynamoDB PITR rule, HPA suppresses single-replica SPOF |
| `test_cost_rules.py` | K8s + Terraform cost rules. CloudWatch retention, S3 lifecycle (companion-aware), DynamoDB billing mode |
| `test_arch_filters.py` | `_filter_k8s_platform_gaps`, `_filter_terraform_speculative_gaps`, `_filter_terraform_secrets_gap` |
| `test_parsers.py` | K8s YAML/JSON, Terraform HCL/JSON, `resources_with_companion`. **Phase 2 sentinel:** Terraform JSON dict-format parsing |
| `test_mock_llm.py` | Sanity checks for the LLM mock fixture itself |
| `test_samples_rules_only.py` | Per-sample regression: deterministic per-agent + overall scores from rule-based path. Pinned in `expected_scores.yaml`. |
| `test_samples_full_pipeline.py` | Per-sample full pipeline (with mocked LLM), confirms agent + arch wiring + supervisor synthesis |

---

## Adding a new rule

When you add a new rule to `app/agents/{security,reliability,cost}.py`:

1. **Write at least one positive test** (asserts the rule fires) and **one negative test** (asserts the rule does NOT fire on a benign input). Place in the matching `test_*_rules.py` file.
2. **Run the rules-only sample tests** to see if any pinned scores need updating:
   ```bash
   pytest tests/test_samples_rules_only.py -v
   ```
3. If a sample's score legitimately shifts, update `tests/expected_scores.yaml`. The test failure message will tell you what number changed.
4. Re-run the full suite — it should be green.

---

## Updating `expected_scores.yaml`

When a rule change *should* shift sample scores:

1. Run `pytest tests/test_samples_rules_only.py -v`. Each failing assertion includes the new actual score.
2. Update the corresponding `overall_score` and `agent_scores` entries in the manifest.
3. Re-run; should be green.
4. Commit the rule change AND the manifest update in the same PR so reviewers can see both.

---

## How the LLM mock works

`tests/conftest.py::mock_llm` is a pytest fixture that:

1. Replaces `app.core.llm.get_llm` in every importer's namespace (`app.core.llm`, `app.agents.security`, `.reliability`, `.cost`, `.architecture_reviewer`, `.supervisor`).
2. The replacement returns a `_FakeRunnable` (subclass of `langchain_core.runnables.Runnable`) whose `ainvoke()` inspects the rendered system prompt and returns canned JSON keyed by agent type.
3. Default canned responses live in `tests/fixtures/llm_responses.py::EMPTY_RESPONSES` — every agent gets "no extra findings" so rule-based findings dominate.

**Override per-test:**
```python
def test_arch_dedup(mock_llm):
    from tests.fixtures.llm_responses import make_arch_response
    mock_llm.set("architecture", make_arch_response(gaps=[
        {"title": "Combined risk", "severity": "high", "description": "...",
         "recommendation": "..."},
    ]))
    # ... run pipeline, assert dedup behavior
```

**The gotcha:** Each agent module does `from app.core.llm import get_llm`, which binds the name at import time. Patching only `app.core.llm.get_llm` does NOT redirect lookups inside agent modules. The fixture patches all 6 namespaces. If you add a new agent that imports `get_llm`, add a `monkeypatch.setattr` line for it in `conftest.py`.

---

## Conventions

- **Test names:** `test_<thing>_<condition>_<expected>` — e.g., `test_iam_xray_wildcard_not_flagged`.
- **Fixture builders:** in `tests/fixtures/findings.py` (`make_finding`, `make_gap`, `make_report`, `minimal_deployment`, `tf_resource`).
- **Markers:** `@pytest.mark.slow` and `@pytest.mark.integration` for full-pipeline tests.
- **No real LLM in any test.** If you add a test that imports anything that hits Ollama, use the `mock_llm` fixture.
