import os
import streamlit as st
import httpx
import json
import time

API_URL = os.getenv("API_URL", "http://localhost:8000/api/v1")

st.set_page_config(
    page_title="AI Infrastructure Governance Platform",
    page_icon="🏗️",
    layout="wide",
)

st.title("🏗️ AI Infrastructure Governance Platform")
st.markdown("**Multi-agent AI analysis for Kubernetes & Terraform infrastructure**")
st.divider()

# Sidebar
with st.sidebar:
    st.header("About")
    st.markdown(
        "**AI Infrastructure Governance & Architecture Intelligence Platform** — "
        "a multi-agent system that analyzes your Kubernetes, Helm, and Terraform "
        "code for security, reliability, cost, and architectural issues, then "
        "generates code patches that fix them."
    )
    st.markdown(
        "Defaults to local **Gemma4** via **Ollama** — no cloud APIs, no "
        "telemetry, no data leaves your laptop. Switch to **Claude / GPT / "
        "Gemini** by editing one line in `.env` (`LLM_PROVIDER=anthropic` / "
        "`openai` / `google`) and adding the corresponding API key. The "
        "agents themselves are provider-agnostic."
    )

    st.divider()
    st.subheader("Phase 1 — Analysis")
    st.markdown(
        "Four specialist agents inspect your files in parallel. Each runs a "
        "deterministic rule engine first (~30 hand-coded checks) and then "
        "extends that with LLM reasoning for issues the rules miss."
    )
    st.markdown(
        "- 🔒 **Security Agent** — privileged containers, RBAC, public exposure, "
        "hardcoded secrets, encryption, IMDSv2, IAM scopes\n"
        "- 🔄 **Reliability Agent** — probes, replicas, PDB/HPA, anti-affinity, "
        "Multi-AZ, backup, DLQ, deletion protection\n"
        "- 💰 **Cost Agent** — overprovisioning, missing lifecycle rules, "
        "instance-class fit, expensive defaults, idle resources\n"
        "- 🏗️ **Architecture Reviewer** — cross-domain tradeoffs, anti-patterns, "
        "and cross-cutting gaps the per-domain agents miss"
    )
    st.markdown(
        "A **Supervisor Agent** synthesizes all findings into a single "
        "report with prioritized actions, executive summary, and risk profile."
    )

    st.divider()
    st.subheader("Phase 2 — Compliance")
    st.markdown(
        "Every finding is automatically tagged with the compliance controls "
        "it implicates, and the report shows per-framework pass/fail scores:"
    )
    st.markdown(
        "- **CIS Kubernetes Benchmark** v1.10\n"
        "- **CIS AWS Foundations** v3.0\n"
        "- **CIS Azure Foundations** v3.0\n"
        "- **CIS GCP Foundations** v3.0\n"
        "- **NIST 800-53** Rev 5"
    )
    st.markdown(
        "Frameworks are scoped by detected cloud — an Azure-only upload "
        "won't see CIS AWS controls, and vice versa."
    )

    st.divider()
    st.subheader("Phase 3 — Remediation")
    st.markdown(
        "Click 🛠️ **Generate fix** on any finding to produce a code patch:"
    )
    st.markdown(
        "- ⚡ **Deterministic fixers** for known rule categories — "
        "near-instant, predictable, surgical edits "
        "(privileged containers, secrets, encryption, IMDSv2, "
        "S3 public access, KMS rotation, ingress/egress CIDRs, …)\n"
        "- 🤖 **LLM fallback** for everything else — slower but flexible "
        "(probes, custom advisories, cost ratios)\n"
        "- 📝 **Companion-resource templates** for HPA, PodDisruptionBudget, "
        "and NetworkPolicy — emitted as ready-to-apply YAML files"
    )
    st.markdown(
        "Every patch is **validated by re-parse** before it's returned — "
        "the platform never produces broken IaC."
    )

    st.divider()
    st.subheader("Other features")
    st.markdown(
        "- 📊 **Drift detection** — re-uploading the same files compares "
        "against your last scan and shows what's new, resolved, or persisting\n"
        "- 📄 **PDF export** — auditor-ready report with scores, findings, "
        "and per-framework compliance breakdown\n"
        "- 🔍 **Similar past scans** — vector-search across your history "
        "to find related risk profiles\n"
        "- 📜 **Report history** — every scan persists locally; reload "
        "any past report by ID"
    )

    st.divider()
    st.subheader("Privacy & safety")
    st.markdown(
        "- All analysis runs **locally by default** (Ollama). No outbound "
        "API calls until you explicitly opt into a cloud provider via `.env`.\n"
        "- File contents are **echoed once** in the analyze response so "
        "the frontend can cache them; never persisted server-side.\n"
        "- Patches are **downloads only** — the platform never modifies "
        "your working tree.\n"
        "- Every patch round-trips through the parser to guarantee "
        "valid output."
    )

    st.divider()
    st.markdown(
        "**Supported files:** `.yaml`, `.yml`, `.tf`, `.json`, `.hcl`, "
        "`.tgz` (Helm charts)"
    )
    st.caption(
        "Helm charts are rendered server-side; the rendered manifest "
        "is what gets analyzed and patched."
    )

# File upload section
st.header("📁 Upload Infrastructure Files")

uploaded_files = st.file_uploader(
    "Upload Kubernetes YAML, Helm charts (.tgz), or Terraform files",
    type=["yaml", "yml", "tf", "json", "hcl", "tgz"],
    accept_multiple_files=True,
)

# Text input alternative
with st.expander("Or paste YAML/Terraform content directly"):
    pasted_content = st.text_area(
        "Paste your infrastructure configuration:",
        height=300,
        placeholder="apiVersion: apps/v1\nkind: Deployment\n...",
    )
    pasted_filename = st.text_input("Filename (for identification)", value="pasted-config.yaml")

# Analyze button
if st.button("🔍 Analyze Infrastructure", type="primary", use_container_width=True):
    files_multipart = []

    # Collect uploaded files (send as raw bytes — handles both text and .tgz)
    if uploaded_files:
        for f in uploaded_files:
            raw = f.read()
            mime = "application/gzip" if f.name.endswith(".tgz") else "text/plain"
            files_multipart.append(("files", (f.name, raw, mime)))

    # Collect pasted content
    if pasted_content.strip():
        files_multipart.append(("files", (pasted_filename, pasted_content.encode("utf-8"), "text/plain")))

    if not files_multipart:
        st.error("Please upload files or paste infrastructure content.")
    else:
        with st.spinner("🤖 Running multi-agent analysis with local Gemma4... This takes ~3 min. Please wait."):
            start_time = time.time()
            try:
                response = httpx.post(
                    f"{API_URL}/analyze",
                    files=files_multipart,
                    timeout=1200.0,
                )
                elapsed = time.time() - start_time

                if response.status_code == 200:
                    report = response.json()
                    st.success(f"Analysis complete in {elapsed:.1f}s")
                    st.session_state["report"] = report
                    # Phase 3.4 — cache the file_contents the API echoes back.
                    # This is authoritative for ALL upload types — including
                    # .tgz Helm charts where the rendered YAML is created
                    # server-side and the frontend never sees it otherwise.
                    api_returned_files = report.get("file_contents") or {}
                    if api_returned_files:
                        st.session_state["cached_file_contents"] = dict(api_returned_files)
                    else:
                        # Older backend without the echo — fall back to
                        # client-side re-read for non-.tgz files only.
                        cached: dict[str, str] = {}
                        if uploaded_files:
                            for f in uploaded_files:
                                try:
                                    f.seek(0)
                                    if not f.name.endswith(".tgz"):
                                        cached[f.name] = f.read().decode("utf-8", errors="replace")
                                except Exception:
                                    pass
                        if pasted_content.strip():
                            cached[pasted_filename] = pasted_content
                        st.session_state["cached_file_contents"] = cached
                else:
                    st.error(f"Analysis failed: {response.text}")
            except httpx.ConnectError:
                st.error("Cannot connect to API. Make sure the FastAPI backend is running: `uvicorn app.main:app --reload --port 8000`")
            except Exception as e:
                st.error(f"Error: {e}")

# Display report
if "report" in st.session_state:
    report = st.session_state["report"]

    st.divider()
    st.header("📊 Governance Report")

    # Score overview
    col1, col2, col3, col4 = st.columns(4)

    overall_score = report.get("overall_score", 0)
    score_color = "🟢" if overall_score >= 70 else "🟡" if overall_score >= 40 else "🔴"

    with col1:
        st.metric("Overall Score", f"{score_color} {overall_score}/100")

    # Agent scores
    agent_reports = report.get("agent_reports", [])
    for i, agent_report in enumerate(agent_reports):
        col = [col2, col3, col4][i] if i < 3 else col4
        with col:
            name = agent_report["agent_name"].replace(" Agent", "")
            score = agent_report["score"]
            icon = "🔒" if "Security" in name else "🔄" if "Reliability" in name else "💰"
            st.metric(f"{icon} {name}", f"{score}/100")

    st.divider()

    # Phase 3.3 — Compliance Posture panel. Hidden when no compliance data.
    compliance = report.get("compliance")
    if compliance and compliance.get("frameworks"):
        st.subheader("📋 Compliance Posture")
        fw_list = compliance["frameworks"]
        cols = st.columns(len(fw_list))
        for col, fw in zip(cols, fw_list):
            with col:
                score = fw.get("score_pct", 0)
                icon = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
                passed = len(fw.get("controls_passed", []))
                failed = len(fw.get("controls_failed", []))
                st.metric(
                    f"{icon} {fw.get('framework_name', fw.get('framework_id', '?'))}",
                    f"{score}%",
                    help=f"{passed} passed, {failed} failed",
                )
        with st.expander("Compliance details"):
            for fw in fw_list:
                st.markdown(
                    f"**{fw.get('framework_name', '?')}** "
                    f"(v{fw.get('version', '?')})"
                )
                passed_ids = fw.get("controls_passed", [])
                failed_ids = fw.get("controls_failed", [])
                if passed_ids:
                    st.markdown(
                        f"  ✅ Passed ({len(passed_ids)}): "
                        + ", ".join(f"`{c}`" for c in passed_ids)
                    )
                if failed_ids:
                    st.markdown(
                        f"  ❌ Failed ({len(failed_ids)}): "
                        + ", ".join(f"`{c}`" for c in failed_ids)
                    )
                st.markdown("---")
        st.divider()

    # Phase 3.2 — Drift detection panel. Hidden silently when no prior scan exists.
    report_id = report.get("report_id", "")
    if report_id:
        try:
            drift_resp = httpx.get(
                f"{API_URL}/reports/{report_id}/drift", timeout=10.0
            )
            if drift_resp.status_code == 200:
                drift_data = drift_resp.json()
                if drift_data.get("baseline") and drift_data.get("drift"):
                    d = drift_data["drift"]
                    base_ts = d["baseline"]["timestamp"][:19].replace("T", " ")
                    deltas = d["score_deltas"]

                    def _fmt_delta(v):
                        if v is None:
                            return None
                        return f"{v:+.1f}"

                    intro = d["findings_introduced"]
                    resolved = d["findings_resolved"]
                    persist = d["findings_persisting"]

                    panel_label = (
                        f"📊 Compare with previous scan ({base_ts}) — "
                        f"{len(intro)} new, {len(resolved)} resolved, "
                        f"{len(persist)} persisting"
                    )
                    with st.expander(panel_label, expanded=True):
                        st.caption(
                            "Drift compares deterministic (rule-based) findings only. "
                            "AI-augmented findings vary across runs and are excluded "
                            "from this diff to avoid false positives."
                        )
                        c1, c2, c3, c4 = st.columns(4)
                        with c1:
                            st.metric(
                                "Overall",
                                report.get("overall_score", 0),
                                _fmt_delta(deltas.get("overall")),
                            )

                        # Per-agent score panels driven by current report scores
                        agent_score_lookup = {
                            ar["agent_name"]: ar["score"]
                            for ar in report.get("agent_reports", [])
                        }
                        sec_score = agent_score_lookup.get("Security Agent", 0)
                        rel_score = agent_score_lookup.get("Reliability Agent", 0)
                        cost_score = agent_score_lookup.get("Cost Agent", 0)
                        with c2:
                            st.metric(
                                "🔒 Security",
                                sec_score,
                                _fmt_delta(deltas.get("security")),
                            )
                        with c3:
                            st.metric(
                                "🔄 Reliability",
                                rel_score,
                                _fmt_delta(deltas.get("reliability")),
                            )
                        with c4:
                            st.metric(
                                "💰 Cost",
                                cost_score,
                                _fmt_delta(deltas.get("cost")),
                            )

                        sev_colors = {
                            "critical": "🔴",
                            "high": "🟠",
                            "medium": "🟡",
                            "low": "🔵",
                            "info": "⚪",
                        }

                        def _render_findings(items):
                            if not items:
                                st.markdown("_None._")
                                return
                            for f in items:
                                sev = f.get("severity", "info")
                                color = sev_colors.get(sev, "⚪")
                                title = f.get("title", "(no title)")
                                resource = f.get("resource", "")
                                st.markdown(
                                    f"{color} **[{sev.upper()}] {title}** — `{resource}`"
                                )

                        with st.expander(f"➕ Findings introduced ({len(intro)})"):
                            _render_findings(intro)
                        with st.expander(f"✅ Findings resolved ({len(resolved)})"):
                            _render_findings(resolved)
                        with st.expander(
                            f"➖ Findings persisting ({len(persist)})"
                        ):
                            _render_findings(persist)
        except Exception:
            # Silent fail — drift is a value-add, never block the main report.
            pass

    # Executive Summary
    st.subheader("📝 Executive Summary")
    st.markdown(report.get("executive_summary", "N/A"))

    # Risk Summary
    st.subheader("⚠️ Risk Summary")
    st.markdown(report.get("risk_summary", "N/A"))

    # Findings by agent
    st.subheader("🔍 Detailed Findings")

    # Phase 3.4 — re-upload widget for missing cache. Triggers when the
    # user is viewing a report loaded from history (no cache) or the
    # backend didn't echo file_contents (old server). Lets remediation
    # work on any past report without losing the cache-based design.
    files_analyzed = report.get("files_analyzed", []) or []
    cache_now = st.session_state.get("cached_file_contents", {}) or {}
    missing_files = [f for f in files_analyzed if f not in cache_now]
    if missing_files:
        with st.expander(
            f"📤 Re-upload original files for remediation ({len(missing_files)} missing)",
            expanded=False,
        ):
            st.caption(
                "Reports loaded from history don't include the original file "
                "contents (we don't persist them server-side by design). "
                "Re-upload here so the Generate fix buttons can work."
            )
            st.markdown("**Files this report needs:**")
            for fname in missing_files:
                st.markdown(f"  • `{fname}`")
            reupload = st.file_uploader(
                "Re-upload original file(s) to enable remediation",
                type=["yaml", "yml", "tf", "json", "hcl", "tgz"],
                accept_multiple_files=True,
                key=f"reupload_{report.get('report_id', '')}",
            )
            if reupload:
                _need_helm = any(f.endswith(".tgz") for f in missing_files)
                _has_helm_upload = any(f.name.endswith(".tgz") for f in reupload)
                if _need_helm and not _has_helm_upload:
                    # The report was generated from a Helm chart. The user
                    # must re-upload the same .tgz so we can ask the API to
                    # re-render and stash the rendered YAML in the cache.
                    st.warning(
                        "This report was generated from a Helm chart (.tgz). "
                        "Re-upload the same .tgz so we can re-render and cache "
                        "the YAML."
                    )
                if st.button("📥 Cache uploaded contents", key=f"reup_btn_{report.get('report_id', '')}"):
                    new_cache = dict(cache_now)
                    files_for_render: list = []
                    for f in reupload:
                        try:
                            f.seek(0)
                            raw = f.read()
                        except Exception as e:
                            st.error(f"Could not read {f.name}: {e}")
                            continue
                        if f.name.endswith(".tgz"):
                            # Send to /analyze/text won't work for tgz — we
                            # need server-side render. Use /analyze with just
                            # this file to get back the rendered YAML in
                            # file_contents.
                            files_for_render.append(("files", (f.name, raw, "application/gzip")))
                        else:
                            try:
                                new_cache[f.name] = raw.decode("utf-8", errors="replace")
                            except Exception as e:
                                st.error(f"Could not decode {f.name}: {e}")
                    if files_for_render:
                        # Re-run /analyze just to extract the rendered YAML
                        # (we discard the duplicate report). This is the
                        # only way to get post-render text without persisting
                        # contents server-side.
                        try:
                            with st.spinner("Re-rendering Helm chart..."):
                                rerun = httpx.post(
                                    f"{API_URL}/analyze",
                                    files=files_for_render,
                                    timeout=1200.0,
                                )
                            if rerun.status_code == 200:
                                rerun_files = rerun.json().get("file_contents", {}) or {}
                                new_cache.update(rerun_files)
                            else:
                                st.error(f"Re-render failed: {rerun.text}")
                        except Exception as e:
                            st.error(f"Re-render error: {e}")
                    st.session_state["cached_file_contents"] = new_cache
                    still_missing = [f for f in files_analyzed if f not in new_cache]
                    if still_missing:
                        st.warning(
                            f"Cached {len(new_cache) - len(cache_now)} file(s). "
                            f"Still missing: {', '.join(still_missing)}"
                        )
                    else:
                        st.success("All files cached. Generate fix buttons are now active.")
                        st.rerun()

    severity_colors = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    for agent_report in agent_reports:
        agent_name = agent_report["agent_name"]
        icon = "🔒" if "Security" in agent_name else "🔄" if "Reliability" in agent_name else "💰"

        with st.expander(f"{icon} {agent_name} — {len(agent_report['findings'])} findings (Score: {agent_report['score']}/100)"):
            st.markdown(f"**Summary:** {agent_report['summary']}")
            st.markdown("---")

            findings = agent_report.get("findings", [])
            # Phase 3.4 — compute the GLOBAL flat index for each finding so the
            # remediation endpoint receives the same index the backend computes.
            # We must NOT sort findings here (sorting changes the displayed
            # index but the backend uses the un-sorted order).
            agent_idx = next(
                (i for i, ar in enumerate(agent_reports) if ar["agent_name"] == agent_name),
                0,
            )
            findings_with_index = []
            base = sum(len(ar.get("findings", [])) for ar in agent_reports[:agent_idx])
            for local_i, finding in enumerate(findings):
                findings_with_index.append((base + local_i, finding))

            # Sort presentation by severity but keep the global index attached.
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings_with_index.sort(
                key=lambda pair: severity_order.get(pair[1].get("severity", "info"), 5)
            )

            for global_i, finding in findings_with_index:
                sev = finding.get("severity", "info")
                color = severity_colors.get(sev, "⚪")
                st.markdown(f"**{color} [{sev.upper()}] {finding['title']}**")
                st.markdown(f"  📦 Resource: `{finding.get('resource', 'N/A')}`")
                st.markdown(f"  {finding['description']}")
                st.markdown(f"  ✅ **Recommendation:** {finding.get('recommendation', 'N/A')}")
                # Phase 3.3 — show compliance controls when present
                ctrls = finding.get("compliance_controls", [])
                if ctrls:
                    st.markdown(
                        f"  📋 **Controls:** "
                        + ", ".join(f"`{c}`" for c in ctrls)
                    )

                # Phase 3.4 — Generate fix button (hidden for advisory findings)
                rid = report.get("report_id", "")
                cached_files = st.session_state.get("cached_file_contents", {})
                resource_str = str(finding.get("resource", "")).strip()
                resource_lower = resource_str.lower()
                _NON_PATCHABLE = {
                    "", "n/a", "na", "none", "null", "-",
                    "infrastructure", "all", "global", "various", "multiple",
                }
                _looks_like_path = (
                    resource_lower.endswith((".yaml", ".yml", ".json", ".tf", ".hcl", ".tgz"))
                    or "/templates/" in resource_lower
                )
                # LLM "deployment.yaml (chart-name)" annotated form
                if not _looks_like_path and " (" in resource_lower and resource_lower.endswith(")"):
                    _prefix = resource_lower.split(" (", 1)[0].strip()
                    if _prefix.endswith((".yaml", ".yml", ".json", ".tf", ".hcl", ".tgz")):
                        _looks_like_path = True
                    elif "/templates/" in _prefix:
                        _looks_like_path = True
                # Advisory-language detection: LLM-emitted findings whose
                # recommendation begins with a decision verb ("Analyze...",
                # "Consider...", "Monitor...") or a no-action phrase
                # ("No immediate action required", "Maintain this setting")
                # aren't fixable by a code patch.
                _ADVISORY_VERBS = (
                    "analyze", "monitor", "consider", "evaluate", "review",
                    "determine", "investigate", "audit", "assess",
                    "maintain", "continue", "keep",
                )
                _NO_ACTION_PHRASES = (
                    "no immediate action", "no action", "no change", "no changes",
                    "no fix", "this is already", "this is a recommended",
                    "this is best practice", "this is correct",
                    "this is the recommended",
                    "already configured", "already enabled", "already in place",
                    "already meets", "already follows",
                    "the current configuration is correct",
                    "the configuration is already",
                )
                _rec = str(finding.get("recommendation", "")).strip()
                _rec_lower = _rec.lower()
                _first_word = (
                    _rec.split(maxsplit=1)[0].strip(".,:;").lower() if _rec else ""
                )
                _is_advisory_lang = (
                    finding.get("category") == "ai-analysis"
                    and (
                        _first_word in _ADVISORY_VERBS
                        or any(_rec_lower.startswith(p) for p in _NO_ACTION_PHRASES)
                    )
                )
                is_advisory = (
                    resource_lower in _NON_PATCHABLE
                    or _looks_like_path
                    or _is_advisory_lang
                )

                if is_advisory:
                    if _looks_like_path:
                        st.caption(
                            f"ℹ️ Resource `{resource_str}` looks like a file or "
                            "template path, not a runtime resource — no automatic "
                            "patch available."
                        )
                    elif _is_advisory_lang:
                        # Distinguish praise findings from decision-task findings
                        if any(_rec_lower.startswith(p) for p in _NO_ACTION_PHRASES):
                            st.caption(
                                "ℹ️ No action needed — this finding praises an "
                                "already-correct configuration. Nothing to patch."
                            )
                        else:
                            _verb = _rec.split(maxsplit=1)[0] if _rec else "Advisory"
                            st.caption(
                                f"ℹ️ Advisory finding — its recommendation starts with "
                                f"\"{_verb}…\", meaning it asks you to evaluate or "
                                "make a decision rather than apply a specific code "
                                "change. Not auto-remediable."
                            )
                    else:
                        st.caption(
                            "ℹ️ Advisory finding — describes a whole-infrastructure "
                            "or purchasing decision; no automatic patch available."
                        )
                else:
                    fix_key = f"fix_{rid}_{global_i}"
                    btn_col, _ = st.columns([0.3, 0.7])
                    with btn_col:
                        if st.button("🛠️ Generate fix", key=f"btn_{fix_key}"):
                            if not cached_files:
                                st.warning(
                                    "No cached file contents — re-run the analysis first so "
                                    "remediation can access the original files."
                                )
                            else:
                                try:
                                    fix_resp = httpx.post(
                                        f"{API_URL}/reports/{rid}/remediate/{global_i}",
                                        json={"file_contents": cached_files},
                                        timeout=600.0,
                                    )
                                    if fix_resp.status_code == 200:
                                        st.session_state[fix_key] = fix_resp.json()
                                    else:
                                        # Try to surface the API's structured detail
                                        try:
                                            err = fix_resp.json().get("detail", fix_resp.text)
                                        except Exception:
                                            err = fix_resp.text
                                        st.session_state[fix_key] = {
                                            "_error": err,
                                            "_status": fix_resp.status_code,
                                        }
                                except Exception as e:
                                    st.session_state[fix_key] = {"_error": str(e)}

                    if fix_key in st.session_state:
                        patch = st.session_state[fix_key]
                        if patch.get("_error"):
                            err_payload = patch["_error"]
                            # Companion-resource case: structured 409 with
                            # template + filename. Render the template inline.
                            if (
                                patch.get("_status") == 409
                                and isinstance(err_payload, dict)
                                and err_payload.get("kind") == "companion_resource_required"
                            ):
                                st.info(f"ℹ️ {err_payload.get('message', '')}")
                                template = err_payload.get("template", "")
                                tmpl_filename = err_payload.get("filename", "companion.yaml")
                                if template:
                                    st.markdown(
                                        f"**Copy this into a new file `{tmpl_filename}` "
                                        "and apply alongside your existing manifest:**"
                                    )
                                    st.code(template, language="yaml")
                                    st.download_button(
                                        label=f"📥 Download {tmpl_filename}",
                                        data=template,
                                        file_name=tmpl_filename,
                                        mime="text/yaml",
                                        key=f"companion_dl_{fix_key}",
                                    )
                            elif patch.get("_status") == 409:
                                # Plain non-patchable advisory — string detail
                                st.info(f"ℹ️ {err_payload}")
                            else:
                                st.error(f"Could not generate fix: {err_payload}")
                        else:
                            strategy_badge = "🤖 LLM" if patch.get("strategy") == "llm" else "⚡ Deterministic"
                            st.markdown(
                                f"**{strategy_badge}** patch for `{patch.get('filename', '?')}` — "
                                f"{patch.get('explanation', '')}"
                            )
                            for w in patch.get("warnings", []):
                                st.warning(w)
                            diff_text = patch.get("unified_diff", "")
                            if diff_text:
                                st.code(diff_text, language="diff")
                            else:
                                st.info("Patch produced no diff (possibly a no-op).")
                            st.download_button(
                                label=f"📋 Download patched {patch.get('filename', 'file')}",
                                data=patch.get("patched_content", ""),
                                file_name=f"patched-{patch.get('filename', 'file')}",
                                mime="text/plain",
                                key=f"dl_{fix_key}",
                            )

                st.markdown("---")

    # Recommendations
    st.subheader("🎯 Top Recommendations")
    recommendations = report.get("recommendations", [])
    for i, rec in enumerate(recommendations, 1):
        st.markdown(f"**{i}.** {rec}")

    # Architecture Review
    arch_review = report.get("architecture_review")
    if arch_review:
        st.divider()
        st.subheader("🏗️ Architecture Review")
        st.markdown(f"**Architecture Score:** {arch_review.get('architecture_score', 0)}/100")
        st.markdown(arch_review.get("summary", ""))

        tradeoffs = arch_review.get("tradeoffs", [])
        if tradeoffs:
            with st.expander(f"⚖️ Tradeoff Conflicts ({len(tradeoffs)})"):
                for t in tradeoffs:
                    agents = ", ".join(t.get("agents_involved", []))
                    st.markdown(f"**{t['title']}** ({agents})")
                    st.markdown(f"  {t['description']}")
                    st.markdown(f"  ✅ **Recommendation:** {t.get('recommendation', 'N/A')}")
                    st.markdown("---")

        patterns = arch_review.get("patterns_detected", [])
        if patterns:
            with st.expander(f"🧩 Architectural Patterns ({len(patterns)})"):
                for p in patterns:
                    badge = "✅" if p["assessment"] == "good" else "⚠️" if p["assessment"] == "partial" else "❌"
                    st.markdown(f"{badge} **{p['pattern']}** — {p['assessment']}")
                    st.markdown(f"  {p.get('details', '')}")
                    st.markdown("---")

        gaps = arch_review.get("cross_cutting_gaps", [])
        if gaps:
            with st.expander(f"🕳️ Cross-Cutting Gaps ({len(gaps)})"):
                for g in gaps:
                    color = severity_colors.get(g.get("severity", "medium"), "🟡")
                    st.markdown(f"**{color} [{g.get('severity', 'medium').upper()}] {g['title']}**")
                    st.markdown(f"  {g['description']}")
                    st.markdown(f"  ✅ **Recommendation:** {g.get('recommendation', 'N/A')}")
                    st.markdown("---")

        actions = arch_review.get("prioritized_actions", [])
        if actions:
            with st.expander("📋 Prioritized Actions"):
                for i, action in enumerate(actions, 1):
                    st.markdown(f"**{i}.** {action}")

    # Download report
    st.divider()
    report_json = json.dumps(report, indent=2)
    dl_col_a, dl_col_b = st.columns(2)
    with dl_col_a:
        st.download_button(
            label="📥 Download Full Report (JSON)",
            data=report_json,
            file_name=f"governance-report-{report.get('report_id', 'unknown')}.json",
            mime="application/json",
        )
    with dl_col_b:
        # Phase 3.3 — PDF export. We pre-fetch on click so Streamlit can serve
        # the bytes via st.download_button. Falls back gracefully if the API
        # is unreachable.
        rid = report.get("report_id", "")
        if rid:
            if st.button("📄 Download PDF Report", use_container_width=True):
                try:
                    pdf_resp = httpx.get(
                        f"{API_URL}/reports/{rid}/export/pdf", timeout=30.0
                    )
                    if pdf_resp.status_code == 200:
                        st.session_state[f"pdf_{rid}"] = pdf_resp.content
                    else:
                        st.error(f"PDF export failed: {pdf_resp.status_code}")
                except Exception as e:
                    st.error(f"PDF export error: {e}")
            if f"pdf_{rid}" in st.session_state:
                st.download_button(
                    label="⬇️ Save PDF",
                    data=st.session_state[f"pdf_{rid}"],
                    file_name=f"governance-report-{rid}.pdf",
                    mime="application/pdf",
                    key=f"pdf_dl_{rid}",
                )

    # Similar past reports
    report_id = report.get("report_id", "")
    if report_id:
        try:
            similar_resp = httpx.get(f"{API_URL}/reports/{report_id}/similar", timeout=10.0)
            if similar_resp.status_code == 200:
                similar = similar_resp.json()
                if similar:
                    st.divider()
                    st.subheader("🔍 Similar Past Scans")
                    for s in similar:
                        sim_score = s.get("similarity", 0)
                        overall = s.get("overall_score", 0)
                        icon = "🟢" if overall >= 70 else "🟡" if overall >= 40 else "🔴"
                        files = s.get("files_analyzed", "")
                        ts = s.get("timestamp", "")[:19].replace("T", " ")
                        st.markdown(
                            f"{icon} **{overall}/100** — `{files}` — {ts} — similarity: {sim_score}"
                        )
        except Exception:
            pass

# Report History
st.divider()
st.header("📜 Report History")

try:
    history_resp = httpx.get(f"{API_URL}/reports", timeout=10.0)
    if history_resp.status_code == 200:
        history = history_resp.json()
        if history:
            for entry in history:
                score = entry.get("overall_score", 0)
                icon = "🟢" if score >= 70 else "🟡" if score >= 40 else "🔴"
                files = entry.get("files_analyzed", "")
                ts = entry.get("timestamp", "")[:19].replace("T", " ")
                rid = entry.get("report_id", "")
                col1, col2, col3, col4 = st.columns([0.74, 0.1, 0.08, 0.08])
                with col1:
                    st.markdown(
                        f"{icon} **{score}/100** — `{files}` — {ts} — `{rid}`"
                    )
                with col2:
                    if st.button("📄 View", key=f"view_{rid}", help="View full report"):
                        try:
                            view_resp = httpx.get(f"{API_URL}/reports/{rid}", timeout=10.0)
                            if view_resp.status_code == 200:
                                st.session_state["report"] = view_resp.json()
                                st.rerun()
                            else:
                                st.error("Failed to load report.")
                        except Exception:
                            st.error("Could not connect to API.")
                with col3:
                    if st.button("📥", key=f"json_{rid}", help="Download JSON"):
                        try:
                            json_resp = httpx.get(f"{API_URL}/reports/{rid}", timeout=10.0)
                            if json_resp.status_code == 200:
                                st.session_state[f"download_{rid}"] = json_resp.json()
                        except Exception:
                            st.error("Could not connect to API.")
                    if f"download_{rid}" in st.session_state:
                        st.download_button(
                            "⬇️",
                            data=json.dumps(st.session_state[f"download_{rid}"], indent=2),
                            file_name=f"governance-report-{rid}.json",
                            mime="application/json",
                            key=f"dl_{rid}",
                        )
                with col4:
                    if st.button("🗑️", key=f"del_{rid}", help="Delete this report"):
                        try:
                            del_resp = httpx.delete(f"{API_URL}/reports/{rid}", timeout=10.0)
                            if del_resp.status_code == 200:
                                st.toast(f"Deleted report {rid[:8]}…")
                                st.rerun()
                            else:
                                st.error("Failed to delete report.")
                        except Exception:
                            st.error("Could not connect to API.")
        else:
            st.info("No reports yet. Run an analysis to get started.")
    else:
        st.warning("Could not load report history.")
except httpx.ConnectError:
    st.info("Connect to the API to view report history.")
except Exception:
    st.info("Report history unavailable.")
