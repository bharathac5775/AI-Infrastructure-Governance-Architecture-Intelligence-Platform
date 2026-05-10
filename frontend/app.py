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
    st.markdown("""
    This platform uses **4 AI agents** powered by local **Gemma4** (via Ollama) to analyze your infrastructure:

    - 🔒 **Security Agent** — vulnerabilities, RBAC, exposure
    - 🔄 **Reliability Agent** — probes, replicas, autoscaling
    - 💰 **Cost Agent** — overprovisioning, waste, optimization
    - 🏗️ **Architecture Reviewer** — tradeoffs, patterns, gaps

    A **Supervisor Agent** synthesizes all findings into an actionable report.
    """)
    st.divider()
    st.markdown("**Supported files:** `.yaml`, `.yml`, `.tf`, `.json`, `.hcl`, `.tgz` (Helm charts)")

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
                    timeout=600.0,
                )
                elapsed = time.time() - start_time

                if response.status_code == 200:
                    report = response.json()
                    st.success(f"Analysis complete in {elapsed:.1f}s")
                    st.session_state["report"] = report
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

    # Executive Summary
    st.subheader("📝 Executive Summary")
    st.markdown(report.get("executive_summary", "N/A"))

    # Risk Summary
    st.subheader("⚠️ Risk Summary")
    st.markdown(report.get("risk_summary", "N/A"))

    # Findings by agent
    st.subheader("🔍 Detailed Findings")

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
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))

            for finding in findings:
                sev = finding.get("severity", "info")
                color = severity_colors.get(sev, "⚪")
                st.markdown(f"**{color} [{sev.upper()}] {finding['title']}**")
                st.markdown(f"  📦 Resource: `{finding.get('resource', 'N/A')}`")
                st.markdown(f"  {finding['description']}")
                st.markdown(f"  ✅ **Recommendation:** {finding.get('recommendation', 'N/A')}")
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
    st.download_button(
        label="📥 Download Full Report (JSON)",
        data=report_json,
        file_name=f"governance-report-{report.get('report_id', 'unknown')}.json",
        mime="application/json",
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
