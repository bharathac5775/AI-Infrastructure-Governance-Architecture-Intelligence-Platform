import streamlit as st
import httpx
import json
import time

API_URL = "http://localhost:8000/api/v1"

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
    This platform uses **3 AI agents** powered by local **Gemma4** (via Ollama) to analyze your infrastructure:

    - 🔒 **Security Agent** — vulnerabilities, RBAC, exposure
    - 🔄 **Reliability Agent** — probes, replicas, autoscaling
    - 💰 **Cost Agent** — overprovisioning, waste, optimization

    A **Supervisor Agent** synthesizes all findings into an actionable report.
    """)
    st.divider()
    st.markdown("**Supported files:** `.yaml`, `.yml`, `.tf`, `.json`, `.hcl`")

# File upload section
st.header("📁 Upload Infrastructure Files")

uploaded_files = st.file_uploader(
    "Upload Kubernetes YAML, Helm charts, or Terraform files",
    type=["yaml", "yml", "tf", "json", "hcl"],
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
    file_contents = {}

    # Collect uploaded files
    if uploaded_files:
        for f in uploaded_files:
            content = f.read().decode("utf-8")
            file_contents[f.name] = content

    # Collect pasted content
    if pasted_content.strip():
        file_contents[pasted_filename] = pasted_content

    if not file_contents:
        st.error("Please upload files or paste infrastructure content.")
    else:
        with st.spinner("🤖 Running multi-agent analysis with local Gemma4... This takes ~3 min. Please wait."):
            start_time = time.time()
            try:
                response = httpx.post(
                    f"{API_URL}/analyze/text",
                    json={"file_contents": file_contents},
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

    # Download report
    st.divider()
    report_json = json.dumps(report, indent=2)
    st.download_button(
        label="📥 Download Full Report (JSON)",
        data=report_json,
        file_name=f"governance-report-{report.get('report_id', 'unknown')}.json",
        mime="application/json",
    )
