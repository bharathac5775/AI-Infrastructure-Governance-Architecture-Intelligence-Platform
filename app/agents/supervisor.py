import asyncio
import json
import logging
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langchain_core.prompts import ChatPromptTemplate
from app.core.llm import get_llm
from app.core.report import calculate_overall_score
from app.models import AnalysisReport, AgentReport
from app.agents.security import analyze_security
from app.agents.reliability import analyze_reliability
from app.agents.cost import analyze_cost
from app.parsers.kubernetes import parse_kubernetes_yaml, extract_k8s_resources
from app.parsers.terraform import parse_terraform, extract_tf_resources

logger = logging.getLogger(__name__)


class AnalysisState(TypedDict):
    file_contents: dict[str, str]
    k8s_resources: dict
    tf_resources: list
    security_report: AgentReport | None
    reliability_report: AgentReport | None
    cost_report: AgentReport | None
    final_report: AnalysisReport | None


SUPERVISOR_PROMPT = """You are an Architecture Review Supervisor.
Synthesize these agent reports into a brief executive summary.

Security: {security_summary} (Score: {security_score}/100, {security_findings_count} findings)
Reliability: {reliability_summary} (Score: {reliability_score}/100, {reliability_findings_count} findings)
Cost: {cost_summary} (Score: {cost_score}/100, {cost_findings_count} findings)

Respond ONLY with valid JSON:
{{"executive_summary": "2-3 paragraph overview", "risk_summary": "key risks", "recommendations": ["rec1", "rec2", "rec3", "rec4", "rec5"]}}"""


def parse_files_node(state: AnalysisState) -> dict:
    """Parse uploaded files and extract K8s + Terraform resources."""
    all_k8s_resources: dict = {}
    all_tf_resources: list = []
    for fname, content in state["file_contents"].items():
        if fname.endswith((".yaml", ".yml")):
            try:
                docs = parse_kubernetes_yaml(content)
                resources = extract_k8s_resources(docs)
                for kind, items in resources.items():
                    all_k8s_resources.setdefault(kind, []).extend(items)
            except (ValueError, Exception):
                pass
        elif fname.endswith((".tf", ".hcl")):
            try:
                parsed = parse_terraform(content)
                tf_res = extract_tf_resources(parsed)
                all_tf_resources.extend(tf_res)
            except (ValueError, Exception):
                pass
        elif fname.endswith(".json"):
            # Try Kubernetes JSON first, then Terraform JSON
            try:
                import json as _json
                data = _json.loads(content)
                if isinstance(data, dict) and data.get("apiVersion"):
                    docs = [data]
                    resources = extract_k8s_resources(docs)
                    for kind, items in resources.items():
                        all_k8s_resources.setdefault(kind, []).extend(items)
                elif isinstance(data, dict) and (data.get("resource") or data.get("terraform")):
                    tf_res = extract_tf_resources(data)
                    all_tf_resources.extend(tf_res)
            except Exception:
                pass
    return {"k8s_resources": all_k8s_resources, "tf_resources": all_tf_resources}


async def security_node(state: AnalysisState) -> dict:
    """Run security analysis."""
    logger.info("Starting Security Agent...")
    report = await analyze_security(state["file_contents"], state["k8s_resources"], state.get("tf_resources", []))
    logger.info(f"Security Agent done: {report.score}/100, {len(report.findings)} findings")
    return {"security_report": report}


async def reliability_node(state: AnalysisState) -> dict:
    """Run reliability analysis."""
    logger.info("Starting Reliability Agent...")
    report = await analyze_reliability(state["file_contents"], state["k8s_resources"], state.get("tf_resources", []))
    logger.info(f"Reliability Agent done: {report.score}/100, {len(report.findings)} findings")
    return {"reliability_report": report}


async def cost_node(state: AnalysisState) -> dict:
    """Run cost analysis."""
    logger.info("Starting Cost Agent...")
    report = await analyze_cost(state["file_contents"], state["k8s_resources"], state.get("tf_resources", []))
    logger.info(f"Cost Agent done: {report.score}/100, {len(report.findings)} findings")
    return {"cost_report": report}


async def supervisor_node(state: AnalysisState) -> dict:
    """Synthesize all agent reports into final report."""
    sec = state["security_report"]
    rel = state["reliability_report"]
    cost = state["cost_report"]

    agent_reports = [r for r in [sec, rel, cost] if r]

    llm = get_llm(temperature=0.2)
    prompt = ChatPromptTemplate.from_messages([
        ("system", SUPERVISOR_PROMPT),
    ])

    chain = prompt | llm
    try:
        response = await chain.ainvoke({
            "security_summary": sec.summary if sec else "N/A",
            "security_score": sec.score if sec else 0,
            "security_findings_count": len(sec.findings) if sec else 0,
            "reliability_summary": rel.summary if rel else "N/A",
            "reliability_score": rel.score if rel else 0,
            "reliability_findings_count": len(rel.findings) if rel else 0,
            "cost_summary": cost.summary if cost else "N/A",
            "cost_score": cost.score if cost else 0,
            "cost_findings_count": len(cost.findings) if cost else 0,
        })
        response_text = response.content.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1]
            response_text = response_text.rsplit("```", 1)[0]

        result = json.loads(response_text)
        executive_summary = result.get("executive_summary", "")
        risk_summary = result.get("risk_summary", "")
        recommendations = result.get("recommendations", [])
    except Exception:
        executive_summary = "Analysis complete. Review individual agent reports for details."
        risk_summary = "Unable to generate AI risk summary."
        recommendations = ["Review security findings", "Address reliability gaps", "Optimize costs"]

    overall_score = calculate_overall_score(agent_reports)

    final_report = AnalysisReport(
        files_analyzed=list(state["file_contents"].keys()),
        agent_reports=agent_reports,
        overall_score=overall_score,
        executive_summary=executive_summary,
        risk_summary=risk_summary,
        recommendations=recommendations,
    )

    return {"final_report": final_report}


def build_analysis_graph() -> StateGraph:
    """Build the LangGraph multi-agent analysis workflow (sequential for local LLM)."""
    graph = StateGraph(AnalysisState)

    # Add nodes
    graph.add_node("parse_files", parse_files_node)
    graph.add_node("security_analysis", security_node)
    graph.add_node("reliability_analysis", reliability_node)
    graph.add_node("cost_analysis", cost_node)
    graph.add_node("supervisor", supervisor_node)

    # Sequential edges: parse → security → reliability → cost → supervisor
    # Local LLMs can only handle one request at a time efficiently
    graph.set_entry_point("parse_files")
    graph.add_edge("parse_files", "security_analysis")
    graph.add_edge("security_analysis", "reliability_analysis")
    graph.add_edge("reliability_analysis", "cost_analysis")
    graph.add_edge("cost_analysis", "supervisor")
    graph.add_edge("supervisor", END)

    return graph.compile()


async def run_analysis(file_contents: dict[str, str]) -> AnalysisReport:
    """Run the complete multi-agent analysis pipeline."""
    graph = build_analysis_graph()

    initial_state: AnalysisState = {
        "file_contents": file_contents,
        "k8s_resources": {},
        "tf_resources": [],
        "security_report": None,
        "reliability_report": None,
        "cost_report": None,
        "final_report": None,
    }

    result = await graph.ainvoke(initial_state)
    return result["final_report"]
