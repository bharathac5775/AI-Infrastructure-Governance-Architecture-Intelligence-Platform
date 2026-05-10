"""Report store backed by ChromaDB for persistent storage and comparison."""

import json
import logging
from datetime import datetime
from typing import Optional

import chromadb

from app.models import AnalysisReport

logger = logging.getLogger(__name__)

_client: Optional[chromadb.ClientAPI] = None
_collection: Optional[chromadb.Collection] = None

COLLECTION_NAME = "governance_reports"
PERSIST_DIR = "data/chromadb"


def _get_collection() -> chromadb.Collection:
    """Get or create the ChromaDB collection (lazy singleton)."""
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path=PERSIST_DIR)
        _collection = _client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"description": "Infrastructure governance analysis reports"},
        )
        logger.info(f"ChromaDB collection '{COLLECTION_NAME}' ready ({_collection.count()} reports stored)")
    return _collection


def save_report(report: AnalysisReport) -> str:
    """Persist a report to ChromaDB. Returns report_id."""
    collection = _get_collection()

    report_dict = report.model_dump()
    report_json = json.dumps(report_dict)

    # Detect infrastructure type from file extensions
    files = report.files_analyzed
    has_tf = any(f.endswith((".tf", ".hcl")) for f in files)
    has_k8s = any(f.endswith((".yaml", ".yml")) for f in files)
    infra_type = "terraform" if has_tf and not has_k8s else "kubernetes" if has_k8s and not has_tf else "mixed"

    # Build metadata for filtering/querying
    metadata = {
        "report_id": report.report_id,
        "timestamp": report.timestamp,
        "overall_score": report.overall_score,
        "files_analyzed": ", ".join(files),
        "file_count": len(files),
        "infra_type": infra_type,
    }

    # Add per-agent scores to metadata
    for ar in report.agent_reports:
        key = ar.agent_name.lower().replace(" ", "_") + "_score"
        metadata[key] = ar.score

    if report.architecture_review:
        metadata["architecture_score"] = report.architecture_review.architecture_score

    collection.upsert(
        ids=[report.report_id],
        documents=[report_json],
        metadatas=[metadata],
    )

    # Also cache in memory for fast access within the same session
    _full_reports_cache[report.report_id] = report_json

    logger.info(f"Saved report {report.report_id} (score: {report.overall_score})")
    return report.report_id


# In-memory cache for full report JSON (ChromaDB stores metadata + summary)
_full_reports_cache: dict[str, str] = {}


def get_report(report_id: str) -> Optional[AnalysisReport]:
    """Retrieve a report by ID."""
    # Try in-memory cache first (fast path)
    if report_id in _full_reports_cache:
        return AnalysisReport(**json.loads(_full_reports_cache[report_id]))

    # Fall back to ChromaDB (survives server restarts)
    collection = _get_collection()
    try:
        result = collection.get(ids=[report_id], include=["documents"])
        if result and result["ids"] and result["documents"][0]:
            report_json = result["documents"][0]
            _full_reports_cache[report_id] = report_json  # re-populate cache
            return AnalysisReport(**json.loads(report_json))
    except Exception:
        pass
    return None


def list_reports(limit: int = 50) -> list[dict]:
    """List recent reports with metadata (without full findings)."""
    collection = _get_collection()
    count = collection.count()
    if count == 0:
        return []

    result = collection.get(
        limit=limit,
        include=["metadatas"],
    )

    reports = []
    for i, rid in enumerate(result["ids"]):
        meta = result["metadatas"][i]
        reports.append({
            "report_id": rid,
            "timestamp": meta.get("timestamp", ""),
            "overall_score": meta.get("overall_score", 0),
            "files_analyzed": meta.get("files_analyzed", ""),
            "file_count": meta.get("file_count", 0),
            "security_agent_score": meta.get("security_agent_score", 0),
            "reliability_agent_score": meta.get("reliability_agent_score", 0),
            "cost_agent_score": meta.get("cost_agent_score", 0),
            "architecture_score": meta.get("architecture_score", 0),
        })

    # Sort by timestamp descending
    reports.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return reports[:limit]


def compare_reports(report_id_a: str, report_id_b: str) -> Optional[dict]:
    """Compare two reports and return score deltas."""
    report_a = get_report(report_id_a)
    report_b = get_report(report_id_b)

    if not report_a or not report_b:
        return None

    def _agent_score(report: AnalysisReport, name_prefix: str) -> float:
        for ar in report.agent_reports:
            if ar.agent_name.lower().startswith(name_prefix):
                return ar.score
        return 0.0

    return {
        "report_a": {"id": report_id_a, "timestamp": report_a.timestamp},
        "report_b": {"id": report_id_b, "timestamp": report_b.timestamp},
        "overall_delta": round(report_b.overall_score - report_a.overall_score, 1),
        "security_delta": round(
            _agent_score(report_b, "security") - _agent_score(report_a, "security"), 1
        ),
        "reliability_delta": round(
            _agent_score(report_b, "reliability") - _agent_score(report_a, "reliability"), 1
        ),
        "cost_delta": round(
            _agent_score(report_b, "cost") - _agent_score(report_a, "cost"), 1
        ),
        "findings_delta": sum(len(ar.findings) for ar in report_b.agent_reports)
        - sum(len(ar.findings) for ar in report_a.agent_reports),
        "scores": {
            "before": {
                "overall": report_a.overall_score,
                "security": _agent_score(report_a, "security"),
                "reliability": _agent_score(report_a, "reliability"),
                "cost": _agent_score(report_a, "cost"),
            },
            "after": {
                "overall": report_b.overall_score,
                "security": _agent_score(report_b, "security"),
                "reliability": _agent_score(report_b, "reliability"),
                "cost": _agent_score(report_b, "cost"),
            },
        },
    }


def delete_report(report_id: str) -> bool:
    """Delete a specific report from ChromaDB and the in-memory cache."""
    collection = _get_collection()
    try:
        # Check it exists first
        existing = collection.get(ids=[report_id])
        if not existing["ids"]:
            return False
        collection.delete(ids=[report_id])
        _full_reports_cache.pop(report_id, None)
        logger.info(f"Deleted report {report_id}")
        return True
    except Exception:
        logger.exception(f"Failed to delete report {report_id}")
        return False


def find_similar_reports(query_text: str, n_results: int = 3, exclude_id: str = "", infra_type: str = "") -> list[dict]:
    """Find past reports with similar risk profiles using vector similarity search."""
    collection = _get_collection()
    if collection.count() == 0:
        return []

    # Filter by infra type so Terraform reports only match Terraform, etc.
    where_filter = {"infra_type": infra_type} if infra_type else None
    fetch_n = min(n_results + 1, collection.count())

    results = None
    if where_filter:
        try:
            results = collection.query(
                query_texts=[query_text],
                n_results=fetch_n,
                include=["metadatas", "distances"],
                where=where_filter,
            )
        except Exception:
            results = None
        # If filtered query returned nothing, retry without filter
        if not results or not results["ids"][0]:
            results = None

    if results is None:
        results = collection.query(
            query_texts=[query_text],
            n_results=fetch_n,
            include=["metadatas", "distances"],
        )

    similar = []
    for i, rid in enumerate(results["ids"][0]):
        if rid == exclude_id:
            continue
        meta = results["metadatas"][0][i]
        distance = results["distances"][0][i]
        # ChromaDB uses L2 distance (0 to ∞). Convert to 0-1 similarity.
        similarity = round(1 / (1 + distance), 3)
        similar.append({
            "report_id": rid,
            "timestamp": meta.get("timestamp", ""),
            "overall_score": meta.get("overall_score", 0),
            "files_analyzed": meta.get("files_analyzed", ""),
            "similarity": similarity,
        })
        if len(similar) >= n_results:
            break

    return similar
