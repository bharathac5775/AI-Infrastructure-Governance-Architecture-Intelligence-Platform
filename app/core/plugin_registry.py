"""Plugin registry — discovers agent plugins from ``skills/*.md`` frontmatter.

Phase 3.5. A skill file becomes a *registerable plugin agent* only when its
frontmatter declares BOTH ``agent_type`` and ``weight``. Existing skills declare
neither, so nothing is picked up until a skill explicitly opts in — this is the
guarantee that the plugin harness changes no behavior by merely existing.

The core agents (security / reliability / cost / architecture-reviewer /
supervisor / remediator) are hardcoded into the LangGraph pipeline. Even if their
skill files gain ``agent_type``/``weight`` frontmatter (for discoverability), the
scanner excludes them from the runtime plugin set so they never double-execute.
"""

import logging
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.core.skills import SKILLS_DIR, load_skill

logger = logging.getLogger(__name__)

AgentType = Literal["rule_based", "llm_only", "hybrid"]

# Skills whose agents are already wired into the pipeline in Python. They may
# carry plugin frontmatter for documentation, but must never register as runtime
# plugins (that would run them twice). Keyed by the frontmatter ``agent`` value.
CORE_AGENTS: frozenset[str] = frozenset(
    {"security", "reliability", "cost", "architecture-reviewer", "supervisor", "remediator"}
)


class PluginAgent(BaseModel):
    """A dynamically-registered analysis agent described by a skill file."""

    name: str                      # skill file stem, unique key
    agent_name: str                # human label, e.g. "Compliance Agent"
    agent_type: AgentType
    weight: float = Field(gt=0.0, le=1.0)
    infra_type: str = "all"
    skill_name: str                # skill to load the prompt from
    prompt: str = ""               # skill body (system prompt for llm_only/hybrid)

    @field_validator("weight", mode="before")
    @classmethod
    def _coerce_weight(cls, v: Any) -> Any:
        # YAML may hand us a string; coerce so a quoted "0.1" still validates.
        if isinstance(v, str):
            try:
                return float(v)
            except ValueError:
                return v
        return v


def _derive_agent_name(meta: dict[str, Any], agent: str) -> str:
    """Choose a display name for the agent.

    Prefers an explicit ``agent_name`` in frontmatter, else Title-cases the
    ``agent`` slug and appends "Agent" (e.g. ``compliance`` -> "Compliance Agent").
    """
    explicit = meta.get("agent_name")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    label = agent.replace("-", " ").replace("_", " ").strip().title()
    return f"{label} Agent" if label else "Plugin Agent"


def _plugin_from_meta(stem: str, meta: dict[str, Any]) -> PluginAgent | None:
    """Build a ``PluginAgent`` from one skill's frontmatter, or None if not eligible."""
    # Gate: both fields must be present for a skill to be a plugin at all.
    if "agent_type" not in meta or "weight" not in meta:
        return None

    agent = str(meta.get("agent", stem)).strip()

    # Never register a core agent as a runtime plugin (avoids double execution).
    if agent in CORE_AGENTS:
        logger.debug("Skill '%s' maps to core agent '%s'; not registered as plugin.", stem, agent)
        return None

    try:
        return PluginAgent(
            name=stem,
            agent_name=_derive_agent_name(meta, agent),
            agent_type=meta["agent_type"],
            weight=meta["weight"],
            infra_type=str(meta.get("infra_type", "all")),
            skill_name=stem,
            prompt=meta.get("prompt", ""),
        )
    except ValidationError as e:
        logger.warning("Skill '%s' has invalid plugin frontmatter, skipping: %s", stem, e)
        return None


def discover_plugins(skills_dir: Path | None = None) -> list[PluginAgent]:
    """Scan the skills directory and return every eligible plugin agent.

    Discovery never raises: a malformed skill file is logged and skipped so one
    bad plugin cannot break the pipeline.
    """
    base = skills_dir or SKILLS_DIR
    plugins: list[PluginAgent] = []
    if not base.exists():
        return plugins

    for path in sorted(base.glob("*.md")):
        try:
            meta = load_skill(path.stem, skills_dir=base)
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to load skill '%s' during plugin discovery: %s", path.stem, e)
            continue
        plugin = _plugin_from_meta(path.stem, meta)
        if plugin is not None:
            plugins.append(plugin)

    if plugins:
        logger.info("Discovered %d plugin agent(s): %s", len(plugins), [p.name for p in plugins])
    return plugins
