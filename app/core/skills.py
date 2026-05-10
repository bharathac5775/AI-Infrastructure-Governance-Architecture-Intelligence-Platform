"""Skill file loader — reads agent behavior from markdown skill files."""

import os
import yaml
from pathlib import Path
from typing import Any

SKILLS_DIR = Path(__file__).parent.parent.parent / "skills"


def load_skill(skill_name: str) -> dict[str, Any]:
    """Load a skill file and return its metadata + prompt content.

    Skill files use YAML frontmatter (between --- delimiters) for metadata,
    followed by the prompt content in the body.

    Returns:
        {
            "name": str,
            "agent": str,
            "infra_type": str,
            "description": str,
            "prompt": str,
            ...other frontmatter fields
        }
    """
    skill_path = SKILLS_DIR / f"{skill_name}.md"
    if not skill_path.exists():
        raise FileNotFoundError(f"Skill file not found: {skill_path}")

    content = skill_path.read_text(encoding="utf-8")

    # Parse YAML frontmatter
    metadata = {}
    prompt = content

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            metadata = yaml.safe_load(parts[1]) or {}
            prompt = parts[2].strip()

    metadata["prompt"] = prompt
    metadata.setdefault("name", skill_name)
    return metadata


def get_agent_prompt(agent: str, infra_type: str) -> str:
    """Get the prompt for a specific agent and infrastructure type.

    Args:
        agent: "security", "reliability", "cost", "architecture-reviewer", "supervisor"
        infra_type: "kubernetes", "terraform"

    Returns:
        The prompt string for the agent.
    """
    skill_name = f"{agent}-{infra_type}"
    try:
        skill = load_skill(skill_name)
        return skill["prompt"]
    except FileNotFoundError:
        # Try agent-only (no infra_type) for agents like supervisor
        try:
            skill = load_skill(agent)
            return skill["prompt"]
        except FileNotFoundError:
            return ""


def list_skills() -> list[dict[str, Any]]:
    """List all available skill files with their metadata."""
    skills = []
    if not SKILLS_DIR.exists():
        return skills
    for path in sorted(SKILLS_DIR.glob("*.md")):
        try:
            skill = load_skill(path.stem)
            skills.append(skill)
        except Exception:
            continue
    return skills
