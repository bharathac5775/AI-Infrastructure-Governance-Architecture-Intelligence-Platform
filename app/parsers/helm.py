import os
import subprocess
import tempfile


def render_helm_chart(chart_bytes: bytes, release_name: str = "release") -> str:
    """Run helm template on a packaged .tgz chart and return rendered Kubernetes YAML."""
    with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as tmp:
        tmp.write(chart_bytes)
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            ["helm", "template", release_name, tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise ValueError(f"helm template failed: {result.stderr.strip()}")
        return result.stdout
    finally:
        os.unlink(tmp_path)
