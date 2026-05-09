import hcl2
import json
import io
from typing import Any


def parse_terraform(content: str) -> dict[str, Any]:
    """Parse Terraform HCL content."""
    try:
        parsed = hcl2.load(io.StringIO(content))
        return parsed
    except Exception as e:
        raise ValueError(f"Invalid Terraform HCL: {e}")


def extract_tf_resources(parsed: dict) -> list[dict[str, Any]]:
    """Extract resources from parsed Terraform."""
    resources = []
    for resource_block in parsed.get("resource", []):
        for resource_type, instances in resource_block.items():
            for name, config in instances.items():
                resources.append(
                    {
                        "type": resource_type,
                        "name": name,
                        "config": config,
                    }
                )
    return resources


def extract_tf_variables(parsed: dict) -> list[dict[str, Any]]:
    """Extract variables from parsed Terraform."""
    variables = []
    for var_block in parsed.get("variable", []):
        for var_name, var_config in var_block.items():
            variables.append({"name": var_name, "config": var_config})
    return variables
