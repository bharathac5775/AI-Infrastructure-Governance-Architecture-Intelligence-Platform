import hcl2
import io
import json
import re
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


def resources_with_companion(
    tf_resources: list, companion_type: str, parent_type: str = "aws_s3_bucket"
) -> set[str]:
    """Return parent resource names that have a companion resource of the given type.

    AWS provider v4+ splits aws_s3_bucket config into separate resources:
      aws_s3_bucket_server_side_encryption_configuration
      aws_s3_bucket_versioning
      aws_s3_bucket_lifecycle_configuration
      aws_s3_bucket_public_access_block
      aws_s3_bucket_acl
      etc.

    This function extracts which parent resource (by name) has a companion
    by parsing the 'bucket' (or first config value referencing the parent type)
    field in the companion resource.
    """
    # Field that typically references the parent resource
    ref_fields = ("bucket", "parent_id", "resource_id")
    pattern = re.compile(rf'{re.escape(parent_type)}\.(\w+)')
    names = set()
    for res in tf_resources:
        if res.get("type") == companion_type:
            config = res.get("config", {})
            # Try known reference fields first, then scan all string values
            ref_value = None
            for field in ref_fields:
                if field in config:
                    ref_value = config[field]
                    break
            if ref_value is None:
                # Scan all config values for a reference to parent_type
                for v in config.values():
                    if isinstance(v, str) and parent_type in v:
                        ref_value = v
                        break
                    elif isinstance(v, list) and v and isinstance(v[0], str) and parent_type in v[0]:
                        ref_value = v[0]
                        break
            if isinstance(ref_value, list):
                ref_value = ref_value[0] if ref_value else ""
            if isinstance(ref_value, str):
                match = pattern.search(ref_value)
                if match:
                    names.add(match.group(1))
    return names
