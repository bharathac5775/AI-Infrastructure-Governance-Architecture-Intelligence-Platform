"""SHA256 fingerprinting for uploaded infrastructure file bundles.

Used by drift detection (Phase 3.2) to identify when a re-uploaded set of
files represents the SAME infrastructure deployment as a prior scan, so we
can compare findings across versions.

Design choice — bundle hash is over FILENAMES only, not content
================================================================
Re-uploading `production.tf` after editing it must still match the prior
scan as the "same bundle." Content edits are exactly what we want drift
detection to surface — they shouldn't break the match itself.

The bundle fingerprint therefore hashes only the SORTED set of filenames.
Per-file content hashes are computed and stored separately as metadata
(useful to identify which files inside the bundle changed between scans),
but they do not participate in the bundle hash.

What changes the bundle hash:
  - Adding a file:    bundle changes
  - Removing a file:  bundle changes
  - Renaming a file:  bundle changes (logically a different deployment)
  - Editing content:  bundle UNCHANGED (this is the drift signal we want)
"""
from __future__ import annotations

import hashlib


def compute_fingerprints(file_contents: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Compute per-file content hashes and a bundle hash over filenames.

    Args:
        file_contents: mapping of filename -> file content (text)

    Returns:
        (bundle_fingerprint, file_fingerprints)
        - file_fingerprints: {filename: sha256_hex} of file content (informational)
        - bundle_fingerprint: sha256 over the sorted list of filenames joined
          by "\\n". Identifies the bundle as a whole. Content edits to a file
          do NOT change the bundle hash (so drift detection can find the prior
          version after edits).

    See module docstring for the rationale on the filename-only bundle hash.
    """
    file_fingerprints = {
        name: hashlib.sha256(content.encode("utf-8")).hexdigest()
        for name, content in file_contents.items()
    }
    bundle_input = "\n".join(sorted(file_fingerprints))
    bundle_fingerprint = hashlib.sha256(bundle_input.encode("utf-8")).hexdigest()
    return bundle_fingerprint, file_fingerprints
