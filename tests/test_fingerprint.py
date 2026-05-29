"""Tests for SHA256 fingerprinting of uploaded file bundles.

Reference: app/core/fingerprint.py

Critical semantics (locked in here):
- Bundle hash is over the SORTED FILENAME SET only.
- Editing file content does NOT change the bundle hash. (This is what enables
  drift detection across edits — see app/core/drift.py.)
- Per-file content hashes are still computed and stored as metadata, but
  they don't drive the bundle hash.
- Adding/removing/renaming a file DOES change the bundle hash.
"""
from __future__ import annotations

from app.core.fingerprint import compute_fingerprints


class TestComputeFingerprints:
    def test_same_content_same_hash(self):
        a = compute_fingerprints({"main.tf": 'resource "aws_s3_bucket" "x" {}'})
        b = compute_fingerprints({"main.tf": 'resource "aws_s3_bucket" "x" {}'})
        assert a == b

    def test_changed_content_same_bundle_hash(self):
        """Editing file content does NOT change the bundle hash. This is the
        property that makes drift detection work across edits — same file,
        different bytes, still the same logical bundle."""
        a_bundle, a_files = compute_fingerprints({"main.tf": "resource a"})
        b_bundle, b_files = compute_fingerprints({"main.tf": "resource b"})
        assert a_bundle == b_bundle, "filename-only bundle hash must ignore content"
        # Per-file hashes still differ — drift logic uses these to identify
        # which files inside the bundle changed.
        assert a_files["main.tf"] != b_files["main.tf"]

    def test_filename_change_changes_bundle_hash(self):
        """Renaming a file DOES change the bundle hash — it's a different
        bundle (different logical deployment)."""
        a_bundle, a_files = compute_fingerprints({"main.tf": "x"})
        b_bundle, b_files = compute_fingerprints({"renamed.tf": "x"})
        assert a_bundle != b_bundle
        # Per-file content hash for surviving content matches across the rename
        assert a_files["main.tf"] == b_files["renamed.tf"]

    def test_add_file_changes_bundle_hash(self):
        """Adding a new file to the upload set changes the bundle hash."""
        a_bundle, _ = compute_fingerprints({"main.tf": "x"})
        b_bundle, _ = compute_fingerprints({"main.tf": "x", "extra.tf": "y"})
        assert a_bundle != b_bundle

    def test_remove_file_changes_bundle_hash(self):
        a_bundle, _ = compute_fingerprints({"main.tf": "x", "extra.tf": "y"})
        b_bundle, _ = compute_fingerprints({"main.tf": "x"})
        assert a_bundle != b_bundle

    def test_file_order_independent(self):
        """Dict insertion order must not affect the bundle hash."""
        a, _ = compute_fingerprints({"a.tf": "1", "b.tf": "2"})
        b, _ = compute_fingerprints({"b.tf": "2", "a.tf": "1"})
        assert a == b

    def test_per_file_hashes_in_dict(self):
        _, files = compute_fingerprints({"a.tf": "alpha", "b.tf": "beta"})
        assert set(files.keys()) == {"a.tf", "b.tf"}
        # SHA256 hex is exactly 64 characters
        assert all(len(v) == 64 for v in files.values())
        assert files["a.tf"] != files["b.tf"]

    def test_per_file_hashes_change_with_content(self):
        """Per-file content hashes ARE content-aware (only the bundle hash isn't)."""
        _, a_files = compute_fingerprints({"main.tf": "alpha"})
        _, b_files = compute_fingerprints({"main.tf": "beta"})
        assert a_files["main.tf"] != b_files["main.tf"]

    def test_empty_input_produces_empty_per_file_dict(self):
        bundle, files = compute_fingerprints({})
        assert files == {}
        # Bundle hash of empty input is the SHA256 of empty string
        assert len(bundle) == 64

    def test_deterministic_across_invocations(self):
        """Same input -> same hash, every time."""
        files = {"a.tf": "alpha", "b.tf": "beta"}
        results = [compute_fingerprints(files) for _ in range(3)]
        assert all(r == results[0] for r in results)
