# SPDX-License-Identifier: Apache-2.0
"""The issue-#18 vectors are byte-reproducible and agree with the harness.

If the vectors are not present (for example in a wheel-only clean room that does
not stage them), these tests skip rather than fail.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from algovoi_ube.canonical import canonicalize  # noqa: E402
from algovoi_ube.chain import verify_chain  # noqa: E402

VEC_DIR = ROOT / "vectors" / "issue-18"
pytestmark = pytest.mark.skipif(not VEC_DIR.is_dir(), reason="issue-18 vectors not present")


def _load(name: str) -> dict:
    return json.loads((VEC_DIR / f"{name}.json").read_text(encoding="utf-8"))


def test_preimage_vector_matches_the_canonicalizer():
    v = _load("preimage_reproducibility")
    assert canonicalize(v["event"]) == v["jcs_canonical"]
    assert hashlib.sha256(v["jcs_canonical"].encode("utf-8")).hexdigest() == v["event_hash_sha256"]
    dc = v["delimiter_collision"]
    assert dc["colon_join_collides"] is True
    assert dc["jcs_collides"] is False


def test_tamper_vector_fails_verification():
    v = _load("tamper_detection")
    assert verify_chain(v["valid_chain"]).ok is True
    assert verify_chain(v["tampered_chain"]).ok is False


def test_truncation_vector_prefix_links_but_is_short():
    v = _load("truncation")
    assert verify_chain(v["truncated_prefix"]).ok is True
    assert v["expected_length"] == len(v["full_chain"])
    assert len(v["truncated_prefix"]) != v["expected_length"]


def test_duplicate_vote_vector_cannot_meet_threshold():
    v = _load("duplicate_vote")
    req = v["request"]
    unique = {vote["voter_id"] for vote in req["votes"]}
    assert len(unique) < req["threshold"]


@pytest.mark.skipif(
    not (ROOT / "scripts" / "gen_issue18_vectors.py").exists(),
    reason="generator not present",
)
def test_vectors_are_byte_reproducible():
    spec = importlib.util.spec_from_file_location(
        "gen_issue18_vectors", ROOT / "scripts" / "gen_issue18_vectors.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name, payload in mod.vectors().items():
        regenerated = mod._render(name, payload)
        on_disk = (VEC_DIR / f"{name}.json").read_text(encoding="utf-8")
        assert regenerated == on_disk, f"{name}.json is stale vs the generator"
