"""algovoi-ube: an independent NTI-1 conformance harness.

Neutral, Apache-2.0 tooling for checking whether an implementation does what
NTI-1 requires. It recomputes the audit chain, runs the five testable
requirements, and states plainly which pillars the AlgoVoi Keystone answers and
which it does not.

This package does not implement an agent trust engine. It checks one.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .boundary import Boundary, BoundaryDecision, describe, judge
from .chain import (
    GENESIS,
    AuditEvent,
    ChainStatus,
    event_hash,
    request_hash,
    verify_chain,
)
from .conformance import Check, Report, run_all
from .failclosed import (
    REASONS,
    IllegalTransition,
    IncompleteCheck,
    Lifecycle,
    State,
    StatusResult,
    resolve,
)
from .keystone_mapping import FLOW, MAPPING, coverage, report as keystone_report

__all__ = [
    "GENESIS",
    "REASONS",
    "AuditEvent",
    "Boundary",
    "BoundaryDecision",
    "ChainStatus",
    "Check",
    "FLOW",
    "IllegalTransition",
    "IncompleteCheck",
    "Lifecycle",
    "MAPPING",
    "Report",
    "State",
    "StatusResult",
    "coverage",
    "describe",
    "event_hash",
    "judge",
    "keystone_report",
    "request_hash",
    "resolve",
    "run_all",
    "verify_chain",
]
