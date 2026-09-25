"""Competition presentation layer.

Reads ONLY the locked authoritative experiment artifacts and renders them as
presentation evidence. Never modifies artifacts, never invokes the pipeline.
"""

from .evidence import (
    AUTHORITATIVE_ID,
    EvidenceBundle,
    HistoricalDemo,
    ModeEvidence,
    authoritative_dir,
    build_evidence_dashboard,
    load_evidence,
)
from .render import presentation_page

__all__ = [
    "AUTHORITATIVE_ID",
    "EvidenceBundle",
    "HistoricalDemo",
    "ModeEvidence",
    "authoritative_dir",
    "build_evidence_dashboard",
    "load_evidence",
    "presentation_page",
]