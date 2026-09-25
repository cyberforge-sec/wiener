"""Adaptive-attack pool selection, driven by ACTUAL policy outcomes.

The adaptive demo advertises seeds at different risk tiers so different runs
show different arcs (REVIEW-ended, escalation, hard-block). Tier claims are
never trusted implicitly: this module measures each seed's baseline against
the real Policy Gate and lets tests assert the pool really does contain both
a REVIEW-tier member and a BLOCK-tier member.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..llm.base import LLMProvider
from ..models import AttackSeed, Decision
from ..orchestration.pipeline import Pipeline
from ..red_ai.loop import render_attack
from ..red_ai.mutator import baseline
from ..red_ai.seed_loader import AdaptiveSeedLoader


def _seed(seed_id: str) -> AttackSeed:
    seed = AdaptiveSeedLoader().get(seed_id)
    if seed is None:
        raise ValueError(f"adaptive seed {seed_id!r} not in adaptive_seeds config")
    return seed


def measure_baseline(seed_id: str, llm: LLMProvider | None = None) -> Decision:
    """Verdict the real Policy Gate gives the seed's baseline scenario.

    `llm` defaults to the strict recorded replay provider (deterministic, no
    network), so tier measurements are reproducible in CI without a model.
    """
    result = Pipeline(llm=llm).run(render_attack(baseline(_seed(seed_id))))
    return result.decision.decision


def verify_catalog_tiers(
    catalog: Iterable[tuple[str, int]],
    llm: LLMProvider | None = None,
) -> dict[str, str]:
    """Map every catalog seed to the Policy Gate verdict it ACTUALLY produced.

    Returns {seed_id: observed verdict}. Callers assert the pool has both a
    REVIEW-tier member (moderate recon -> some sessions end REVIEW) and a
    BLOCK-tier member; a pool without both is misconfigured.
    """
    tiers: dict[str, str] = {}
    for seed_id, _ in catalog:
        tiers[seed_id] = measure_baseline(seed_id, llm=llm).value
    return tiers