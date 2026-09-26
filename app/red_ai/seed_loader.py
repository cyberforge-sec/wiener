from __future__ import annotations

import yaml
from pydantic import ValidationError

from ..config import config
from ..models import AttackSeed

_ALLOWED_KEYS = {"seed_id", "category", "payload", "objective", "targets", "intended_action"}


class SeedLoadingError(ValueError):
    """Raised when red_ai_seeds.yaml is malformed, invalid, or has duplicates."""


class SeedLoader:
    """Loads red_ai_seeds.yaml into validated AttackSeed objects.

    Strict by design: seed_id must be unique (duplicates raise), every entry
    must pass AttackSeed validation, and file order is preserved as the
    deterministic iteration order.
    """

    _LIST_KEY = "seeds"

    def __init__(self, path: str | None = None) -> None:
        path = path or config.RED_AI_SEEDS_PATH
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        raw_seeds = (data or {}).get(self._LIST_KEY)
        if not isinstance(raw_seeds, list):
            raise SeedLoadingError(f"red_ai_seeds.yaml must contain a top-level '{self._LIST_KEY}' list")

        seeds: list[AttackSeed] = []
        seen: set[str] = set()
        for i, entry in enumerate(raw_seeds):
            if not isinstance(entry, dict):
                raise SeedLoadingError(f"seed entry #{i} is not a mapping")
            unknown = set(entry) - _ALLOWED_KEYS
            if unknown:
                raise SeedLoadingError(f"seed entry #{i} has unknown keys: {sorted(unknown)}")
            try:
                seed = AttackSeed.model_validate(entry)
            except ValidationError as exc:
                raise SeedLoadingError(
                    f"seed entry #{i} failed validation: {exc.errors()[0]['msg']}"
                ) from exc
            if seed.seed_id in seen:
                raise SeedLoadingError(f"duplicate seed_id: {seed.seed_id}")
            seen.add(seed.seed_id)
            seeds.append(seed)

        self._seeds: list[AttackSeed] = seeds

    @property
    def seeds(self) -> list[AttackSeed]:
        """Seeds in file order (deterministic)."""
        return list(self._seeds)

    def get(self, seed_id: str) -> AttackSeed | None:
        for seed in self._seeds:
            if seed.seed_id == seed_id:
                return seed
        return None

    def __len__(self) -> int:
        return len(self._seeds)


class AdaptiveSeedLoader(SeedLoader):
    """Loads the SEPARATE `adaptive_seeds` list (interactive demo pool).

    Kept apart from the authoritative `seeds` list on purpose: the recorded
    benchmark, orchestrator capabilities, and /dashboard all derive from
    `SeedLoader().seeds`, and must never grow with the adaptive demo pool.
    Uses the same strict AttackSeed validation as `seeds`.

    The pool also references high-tier seeds (RS-001/RS-003/RS-005) that stay
    AUTHORITATIVE in the primary `seeds` list — they are resolved by fallback,
    never duplicated into a second copy that could drift.
    """

    _LIST_KEY = "adaptive_seeds"

    def get(self, seed_id: str) -> AttackSeed | None:
        return super().get(seed_id) or SeedLoader().get(seed_id)

class StressSeedLoader(SeedLoader):
    """Loads the `stress_seeds` list from config/stress_seeds.yaml.

    A FOURTH, entirely separate population. The benchmark reads
    `SeedLoader().seeds` (135 trials), the interactive demo reads
    `AdaptiveSeedLoader`, and the stress test reads this. None of them reads
    the others, so running a stress test cannot change the benchmark's trial
    count, its metrics, or the /dashboard ledger.

    Resolved by explicit path rather than by a new key in red_ai_seeds.yaml:
    keeping the stress population in its own FILE is what makes that separation
    structural instead of a naming convention. It also means the stress
    population is not in `code_fingerprint`'s `_EXPERIMENT_SOURCES`, which is
    correct - a stress test must never be able to invalidate the provenance of
    the authoritative benchmark.
    """

    _LIST_KEY = "stress_seeds"

    def __init__(self, path: str | None = None) -> None:
        super().__init__(path or config.STRESS_SEEDS_PATH)

    def get(self, seed_id: str) -> AttackSeed | None:
        """Resolve only inside this population.

        Deliberately does NOT fall back to `SeedLoader`: a stress test that
        silently borrowed a benchmark seed would compare two different
        populations and report it as one.
        """
        return super().get(seed_id)

    @property
    def adversarial(self) -> list[AttackSeed]:
        """Entries that ask for a specific action (attack effectiveness)."""
        return [s for s in self.seeds if s.intended_action is not None]

    @property
    def benign_controls(self) -> list[AttackSeed]:
        """Entries that request nothing (operational safety / FIR)."""
        return [s for s in self.seeds if s.intended_action is None]


class HierarchySeedLoader(SeedLoader):
    """Loads the `hierarchy_seeds` list from config/stress_hierarchy_seeds.yaml.

    A FIFTH separate population, and the narrowest of them: every attack varies
    only the attacker's claim over the instruction hierarchy, so the two ungated
    modes differ in exactly one variable - whether the system prompt telling the
    model to resist is present at all.

    Like `StressSeedLoader` it reads its OWN file and does NOT fall back to any
    other population, and it is not in the code fingerprint's
    `_EXPERIMENT_SOURCES`, so a targeted study can never invalidate the
    authoritative benchmark's provenance.
    """

    _LIST_KEY = "hierarchy_seeds"

    def __init__(self, path: str | None = None) -> None:
        super().__init__(path or config.STRESS_HIERARCHY_SEEDS_PATH)

    def get(self, seed_id: str) -> AttackSeed | None:
        return super().get(seed_id)

    @property
    def adversarial(self) -> list[AttackSeed]:
        return [s for s in self.seeds if s.intended_action is not None]

    @property
    def benign_controls(self) -> list[AttackSeed]:
        return [s for s in self.seeds if s.intended_action is None]
