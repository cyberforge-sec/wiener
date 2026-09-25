from __future__ import annotations

from ..models import AttackSeed, RedAttack
from .attack_logger import RedAttackLogger
from .mutator import MUTATION_ORDER, attacks_for
from .seed_loader import SeedLoader

# Default: baseline + one mutation per MutationKind (4 iterations).
DEFAULT_ITERATIONS = len(MUTATION_ORDER)


class RedHarness:
    """Deterministic Red AI harness: fixed seeds -> baseline + basic mutations.

    No adaptive feedback: given the same seed, rng_seed and iteration count,
    generation is fully reproducible. Every generated attack is logged.
    """

    def __init__(
        self,
        loader: SeedLoader | None = None,
        attack_logger: RedAttackLogger | None = None,
        rng_seed: int = 20260708,
        iterations: int = DEFAULT_ITERATIONS,
    ) -> None:
        self._loader = loader or SeedLoader()
        self._logger = attack_logger or RedAttackLogger()
        self._rng_seed = rng_seed
        self._iterations = iterations

    @property
    def rng_seed(self) -> int:
        return self._rng_seed

    def generate(self, seed_id: str, iterations: int | None = None) -> list[RedAttack]:
        """Generate baseline + mutated variants for one seed; all are logged."""
        seed = self._loader.get(seed_id)
        if seed is None:
            raise ValueError(f"unknown seed_id: {seed_id}")
        count = self._iterations if iterations is None else iterations
        attacks = attacks_for(seed, count, self._rng_seed)
        for attack in attacks:
            self._logger.log(attack)
        return attacks

    def generate_all(self, iterations: int | None = None) -> dict[str, list[RedAttack]]:
        """Generate for every loaded seed, in file (deterministic) order."""
        return {
            seed.seed_id: self.generate(seed.seed_id, iterations)
            for seed in self._loader.seeds
        }

    def seeds(self) -> list[AttackSeed]:
        return self._loader.seeds