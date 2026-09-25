from __future__ import annotations

from collections.abc import Callable

from ..models import (
    AgentEvent,
    Decision,
    LoopReport,
    LoopStep,
    RedAttack,
    SOCContext,
    StopReason,
)
from .attack_logger import RedAttackLogger
from .mutator import baseline, mutate_adaptive
from .observer import RedFeedbackError, observe
from .seed_loader import SeedLoader

_FIXED_TS = "2026-01-01T00:00:00Z"

DEFAULT_RNG_SEED = 20260708
DEFAULT_MAX_ITERATIONS = 3  # MVP ceiling: baseline + up to 2 adaptive mutations.


def render_attack(attack: RedAttack) -> SOCContext:
    """Present a RedAttack to the defense as a SOCContext.

    Fully deterministic: fixed timestamp, fixed source/severity, alert_id
    derived only from the attack identity. The attack payload lands in the
    event `detail` so it reaches the SOC Agent / Blue AI without conversion.
    """
    return SOCContext(
        alert_id=f"red-{attack.seed_id}-it{attack.iteration}",
        provenance="red_ai_generated",
        environment="simulated",
        events=[
            AgentEvent(
                event_id=f"red-{attack.seed_id}-{attack.iteration}-e1",
                timestamp=_FIXED_TS,
                source="red_ai",
                event_type="alert",
                severity=8,
                detail=attack.payload,
            )
        ],
    )


class RedLoop:
    """Minimal closed loop: Attack -> Defense -> Feedback -> Mutation -> Attack.

    The defense is an injected callable (e.g. ``Pipeline().run``) returning an
    object that `observe` can read (needs `decision` and `risk`). The loop is
    deterministic: all mutation randomness derives from `rng_seed`, and the
    defense is assumed deterministic (ReplayProvider / FakeLLM / real pipeline).
    Explicit stop conditions: max iterations, attack succeeded (ALLOW), defense
    failure, malformed feedback.
    """

    def __init__(
        self,
        defense: Callable[[SOCContext], object],
        *,
        loader: SeedLoader | None = None,
        attack_logger: RedAttackLogger | None = None,
        render: Callable[[RedAttack], SOCContext] = render_attack,
        rng_seed: int = DEFAULT_RNG_SEED,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        stop_on_block: bool = False,
    ) -> None:
        if max_iterations < 1:
            raise ValueError(f"max_iterations must be >= 1, got {max_iterations}")
        self._defense = defense
        self._loader = loader or SeedLoader()
        self._logger = attack_logger or RedAttackLogger()
        self._render = render
        self._rng_seed = rng_seed
        self._max_iterations = max_iterations
        # Interactive demos stop as soon as the defense closes the door
        # (BLOCK). The recorded benchmark keeps the legacy full-horizon
        # behavior via the default False, so its pinned outputs never move.
        self._stop_on_block = stop_on_block

    @property
    def rng_seed(self) -> int:
        return self._rng_seed

    @property
    def max_iterations(self) -> int:
        return self._max_iterations

    def run(self, seed_id: str) -> LoopReport:
        seed = self._loader.get(seed_id)
        if seed is None:
            raise ValueError(f"unknown seed_id: {seed_id}")

        steps: list[LoopStep] = []
        attack = baseline(seed)

        for iteration in range(self._max_iterations):
            self._logger.log(attack)
            try:
                result = self._defense(self._render(attack))
                feedback = observe(result, iteration)
            except RedFeedbackError as exc:
                return self._report(seed_id, steps, StopReason.MALFORMED_FEEDBACK, str(exc))
            except Exception as exc:  # noqa: BLE001 - defense failure must stop, not crash.
                return self._report(
                    seed_id,
                    steps,
                    StopReason.PROVIDER_FAILURE,
                    f"{type(exc).__name__}: {exc}",
                )

            self._logger.log_feedback(feedback)
            steps.append(LoopStep(attack=attack, feedback=feedback))

            if feedback.decision == Decision.ALLOW:
                return self._report(seed_id, steps, StopReason.ATTACK_SUCCEEDED)
            if self._stop_on_block and feedback.decision == Decision.BLOCK:
                # Defense closed the door: no more mutations to try.
                return self._report(seed_id, steps, StopReason.DEFENSE_BLOCKED)

            attack = mutate_adaptive(
                seed,
                iteration + 1,
                feedback,
                self._rng_seed,
                base=attack,
            )

        return self._report(seed_id, steps, StopReason.MAX_ITERATIONS)

    def _report(
        self,
        seed_id: str,
        steps: list[LoopStep],
        reason: StopReason,
        error: str | None = None,
    ) -> LoopReport:
        return LoopReport(
            seed_id=seed_id,
            rng_seed=self._rng_seed,
            max_iterations=self._max_iterations,
            steps=steps,
            stopped_reason=reason,
            error=error,
        )