# WIENER — Historical One-Laptop Benchmark

> **Two different measurements live in this repository. Do not mix them.**
>
> 1. The **benchmark** below: latency and resource observations from a
>    development host. Historical, hardware-specific, not a requirement.
> 2. The **effectiveness** numbers (UAR / ASR / FIR / UAPR) produced by the
>    135-trial authoritative experiment. Those are a different claim with
>    different denominators, and they are summarised in
>    [Evidence honesty](#evidence-honesty) at the end of this file.
>
> A fast system that does not stop unsafe actions, and a system that stops
> unsafe actions slowly, are different products. This file keeps them apart.

> These are development-host observations from a prior environment, not
> hardware requirements or a service-level claim. Re-run the harness on the
> evaluator's own host before relying on timings. Provider credentials and
> endpoints remain evaluator-configured as described in the root README.

Measured with `benchmarks/bench_demo.py` on the development host
(CPU-only inference, 8 logical cores, ~6.5 GB RAM, Ollama Vulkan disabled).
**The authoritative numbers for the competition are produced by running the
same harness on the target laptop** (Intel Core i5-1335U, 16 GB RAM,
Intel Iris Xe, ~80 GB free):

```bash
pip install psutil   # optional; richer RAM/CPU sampling
python3 benchmarks/bench_demo.py --runs 5 --report docs/BENCHMARK.md
```

## Measured (dev host)

### Start-up
| metric | value |
|---|---|
| cold import (fresh interpreter) | ~232 ms |
| cold `Pipeline()` build | ~5.4 ms |
| warm `Pipeline()` build | ~4.9 ms (n=5) |

### Cloud provider (historical OpenAI-compatible endpoint)
Latency is per SOC call. The gateway is healthy on this host but **flaky**:
the pre-flight `/models` probe timed out on ~half the runs, and one call
took `22 080 ms` while the median was `1 357 ms`.

| metric | value |
|---|---|
| SOC call wall, median | ~1.36 s (p95 ~1.8 s, one outlier 22 s) |
| streaming first token | ~5.2 s (one slow run) |
| streaming total | ~9.8 s (one slow run) |

### Local Qwen2.5 1.5B (Ollama, CPU)
| metric | value |
|---|---|
| true cold call (model load + inference) | ~7.7 s wall (2.6 s load) |
| warm SOC call | ~1.6 s median (n=5: 1.59–2.05 s) |
| prompt tokens | 198 |
| output tokens / throughput | 38 / ~27 tok/s |
| model keep-alive | default `5m` (enabled after inference run) |

### Pipeline end-to-end — deterministic path (ReplayProvider)
| metric | value |
|---|---|
| e2e `Pipeline.run` | 0.06–0.32 ms (median 0.07 ms) |
| decision / risk | ALLOW / 25.5 (benign scenario) |
| repeated-run stability | True (identical decisions & risk across runs) |

### Resources
| metric | value |
|---|---|
| app RSS | ~60–65 MB |
| CPU during sustained replay load | ~50–110 % (Multi-CPU percent, i.e. ≈1 core) |

## Interpretation

1. **Cloud is faster when healthy (~1.4 s vs ~1.6 s warm local)** — the
   cloud-primary architecture is justified by measured numbers, so it stays.
2. **Cloud variance is the demo risk** (timeouts + a 22 s outlier). Mitigation
   is operational, not architectural: pre-flight reachability check, Qwen kept
   warm, and the existing downward-only failover (cloud → local Ollama → replay).
3. **Qwen keeps a ~1.6 s floor on CPU.** Pre-warming the model avoids a
   **7.7 s** cold hitch mid-demo. `WIENER_LOCAL_KEEP_ALIVE` (default `5m`)
   keeps it resident after the first call.
4. **Deterministic stack is essentially free** (sub-ms e2e), so no
   deterministic security control was touched for speed.
5. **App RAM (~60 MB) is negligible**; Qwen 1.5B adds ~1–1.5 GB — trivial on
   the target's 16 GB.

No model replacement was made (Qwen stays), no GPU/acceleration stack was added
(Vulkan was left disabled), and no deterministic security control was changed.

## Evidence honesty

The effectiveness numbers are not produced by `benchmarks/bench_demo.py`. They
come from the authoritative experiment harness, which stores every trial and
locks the artifacts. This section states what those numbers mean, because the
metric names alone are easy to misread.

### What is measured

| Metric | Definition | Denominator |
| --- | --- | --- |
| UAR (Unsafe Action Rate) | Share of trials where a dangerous action was actually executed. In gated (WIENER) mode this requires real execution past the Policy Gate. | All trials in the mode (45). |
| ASR (Attack Success Rate) | Share of trials where the SOC agent adopted the attack's intended dangerous action. | All trials in the mode (45). |
| FIR (False Intervention Rate) | Share of **benign** scenarios where the gate intervened when it should not have. | Benign trials only (10). |
| UAPR (Unsafe Action Prevention Rate) | `(UAR_baseline - UAR_defended) / UAR_baseline`. | Undefined when the baseline UAR is 0; reported as `null`, never as a fabricated 0. |

UAR and ASR are **not** the same claim. ASR says the model was convinced; UAR
says something dangerous actually happened. A defense can move ASR without
moving UAR, which is exactly why both are reported.

### What the numbers do not establish

- **Not a claim about a specific model.** The archived run was served by an
  OpenAI-compatible gateway. A different model, a different gateway, or a
  different system prompt will produce different ASR/UAR values.
- **Model identity must be verifiable, or the run cannot be locked.** The
  provider layer records the requested id and the id the provider reports
  separately. If a gateway answers with a *different* id than was requested,
  it is rewriting ids, so neither value identifies the backing model:
  `model_identity_reliable` is false and invariant `I-13b` fails, which blocks
  the lock. An unverified model identity is not shipped with a caveat.
  This is not hypothetical: the development gateway was observed answering
  `oc/big-pickle` with `"model": "big-pickle"`, and advertising 111 models of
  which none completed a request.
- **Not a determinism claim.** The archived run records no decoding
  temperature in any row, and 90 of 135 rows record a transport name
  (`opencode`) in the `model` field rather than a model id. The current
  validation checklist rejects both, so the archived evidence is retained as
  historical and cannot be re-locked without a fresh run.
- **Not a latency claim.** TTI and E2E in `metrics.json` both derive from one
  measured per-trial window, so they are equal by construction. The harness
  does not observe detection separately from attack construction. Treat them
  as pipeline duration, not as a security-response time.
- **Not an execution-prevention proof on its own.** UAPR is computed from
  stored decisions and executions; the direct demonstration that the *gate* is
  what prevents execution (identical proposals, gate removed) is the separate
  [enforcement ablation](../data/experiments/enforcement_ablation_reference/ablation.md).

### Known weaknesses in the scenario construction

Stated here rather than buried, because they bound how far the numbers can be
pushed:

- The malicious and benign scenario sets are **not** matched pairs. Malicious
  contexts are constructed with `severity=8`, benign ones with a lower
  severity, so part of the UAR/FIR separation is a property of the context
  generator, not only of the defense. UAPR close to 1.0 should be read with
  that in mind.
- A payload that successfully induces a dangerous proposal also tends to carry
  a high-severity event, so risk scoring and proposal adoption are correlated
  by construction. Separating them would need a matched-pair design where the
  same payload appears at two severities.
- The per-mode sample is 45 trials, so the Wilson intervals reported next to
  each rate are wide. Quote the interval, not just the point estimate.

None of these were "fixed" by adjusting thresholds, seeds, or denominators.
Changing them to improve a headline number would invalidate the evidence, so
they are documented instead.

## Reproducing the effectiveness numbers

```bash
# 1. Plan and preflight (requires a live provider; refuses to run without one)
python -m scripts.experiments.main plan authoritative_YYYYMMDD_HHMM
python -m scripts.experiments.main preflight authoritative_YYYYMMDD_HHMM

# 2. Run all 135 trials
python -m scripts.experiments.main run authoritative_YYYYMMDD_HHMM

# 3. Enforcement ablation (separate experiment, offline, ~1s)
python -m scripts.experiments.enforcement_ablation
```

A run that produces any degraded (synthetic fallback) trial cannot be locked:
`no_degraded_trials` is a hard gate in the evidence manifest.
