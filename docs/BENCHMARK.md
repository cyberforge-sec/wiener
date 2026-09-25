# WIENER — Historical One-Laptop Benchmark

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
   warm, and the existing downward-only failover (opencode → local → replay).
3. **Qwen keeps a ~1.6 s floor on CPU.** Pre-warming the model avoids a
   **7.7 s** cold hitch mid-demo. `WIENER_LOCAL_KEEP_ALIVE` (default `5m`)
   keeps it resident after the first call.
4. **Deterministic stack is essentially free** (sub-ms e2e), so no
   deterministic security control was touched for speed.
5. **App RAM (~60 MB) is negligible**; Qwen 1.5B adds ~1–1.5 GB — trivial on
   the target's 16 GB.

No model replacement was made (Qwen stays), no GPU/acceleration stack was added
(Vulkan was left disabled), and no deterministic security control was changed.
