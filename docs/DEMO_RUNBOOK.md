# WIENER — Competition-Day Runbook

> Use the root README for current setup. This runbook is operational guidance;
> cloud endpoint/model choices are supplied by the presenter, never bundled.

One-laptop execution guide (Intel Core i5-1335U, 16 GB RAM, Iris Xe).
Goal: stable demo, minimal latency variance, no surprise processes.

## 0. Pre-flight checklist (30 min before demo)

- [ ] Wireless on; verify the cloud gateway is reachable **and fast**:
      ```bash
      python3 benchmarks/bench_demo.py --runs 3 --no-local --report /tmp/preflight.md
      ```
      OK if `status: ok` and median SOC latency < ~5 s. If it times out,
      the demo still works — it will ride the local Qwen rung (keep it warm,
      see step 2). Never block the demo on the cloud.
- [ ] Cloud pre-flight GAGAL → **jangan menunda demo.** Ladder turun otomatis
      `opencode → local → replay`: Qwen hangat tetap jalan (langkah 2), replay
      deterministik tetap bisa menampilkan hasil instan. Semua langkah 1–3
      tetap berjalan tanpa cloud.
- [ ] Close every non-essential browser tab. The dashboard is served locally;
      one tab is enough. (Large open tab counts measurably hurt an i5's
      shared caches.)
- [ ] Stop duplicate model/LLM processes. Exactly **one** `ollama serve` may run:
      ```bash
      pgrep -a ollama          # expect 1 serve (+ its runner children)
      # Optional: inspect the cloud client/service used by your own provider.
      ```
- [ ] RAM headroom: ensure ~3 GB free before model load.
      ```bash
      free -h
      ```

## 2. Keep Qwen warm (default on after first call)

Cold-loading Qwen2.5 1.5B costs **~7.7 s**; a warm call is **~1.6 s** on the
dev host. Do one warm-up inference before the audience sits down:

```bash
curl -s http://localhost:11434/api/generate \
  -d '{"model":"qwen2.5:1.5b","prompt":"reply OK","stream":false,"keep_alive":"5m"}'
```

`WIENER_LOCAL_KEEP_ALIVE` (default `5m`, seconds or `"30m"` string) keeps the
model resident between scenarios. For a long block of local-only scenarios,
set `WIENER_LOCAL_KEEP_ALIVE=30m`.

Jika pre-flight cloud gagal, Qwen adalah rung utama — pastikan hangat sebelum
audiens duduk; replay tetap jadi safety net deterministik (instan) jika Qwen
ikut gagal.

## 3. Strictly sequential inference (default) — do not "help"

- The pipeline already makes **sequential** LLM calls (one SOC call per run, a
  Blue-AI call only on ambiguity) and Red Loop runs **sequential** 3-iteration
  chains. Do not open a second terminal to "speed up" anything — that spawns a
  second inference process and doubles memory pressure on the Iris Xe box.
- Do not run the harness and the live demo at the same time.

## 4. Demo sequence (worst-case budget on dev-host numbers)

| scenario | primary rung | budget |
|---|---|---|
| normal → ALLOW | cloud | ~1.4 s (or ~1.6 s local) |
| prompt injection | cloud | ~1.4 s |
| adaptive (3 iters) | **replay REPLAY-003 (instan, deterministik)** — live local (~5 s) hanya jika ingin tunjukkan adaptasi nyata | <1 ms / ~5 s |
| replay mode | none | <1 ms |

If a cloud call stalls near the timeout, the ladder fails **downward only**
(opencode → local → replay); the UI shows the actual rung (`REPLAY MODE`,
`not live inference`), so the audience always sees a truthful label and the
deterministic replay artifact renders instantly.

## 5. START / STOP

```bash
# terminal 1 (server)
uvicorn app.main:app --host 0.0.0.0 --port 8000
# terminal 2 (dashboard / judge demo)
#  ... one browser tab to http://localhost:8000
```

- Use `Ctrl+C` on the server for a clean shutdown; keep the single `ollama serve`
  running if more scenarios follow, stop it after the demo to free RAM.
- After a demo scenario, restart from the replay/judge view — no manual cleanup
  needed (trajectory + attacks are append-only JSONL, one record per trial).

## 6. If something glitches

- Cloud timeout → engine already fell back to local; say so, move on.
- Local timeout (60 s cap) → `ollama serve` died? Restart it, model reloads in
  ~8 s; restart the scenario.
- Dashboard/render error → replay artifact is deterministic; re-open the report.
- Never hot-fix code on stage. The demo path is deterministic-safe by design.
