# WIENER Architecture

> Current source-aligned architecture. WIENER is a simulated/sandbox PoC.

## Runtime flow

```text
Red AI / input → SOC Agent → Trajectory → Blue AI → Risk Engine → Policy Gate → SimulatedToolExecutor
```

`Pipeline` in `app/orchestration/pipeline.py` owns this order. The SOC Agent
only proposes a `SOCOutput`; it cannot return an authorization decision. Blue
AI produces an assessment, Risk Engine computes score/constraint matches, and
Policy Gate is the deterministic final authority. `SimulatedToolExecutor`
rechecks that authority and never touches real infrastructure.

## Provider layer

`app/llm/factory.py` resolves the downward ladder `opencode → local → replay`.
`OpenCodeProvider` calls a user-configured OpenAI-compatible cloud endpoint;
`LocalProvider` calls a user-configured Ollama `/api/generate` endpoint; and
`ReplayProvider` reads hash-keyed recorded responses. The cloud key is never
hardcoded. If a tier is unavailable, the next tier is tried; Judge Mode uses
strict replay so a missing recording fails loudly rather than fabricating a
live-looking answer.

## Implemented modules

```text
app/api/             FastAPI API and endpoints
app/judge/           interactive Judge Mode and SSE stream
app/red_ai/          seed loading, mutation, closed loop, attack logs
app/soc_agent/       action proposal and safe degradation
app/blue_ai/         trajectory feature extraction and ambiguity routing
app/risk_engine/     deterministic weighted risk and constraints
app/policy_gate/     deterministic ALLOW / REVIEW / BLOCK decision
app/tools/           simulation-only executor
app/replay/          recorded deterministic scenarios and CLI
app/experiment/      experiment runner and validation
app/dashboard/       stored-report dashboard
app/present/         curated-evidence presentation view
app/logger/          JSONL trajectory logging
```

The YAML files in `config/` provide action metadata, safety constraints, and
Red AI seeds. `app/models.py` is the canonical data-contract module.

## Safety and observability

`ALLOW` permits only a simulated result; `REVIEW` and `BLOCK` refuse simulated
execution. Optional JSONL logs and cloud diagnostics are runtime output and
are excluded from the public repository. The dashboard reads persisted
artifacts only; it does not run a pipeline or manufacture metrics.

## Non-goals

WIENER has no production SIEM connector, endpoint-isolation integration,
identity-management integration, firewall modification, or real operational
execution capability. Docker packages the FastAPI PoC only; it does not ship
credentials or LLM weights.
