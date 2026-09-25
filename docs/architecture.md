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

`app/llm/factory.py` resolves the downward ladder `cloud → local → replay`.

The cloud tier is an **adapter behind a common contract**, not a vendor. Two
adapters are implemented and tested:

- `OpenAICompatibleProvider` (`app/llm/openai_compatible.py`) targets the
  de-facto standard `POST {base_url}/chat/completions` shape, so one adapter
  covers OpenAI and any OpenAI-compatible gateway.
- `AnthropicProvider` (`app/llm/anthropic_provider.py`) targets the native
  Messages API: `system` is a top-level parameter, auth is `x-api-key` plus a
  version header, the response is a list of typed content blocks, and there is
  no `response_format` parameter. All of that translation stays inside the
  adapter.

`WIENER_CLOUD_ADAPTER` selects between them. `LocalProvider` calls a
user-configured Ollama endpoint (preferring `/api/chat` so the system prompt
keeps instruction priority) and `ReplayProvider` reads hash-keyed recorded
responses. Ollama is the only directly implemented local runtime in this
release; cloud and replay do not require it. No credential is ever hardcoded.

**The security path is provider-blind.** Trajectory, Blue AI, Risk Engine,
Policy Gate and the Tool Executor contain no provider-name conditionals, and
`tests/test_provider_agnostic.py` asserts that structurally as well as
behaviourally: the same untrusted input and the same model output delivered
over two different wire formats produce an identical risk score, decision,
constraint set and execution outcome. Replacing the provider cannot create a
new execution path.

### Model identity is recorded, not inferred

`app/llm/identity.py` keeps four facts apart, because collapsing any two of
them produces a claim the artifact cannot support:

| Field | Meaning |
| --- | --- |
| `provider` | the service addressed (provenance only, never routing) |
| `adapter` | which adapter class spoke to it |
| `requested_model` | the model id we asked for |
| `provider_reported_model` | the model id the provider says it served |

Gateways routinely rewrite the third into the fourth, and frequently report
nothing. When nothing is reported, `model_identity_reliable` is false and the
reason travels with the record; a missing identity is never filled in from the
adapter name. Invariant `I-13b` independently rejects a transport name in a
model field.

If a tier is unavailable, the next tier is tried; Judge Mode uses strict replay
so a missing recording fails loudly rather than fabricating a live-looking
answer.

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
