# Provider Adapters

WIENER's security boundary does not depend on which model produced the SOC
proposal. This document is the contract an adapter implements, and the
procedure for adding one. It is deliberately specific so that adding a
provider is a bounded task rather than a redesign.

## The contract

One class, one method, one return type.

```python
class MyProvider:
    name = "my_provider"          # the ADAPTER name, never a model id

    def complete(self, system: str, user: str) -> LLMResponse: ...
```

`LLMResponse` (`app/llm/base.py`) is the single normalized structure every
provider returns:

```python
LLMResponse(text=<generation>, provider=<adapter name>, meta={...})
```

Raise `ProviderUnavailable(message, kind=...)` on any provider-level failure.
`kind` is what the failover ladder reacts to, so it must be one of the
normalized values — never a provider-specific exception class:

| `kind` | Meaning | Ladder behaviour |
| --- | --- | --- |
| `timeout` | request timed out | transient → demote |
| `connection` | could not connect | transient → demote |
| `auth` | credentials rejected (401/403) | transient → demote, cloud cooldown |
| `unavailable` | any other provider-level failure (5xx, rate limit) | transient → demote |
| `malformed` | response unparseable, or no JSON object | **not** an outage: retry, then surface |
| `replay_missing` | strict replay found no recording | fail loudly |
| `no_provider` | no tier could serve the request | fail loudly |

`malformed` is deliberately not a tier-down trigger. A model that answers with
prose is a model-behaviour problem; treating it as an outage would silently
downgrade a working provider because of one bad completion.

## Model identity

`app/llm/identity.py` holds the four facts apart. Fill them in honestly; do not
collapse them.

| Field | Source |
| --- | --- |
| `provider` | which service you addressed (provenance only, never routing) |
| `adapter` | your adapter's `name` |
| `requested_model` | the id you sent |
| `provider_reported_model` | the id the provider says it served, or `None` |

`ProviderIdentity.model_identity_reliable` is `false` — and invariant `I-13b`
**fails the evidence lock** — when:

1. the provider reported nothing;
2. what it reported is a transport name, not a model id; or
3. the provider reported a *different* id than requested, meaning it rewrites
   ids and neither value identifies the backing model.

Case 3 is not hypothetical. The development gateway was observed answering
a request for `oc/big-pickle` with `"model": "big-pickle"`, while advertising
111 models of which none completed a request. To be precise about what that
does and does not show: **the request identifies the served model as
`big-pickle`, and OpenCode publicly lists `big-pickle` as an OpenCode Zen
model. The gateway provides no independent evidence of the backing model
behind that route.** That is a statement about identifiability, not an
accusation that the model is anything other than what the provider
advertises — and it is why the run is blocked from locking rather than
silently accepted.

## Registering the adapter

1. Implement the class in `app/llm/`.
2. Add a branch to `build_cloud_provider()` in `app/llm/factory.py`, keyed on
   `WIENER_CLOUD_ADAPTER`, raising `ProviderUnavailable` with a clear message
   for an unknown value. Do **not** silently fall back.
3. Add its settings to `app/config.py` (environment variables only; never
   hardcode a key, a personal endpoint or an account) and document them in
   `.env.example`.
4. Test the full failure matrix (below) in `tests/test_provider_agnostic.py`.
5. Add it to the provider table in `README.md` — **only once it is tested**.

The tier, the ladder order and the evidence schema need no changes. A new
adapter is a new value of an existing configuration key.

## Required test matrix

Every adapter must be exercised against all of these. They are the cases that
actually break in production.

| # | Case | Expectation |
| --- | --- | --- |
| 1 | valid response | normalized `LLMResponse`, correct `text` |
| 2 | malformed response | `ProviderUnavailable(kind="malformed")`, never a silent pass |
| 3 | timeout | `kind="timeout"` |
| 4 | authentication failure | `kind="auth"` (401 **and** 403) |
| 5 | provider error (5xx) | `kind="unavailable"` |
| 6 | model not found (404) | `kind="unavailable"`, message names the model |
| 7 | structured-output validation | JSON extracted or `malformed` |
| 8 | metadata extraction | `provider_reported_model` populated or explicitly `None` |
| 9 | provenance recording | the four identity fields present in `meta` |
| 10 | policy/executor path | the pipeline reaches the same verdict as every other adapter |

Case 10 is the one that matters most. The suite already asserts that an
OpenAI-shaped adapter and a native Anthropic adapter produce an **identical**
risk score, decision, constraint set and execution outcome for the same input
and the same model output. A new adapter joins that comparison:

```python
def test_security_verdict_is_identical_across_providers():
    ...
```

A security-path module must also never gain a provider-name conditional. That
is asserted structurally by
`test_security_path_contains_no_provider_conditionals`, so provider-specific
branching cannot be introduced into the enforcement path by accident.

## Currently implemented

| `WIENER_CLOUD_ADAPTER` | Wire format | Covers |
| --- | --- | --- |
| `openai_compatible` (default) | `POST {base_url}/chat/completions` | OpenAI and any OpenAI-compatible gateway: 9Router, OpenCode, Groq, OpenRouter, and others, by changing base URL, key and model only. |
| `anthropic` | `POST {base_url}/v1/messages` | Anthropic native Messages API. |

Not implemented, and therefore not claimed: a native Gemini adapter. Gemini can
be reached through any OpenAI-compatible gateway, or by adding an adapter
behind this contract.

The rule this repository follows: **an untested adapter is not claimed.** The
provider table in the README lists only what the suite exercises.
