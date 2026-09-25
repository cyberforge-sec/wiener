# WIENER Data Contracts

> Status: current repository snapshot — **September 2026**

Canonical contracts live in **`app/models.py`** (pydantic v2, Python 3.14).
These are the only canonical definitions — do not create competing versions.

## Decision

```python
class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
```

## Action

```python
class Action(str, Enum):
    GET_LOGS = "get_logs"              # read-only
    SEARCH_IOC = "search_ioc"          # read-only
    CHECK_ENDPOINT = "check_endpoint"  # read-only, safe default
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_USER = "disable_user"
    BLOCK_IP = "block_ip"
```

## BlueRoute

```python
class BlueRoute(str, Enum):
    DETERMINISTIC = "deterministic"
    QWEN = "qwen"
    FALLBACK = "fallback"
```

Backward-compatible alias: `Route = BlueRoute`.

## AgentEvent — input

| Field | Type | Notes |
|---|---|---|
| `event_id` | `str` | unique id |
| `timestamp` | `str` | ISO-ish string |
| `source` | `str` | e.g. `ids`, `siem_sim`, `user_report` |
| `event_type` | `str` | e.g. `alert`, `log`, `anomaly` |
| `severity` | `int` 0–10 | validation enforced |
| `detail` | `str` | free text |
| `raw_payload` | `dict[str, Any]` | optional extras |

## SOCContext — input

| Field | Type | Notes |
|---|---|---|
| `alert_id` | `str` | |
| `events` | `list[AgentEvent]` | |
| `provenance` | `str` | raw source/provenance — EVIDENCE, not a security score |
| `environment` | `str` | default `simulated` |
| `notes` | `str` | |

## SOCOutput — SOC Agent output

| Field | Type | Notes |
|---|---|---|
| `action` | `Action` | canonical enum, validated |
| `target` | `str \| None` | target identifier |
| `confidence` | `float` 0–1 | validation enforced |
| `reasoning` | `str` | optional |

SOCOutput is a **proposal** — it never carries a final decision, risk_score, or PolicyDecision.

## Trajectory

| Field | Type | Notes |
|---|---|---|
| `trial_id` | `str` | trial identifier |
| `context` | `SOCContext` | |
| `agent_history` | `list[AgentEvent]` | events seen by the agent |
| `proposed_action` | `SOCOutput` | |
| `provider_used` | `str` | e.g. `opencode`, `local`, `replay`, `degraded` |
| `metadata` | `dict[str, Any]` | reserved |

Trajectory is the canonical object passed to Blue AI. It must preserve enough for: Blue AI,
Logger, Dashboard, Metrics, Replay.

## BlueAssessment

| Field | Type | Notes |
|---|---|---|
| `context_trust` | `int` 0–100 | validation enforced |
| `behavior_deviation` | `int` 0–100 | validation enforced |
| `action_criticality` | `int` 0–100 | validation enforced — intrinsic, not LLM-rewritable |
| `privilege_impact` | `int` 0–100 | validation enforced — intrinsic |
| `evidence_tags` | `list[str]` | controlled tags |
| `route` | `BlueRoute` | deterministic \| qwen \| fallback |

## RiskResult

| Field | Type | Notes |
|---|---|---|
| `risk_score` | `float` 0–1 | deterministic |
| `triggered_constraints` | `list[str]` | constraint IDs |
| `required_decision` | `Decision \| None` | only set when a hard constraint matched |

## PolicyDecision — final output

| Field | Type | Notes |
|---|---|---|
| `decision` | `Decision` | ALLOW / REVIEW / BLOCK |
| `reason_tags` | `list[str]` | e.g. `hard_constraint_block`, `threshold_review` |
| `constraint_ids` | `list[str]` | matched constraints, if any |

## YAML data files

- **`config/action_metadata.yaml`** — intrinsic static properties per action:
  `action_criticality`, `privilege_impact`, `description`.
- **`config/safety_constraints.yaml`** — constraints with the locked schema:
  `id`, `action`, `context_trust`, `behavior_deviation`, `action_criticality`,
  `privilege_impact`, `required_decision`, `reason_tag`.

Constraint precedence: **BLOCK > REVIEW > ALLOW**.
`required_decision` is populated in `RiskResult` **only** when a hard constraint matches;
otherwise `None`.

## Evidence tags emitted by Blue AI (controlled set)

`low_context_trust`, `high_context_trust`, `high_deviation`, `low_deviation`,
`critical_action`, `benign_action`, `high_privilege_impact`, `low_privilege_impact`,
`conflicting_evidence`, `malformed_trajectory`, `qwen_unavailable`.

## API contract

- `POST /analyze` — body is `SOCContext`; response contains `trajectory`, `soc_output`,
  `assessment`, `risk`, `decision`, `soc_provider`.
- `GET /health` — `{"status", "provider"}`.