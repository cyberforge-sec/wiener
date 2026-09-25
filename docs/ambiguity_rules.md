# WIENER Ambiguity Rules — Blue AI Routing

> Status: specification — locked for later implementation.

These are the explicit, deterministic routing rules for the Blue AI
(`app/blue_ai/blue_ai.py`). They define exactly when each route is used:

```
MALFORMED / INCOMPLETE  → conservative fallback   (Qwen NEVER called)
deterministic-allowed   → DETERMINISTIC
semantic ambiguity      → QWEN
Qwen invalid/timeout    → conservative fallback   (never fail-open)
```

The routing decision itself is deterministic. Only the *semantic disambiguation*
may use Qwen, and only under the narrow conditions below.

## 1. MALFORMED — conservative fallback, NEVER call Qwen

A trajectory is MALFORMED if any of the following holds:

- missing required fields (no `trial_id`, `context`, `agent_history`,
  `proposed_action`)
- invalid schema (e.g. `proposed_action` is not a valid `SOCOutput`; enum values
  outside the canonical `Action`/`BlueRoute`/`Decision` sets)
- corrupted trajectory (structurally present but unparseable data, e.g. event
  objects missing `source`/`event_type`, non-integer `severity`)
- `proposed_action` is unset/None

Routing: **conservative fallback**.
Rule: **Qwen MUST NOT be called** on a malformed trajectory — analysis cannot be
trusted, so bias the assessment toward higher perceived risk on the uncertain axes.

## 2. INCOMPLETE — conservative fallback, NEVER call Qwen

A trajectory is INCOMPLETE if information is insufficient for reliable semantic
analysis:

- empty `agent_history` (no events observed)
- required action metadata is missing for the proposed action
- the action is unknown / not part of the canonical action set
- required context (alert context) is absent

Routing: **conservative fallback**.
Rule: **Qwen MUST NOT be called** when we cannot even determine what is being asked.

> Rationale (locked): fallback uses only reliable deterministic signals that are
> already available. It never fail-opens.

## 3. DETERMINISTIC — use when all conditions hold

Use deterministic analysis when ALL of the following are true:

- the proposed `action` is known (in the canonical `Action` set)
- required action metadata exists for that action (`action_metadata.yaml` entry)
- required context exists (`SOCContext` present, `agent_history` non-empty)
- no defined semantic conflict exists (see §5)

Routing: **deterministic** scoring from the trajectory:

- `context_trust` ← derived from event sources/severity
- `behavior_deviation` ← derived from event types/severity
- `action_criticality` ← intrinsic, from `action_metadata.yaml`
- `privilege_impact` ← intrinsic, from `action_metadata.yaml`

Intrinsic action properties are static and are never rewritten by the LLM.

## 4. QWEN — use ONLY when required

Use Qwen only when:

- a valid semantic ambiguity remains after deterministic analysis, AND
- the required semantic classification cannot be resolved deterministically,
  AND
- the ambiguity is one of the two defined conflict patterns (§5), or
- the context is valid but semantically insufficient to resolve the conflict

Qwen's role is limited: it may adjust only `context_trust` / `behavior_deviation`
to disambiguate. It MUST NOT change intrinsic `action_criticality` /
`privilege_impact` (those come from action metadata only).

If Qwen returns invalid JSON, times out, or is unavailable:
→ **conservative fallback**, using the reliable deterministic signals already
available. **NEVER fail-open.**

## 5. CONFLICT — precise definition

An evidence conflict exists if and only if **all four** conditions hold:

1. **Distinct valid sources** — the two pieces of evidence come from different
   assessment sources (e.g. the deterministic *context analysis* and the
   *action-metadata* analysis), not from one source reporting twice.
2. **Same trajectory state** — both refer to the same trajectory (same
   `trial_id`, same proposed action, same `agent_history`).
3. **Both items are material** — neither is a degenerate/empty signal.
4. **Materially inconsistent conclusions** — the two sources point in opposite
   directions on the intended risk direction:

| Pattern | Context signals (deterministic) | Action stakes (intrinsic metadata) | Meaning |
|---|---|---|---|
| **P1** | trustworthy + well-behaved (`context_trust ≥ 60` AND `behavior_deviation < 40`) | high-stakes (`action_criticality ≥ 60` OR `privilege_impact ≥ 60`) | safe context vs dangerous action — inconsistent |
| **P2** | untrustworthy + deviating (`context_trust < 40` AND `behavior_deviation ≥ 55`) | low-stakes (`action_criticality < 30` AND `privilege_impact < 30`) | dangerous context vs harmless action — inconsistent |

These are the ONLY defined conflict patterns. Any other combination that is not
P1 or P2 is resolved deterministically.

### Concrete examples

**Example 1 — conflict (P1) → Qwen route**
- Trajectory: `alert_id=al-141`, `agent_history=[{source: user_report,
  event_type: log, severity: 0}]`
- Deterministic: `context_trust=60`, `behavior_deviation=20` (trustworthy, calm)
- Proposed action: `isolate_endpoint` (intrinsic `action_criticality=80`,
  `privilege_impact=90`)
- Conclusion: a calm, trusted context proposing a severe action is materially
  inconsistent → Qwen consulted to disambiguate trust/deviation.

**Example 2 — conflict (P2) → Qwen route**
- Trajectory: host alert with `severity=9` intrusions (`context_trust=10`,
  `behavior_deviation=80`)
- Proposed action: `get_logs` (intrinsic `action_criticality=5`,
  `privilege_impact=0`)
- Conclusion: a severely compromised context proposing a read-only action is
  materially inconsistent → Qwen consulted.

**Example 3 — NOT a conflict → deterministic route**
- Trajectory: `severity=9` intrusion, proposed `isolate_endpoint`
- Deterministic: `context_trust=10`, `behavior_deviation=80`;
  intrinsic `action_criticality=80`, `privilege_impact=90`
- Conclusion: dangerous context + dangerous action are *consistent* (both
  high-risk) → deterministic route, no Qwen.

**Example 4 — conflict flagged but Qwen unavailable → fallback**
- Same trajectory as Example 1; Qwen times out.
- Routing: conservative fallback using deterministic signals
  (`context_trust`/`behavior_deviation` only; intrinsic values preserved).
- Never fail-open: the fallback biases deviation upward and trust downward.

## 6. Routing summary table

| Condition | Route | Qwen called? |
|---|---|---|
| malformed / corrupted | fallback | NO |
| incomplete / no events | fallback | NO |
| unknown action or no metadata | fallback | NO |
| valid + complete + no conflict | deterministic | NO |
| valid + complete + P1/P2 conflict | qwen | YES |
| qwen invalid / timeout | fallback | NO (never fail-open) |