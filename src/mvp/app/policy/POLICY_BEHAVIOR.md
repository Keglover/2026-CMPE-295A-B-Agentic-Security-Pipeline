# Policy Behavior Notes (Current + Future)

## Current merged behavior (May 2026)

- Core policy action is determined only by `app/policy/engine.py` based on risk score/categories.
- Tool-stage URL/domain checks run separately from the policy engine.
- If a tool request includes URL args and any hostname is:
  - private/internal IP space, or
  - not on allowlist and not user-approved,
  then the pipeline currently enforces a hard `BLOCK` before tool execution.
- This hard block is an execution-safety override and does not modify policy-engine rules.

## Why this split exists

- Keeps risk-policy logic stable for ongoing teammate work.
- Allows tool-execution protections (SSRF/allowlist/user approvals) to evolve independently.

## Candidate future expansions

- Option A: convert unapproved public domains from hard `BLOCK` to `REQUIRE_APPROVAL`.
- Option B: add tool-specific domain policies (strict for `fetch_url`, relaxed for read-only media tools).
- Option C: add persistent user/domain approval scopes with expiry and audit trail.
- Option D: classify domain outcomes as policy metadata instead of overriding `policy_action`.

## Non-goals in current patch

- No changes to threshold mapping in `app/policy/engine.py`.
- No changes to risk scoring logic.
