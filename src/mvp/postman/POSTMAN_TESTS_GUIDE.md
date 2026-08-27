# Postman API Test Guide (Separated JSON Requests)

This folder contains one JSON request file per test case.

Base URL used in all files:

- `{{baseUrl}}` -> `http://localhost:8000`

## Files and Intended Endpoint Coverage

1. `01-health.json` -> `GET /health`
2. `02-tools.json` -> `GET /tools`
3. `03-validate-urls-allowed-domain.json` -> `POST /validate-urls`
4. `04-pipeline-benign-summarize.json` -> `POST /pipeline`
5. `05-pipeline-write-note.json` -> `POST /pipeline`
6. `06-pipeline-search-notes.json` -> `POST /pipeline`
7. `07-pipeline-fetch-url-allowed-domain.json` -> `POST /pipeline`
8. `08-pipeline-fetch-url-blocked-private-ip.json` -> `POST /pipeline`
9. `09-pipeline-malicious-content-block.json` -> `POST /pipeline`
10. `10-pipeline-execute-command-queue-for-approval.json` -> `POST /pipeline`
11. `11-list-pending-approvals.json` -> `GET /pending`
12. `12-approve-execute-command.json` -> `POST /approve/{{approvalRequestId}}`
13. `13-replay-execute-command-after-approval.json` -> `POST /pipeline`
14. `14-reject-candidate-injection-attempt.json` -> `POST /pipeline`
15. `15-reject-request.json` -> `POST /reject/{{rejectRequestId}}`
16. `16-audit-history.json` -> `GET /history?limit=20`
17. `17-policy-stats.json` -> `GET /policy/stats`

## How to Run Each in Postman

For each JSON file:

1. Open the file and copy `method`, `url`, headers, and `body`.
2. Create a new request in Postman.
3. Set method and URL exactly as shown.
4. Add header: `Content-Type: application/json`.
5. If `body` is not null: set Body -> raw -> JSON and paste it.
6. Send request and validate using the `expected` section in the file.

## Required Order (for workflow dependencies)

Run in this order:

- 01 -> 09 (independent checks)
- 10 -> 11 -> 12 -> 13 (execute approval workflow)
- 14 -> 15 (reject workflow)
- 16 -> 17 (observability endpoints)

## Execute Command Flow (Important)

This is the full flow from README examples and must be done in sequence.

### Step A: Queue execute request

Use `10-pipeline-execute-command-queue-for-approval.json`.

Expected:

- HTTP 200
- `gateway.gateway_decision = "DENIED"`
- reason indicates request is queued for approval

### Step B: List pending

Use `11-list-pending-approvals.json`.

Expected:

- HTTP 200
- pending list includes `exec-demo-001`

### Step C: Approve

Use `12-approve-execute-command.json`.

Before send:

- Set `approvalRequestId` to `exec-demo-001` in URL variable position.
- Or directly replace `{{approvalRequestId}}` with `exec-demo-001`.

Expected:

- HTTP 200
- approval response indicates approved

### Step D: Replay same request_id

Use `13-replay-execute-command-after-approval.json`.

Expected:

- HTTP 200
- `gateway.gateway_decision = "EXECUTED"`
- command output present in `gateway.tool_output`

Note:

- You must replay with the exact same `request_id` used in Step A.

## Reject Flow

### Step A: Create rejection candidate

Use `14-reject-candidate-injection-attempt.json`.

Expected:

- HTTP 200
- policy should require approval in most runs

### Step B: Reject that request

Use `15-reject-request.json`.

Before send:

- Set `rejectRequestId` to `reject-demo-001` in URL variable position.

Expected:

- HTTP 200
- status indicates rejected

## Tips

- Keep request IDs unique if you rerun many times (for example add a timestamp suffix).
- If a request was already resolved, approve/reject may return not found depending on state.
- For gVisor verification, run execute flow and then check tool-runner logs for `runtime=runsc`.
