# Ollama primary and OpenAI fallback

The autonomous CLI uses native Ollama `POST https://ollama.com/api/chat` with
the requested model `deepseek-v4.1-flash`. OpenAI is an optional fallback using
`POST https://api.openai.com/v1/chat/completions`. The model proposes tools;
every tool call still passes through the authenticated security gateway.

## Add your Ollama key

Create an owner-only `auth/.env.models` from `auth/model-endpoints.env.example`
if it does not already exist, then fill in `OLLAMA_API_KEY`. Preserve existing keys
when upgrading. Do not paste the key into chat or commit this file.
The non-secret template is `auth/model-endpoints.env.example`.

The primary settings are:

```dotenv
JEV_MODEL_PROTOCOL=ollama
JEV_MODEL_URL=https://ollama.com
JEV_MODEL_NAME=deepseek-v4.1-flash
OLLAMA_API_KEY=
```

The file is read only when selected with `--model-env-file`. Values are parsed
without shell evaluation or variable expansion. It must be a regular file
with owner-only permissions; the CLI refuses a symlink or a public file.
Credentials stay out of checkpoints, model messages, gateway payloads and
activity logs. Checkpoints store the local file reference and public provider
configuration so a resumed process can read the current key.

Check the model connection without calling any tool:

```bash
src/mvp/.venv/bin/python auth/check-model.py --config auth/.env.models
```

This sends only `Hello!` to the selected model and reports a safe success/error
code. Native requests use `stream: false` and `options.num_predict: 2048`.
The CLI accepts only a complete, bounded response. This check does not log in
to the gateway or execute a proposal.

## Run an autonomous agent

```bash
JEV_AUDIT_PATH=auth/.runtime/cli-audit.jsonl \
  src/mvp/.venv/bin/jev agent start \
  --prompt 'Summarize this public sample: Hello! This is a simple connection test.' \
  --tool summarize \
  --model-env-file auth/.env.models \
  --checkpoint auth/.runtime/llm-agent-state.json \
  --gateway-url http://127.0.0.1:8003 --login
```

Sign in as `jev-agent-dev` when the device code is shown. Only explicitly
selected tools are advertised to the model and granted to the agent. The API
on port 8003 continues to use MOCK executors, even though model generation
uses the configured provider.

To allow command proposals, explicitly add `--tool execute_command`. Every
command then pauses for review. Complete review and continue the conversation:

```bash
JEV_AUDIT_PATH=auth/.runtime/cli-audit.jsonl \
  src/mvp/.venv/bin/jev approvals review \
  --resume-checkpoint auth/.runtime/llm-agent-state.json --login
```

Caller and reviewer authenticate separately before explicit action
confirmation. The conversation retains model tool-call IDs and completed
results, so resuming does not replay earlier calls or regenerate the held
proposal. `jev agent resume PATH --login --renew-review` can reassess an
expired, unexecuted review under a new request ID. Unknown dispatch outcomes
require reconciliation; they cannot be automatically retried.

Each checkpoint has an OS lock to reject a concurrent CLI run. Context is
written atomically with file and directory synchronization before dispatch.
Prompts, tool results and saved model history are screened before being sent
to the model. Unsafe or oversized tool results are withheld in full. The
iteration budget persists across pauses.

## Verified local result

The approved public-sample test completed through live Keycloak authentication
and native Ollama `deepseek-v4.1-flash`: two model generations, one gateway
`EXECUTED` result for MOCK `summarize`, and a final model reply. The saved
checkpoint `auth/.runtime/ollama-public-demo-retry-state.json` is `complete`;
do not resume it to repeat the test. OAuth credentials were not persisted.
This verifies the model/gateway integration with mock execution. Real
Docker/gVisor execution and the OpenAI fallback have not been live-tested.

## Enable OpenAI later

OpenAI is currently a scaffold: the file has its URL, but its key and model
are empty. Ollama can operate while the fallback is unconfigured.

When OpenAI access is available:

1. Create a project API key through the [OpenAI API key settings](https://platform.openai.com/api-keys).
2. Add that key to `OPENAI_API_KEY` in the same private `auth/.env.models` file.
3. Set `JEV_FALLBACK_MODEL_NAME` to an available model that supports Chat
   Completions and function tools. Keep `JEV_FALLBACK_MODEL_URL=https://api.openai.com/v1`.
4. Run `auth/check-model.py` or resume the conversation. The current file is
   reread on each run; a checkpoint whose fallback model was initially empty
   can obtain the newly configured model from this file.

Each provider receives its own key. The Ollama key is never borrowed for
OpenAI, and a gateway token cannot be selected as a model credential.
OpenAI requests use `max_completion_tokens: 2048`.

Failover happens only on connection errors, timeouts, or server errors during
model generation. Authentication/request denial, rate limiting, malformed or
incomplete responses stop without trying another provider. Completed tool
calls are not replayed when model generation fails over. If Ollama is
unavailable and OpenAI is still unconfigured, the CLI stops with
`FALLBACK_CONFIGURATION_REQUIRED`; it does not submit an unauthenticated
OpenAI request.

Protocol references: [Ollama chat API](https://docs.ollama.com/api/chat),
[Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling),
[OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
