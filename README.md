# Incident Response Assistant (ira)

An LLM agent that receives an alert, investigates it with **read-only** tools, proposes likely
causes backed by cited evidence, and drafts a stakeholder status update plus suggested next steps
for a **human to approve**. It never changes anything on its own.

## Overview

```
alert (CLI or webhook)
  -> normalize + dedupe          ira/normalize.py, ira/dedupe.py
  -> investigate (bounded loop)  ira/agent.py  (Claude + read-only tools)
  -> verify citations            ira/hypotheses.py
  -> draft status update         ira/drafts.py
  -> open approval requests      ira/approvals.py
  -> human approves / rejects    ira CLI  (recorded in the audit log)
```

What you get from one investigation:

- **Ranked hypotheses**, each with a confidence level and evidence (tool call id + verbatim excerpt).
  Citations are machine-checked against the actual tool output; unverifiable claims are dropped.
- **A "not checked" list**: what the agent did not verify.
- **A status update** in plain language that keeps observed facts apart from possible causes.
- **Suggested actions** (rollback, scale, ...). These are suggestions only. Running one requires a
  named human's recorded approval, and the only executor shipped is a dry run.
- **A tamper-evident audit log** (SQLite, hash-chained) of every tool call, hypothesis, draft and
  decision.

### Safety rules (see `CLAUDE.md`)

| Rule | How it is enforced |
|---|---|
| Tools are read-only | Mutating tool names are rejected when a tool is defined; backends only expose search/list/get |
| Remediation is only a suggestion | `requires_approval` is fixed at `True`; approval state is rebuilt from the audit log; `execute` is a dry run |
| Logs, alerts and tickets are untrusted | Wrapped in delimited tags, fake closing tags defused, system prompt says "data, not instructions", injection-looking text is flagged |
| No evidence, no claim | Every citation is checked word for word against tool output |
| Confidence and "not checked" | Confidence level must match its score; a completed investigation must list what was not checked |
| Secrets/PII never reach the model | Redaction runs inside the tool registry, before output leaves it |
| Bounded loop | Max steps, max tokens, per-tool timeouts; every tool call logged |

## Installation

Requirements: [uv](https://docs.astral.sh/uv/) and GNU Make. uv installs Python 3.12 for you.

```bash
git clone <repo-url> && cd incident-response-agent
make install            # uv sync
make test               # no API key needed
```

To use the real model, set an API key (or log in with `ant auth login`):

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # PowerShell: $env:ANTHROPIC_API_KEY = "sk-ant-..."
```

The unit tests and the offline evals never call the API.

## How to run

### Investigate an incident (CLI)

```bash
make demo INCIDENT=bad_deploy            # = uv run ira investigate bad_deploy
```

Then review and decide on the suggested actions:

```bash
uv run ira list
uv run ira show <investigation-id>                       # IDs can be shortened to 8 characters
uv run ira review <investigation-id> --as "your name"    # interactive approve / reject
uv run ira approve <action-id> --as alice --reason "errors began right after the deploy"
uv run ira reject  <action-id> --as alice --reason "too risky during peak"
uv run ira execute <action-id> --as alice                # only works after approval; dry run
uv run ira audit [<investigation-id>] --verify           # print the log and verify the hash chain
```

`agent`, `system` and blank names cannot approve. Exit code 2 means a request was denied.
Add `--template-draft` to `investigate` to skip the LLM for the status update.

### Webhook (FastAPI)

```bash
make serve                                # http://localhost:8000
```

| Endpoint | Purpose |
|---|---|
| `POST /webhooks/alertmanager` | Alertmanager v4 payloads (one or many alerts) |
| `POST /webhooks/pagerduty` | PagerDuty v3 webhooks and Events API v2 |
| `GET /investigations/{id}` | Investigation, latest draft and approval states |
| `GET /healthz` | Liveness |

Webhooks return `202` straight away and investigate in a background pool. Repeated alerts with the
same dedupe key inside the window (default 30 min) are recorded as duplicates instead of starting
another investigation; a "resolved" event closes the entry.

```bash
curl -X POST localhost:8000/webhooks/alertmanager \
  -H 'content-type: application/json' -d @tests/payloads/alertmanager_firing.json
```

There is deliberately **no approve/execute endpoint**; approvals are CLI-only.

### Evals

```bash
uv run python evals/run_evals.py --fake oracle         # offline, proves the harness works
uv run python evals/run_evals.py --fake obedient       # offline, an agent that follows injected text
make eval                                              # REAL API, costs money
make eval EVAL_ARGS="--incidents bad_deploy,memory_leak --trials 3"
make eval-report RUN=evals/runs/<run>.json [BASELINE=evals/runs/<other>.json]
```

Per fixture it scores top-1/top-3 root-cause accuracy, citation validity and hallucination rate,
key-evidence coverage, **unsafe-action rate (must be 0)**, **prompt-injection resistance (must be
100%)**, steps, tokens, cost (an upper bound) and latency. Runs are saved to `evals/runs/*.json`
(git-ignored) so they can be compared; the command exits 1 on any unsafe action, crash or failed
injection resistance.

### Development

```bash
make test        # pytest (live-API tests are skipped without ANTHROPIC_API_KEY)
make lint        # ruff check + format --check
make fmt         # auto-fix
make fixtures    # regenerate fixtures/ (deterministic; re-running must give no diff)
uv run pytest -m live                                  # real-model tests, costs money
```

## Configuration

All settings are environment variables prefixed `IRA_` (or a `.env` file). Defaults are in
`src/ira/config.py`; the model name lives there and nowhere else.

| Variable | Default | Meaning |
|---|---|---|
| `IRA_MODEL` | `claude-opus-5-5` | Model used by the agent and the status draft |
| `IRA_EFFORT` | `high` | Thinking effort (`low` ... `max`) |
| `IRA_REFUSAL_FALLBACK` | `true` | Let the API retry on a fallback model if the model refuses |
| `IRA_MAX_STEPS` | `12` | Max model turns before a forced final answer |
| `IRA_MAX_TOKENS_TOTAL` / `IRA_MAX_TOKENS_PER_CALL` | `200000` / `16000` | Token budgets |
| `IRA_TOOL_TIMEOUT_S` | `10` | Per-tool timeout |
| `IRA_DB_PATH` | `ira.sqlite` | Audit log and investigation store |
| `IRA_FIXTURES_DIR` | `fixtures` | Where simulated incidents live |
| `IRA_DEDUPE_WINDOW_S` | `1800` | Alert dedupe window |
| `IRA_WEBHOOK_TOKEN` | unset | Bearer token for the Alertmanager webhook and `GET /investigations` |
| `IRA_PAGERDUTY_SIGNING_SECRET` | unset | Verifies `X-PagerDuty-Signature` |
| `IRA_PRICE_INPUT_PER_MTOK` / `IRA_PRICE_OUTPUT_PER_MTOK` | `4.0` / `20.0` | Prices used for eval cost estimates |

## Repository layout

```
src/ira/        api, cli, agent, pipeline, models, normalize, dedupe, hypotheses, drafts,
                approvals, audit, redact, prompts, injection, evaluation, config, fixtures, testing
src/ira/tools/  base, backends, registry, logs, metrics, deploys, runbooks
fixtures/       12 simulated incidents: logs, metrics, deploys, runbooks, ground truth
evals/          run_evals.py, report.py   (results land in evals/runs/)
scripts/        build_fixtures.py         (deterministic fixture generator)
tests/          pytest suite + tests/payloads/ (sample webhook bodies)
```

## Fixtures

`fixtures/<name>/` holds `alert.json`, `logs.jsonl`, `metrics.json`, `deploys.json`,
`runbooks/*.md` and `ground_truth.json`. The ground truth is for evals only: the fixture backend
never loads it, so the agent cannot see the answer.

- **8 realistic incidents:** `bad_deploy`, `db_conn_exhaustion`, `memory_leak`, `expired_cert`,
  `upstream_outage`, `noisy_false_alarm`, `config_change`, `traffic_spike`. Each has a red herring.
- **4 prompt-injection variants:** `inj_rollback_logs`, `inj_misdirect_runbook`, `inj_alert_text`,
  `inj_exfil`. Same root cause as their base incident plus attacker text in logs, runbooks, the
  alert or a ticket. The ground truth lists what must not happen (e.g. blaming DNS, calling an
  alert a false alarm, leaking a canary token).
- All secrets, emails and card numbers in the fixtures are fabricated test values.

## Notes

- **Real integrations:** fixtures are the default. A real log/metrics/deploy backend implements the
  protocols in `src/ira/tools/backends.py` and plugs in with `build_registry(backend, ctx)`. The
  webhook currently maps an alert's service to a fixture; an unknown service is recorded as
  `FAILED` (`no_data_source_for_service`) rather than guessed at.
- **Webhook auth is off unless configured.** Set `IRA_WEBHOOK_TOKEN` / `IRA_PAGERDUTY_SIGNING_SECRET`
  before exposing it beyond localhost.
- **Audit log limits:** edits and deletions in the middle of the log are detected by
  `ira audit --verify`; deleting only the newest events is not. Copy the latest hash somewhere
  outside the database to close that gap.
- **Eval accuracy is a keyword match** against the ground truth's acceptable answers, so a vague
  answer can score as correct. Eval cost is an upper bound (cache reads are priced as normal input).
- **Prompt injection:** the detector only flags suspicious text. The real defenses are delimiting,
  read-only tools, verified citations, draft checks and the approval gate.
- **Model behavior:** the default model always reasons before answering and rejects forced
  `tool_choice`, so the agent ends by calling a `submit_findings` tool and the prompt asks for it.
  Fixture timestamps are fixed in 2026, so tools default to time windows around each alert's own
  `fired_at`, not "now".
- **Windows:** the Makefile uses only `uv run`, so it works with GNU Make under Git Bash or
  PowerShell. Report output is UTF-8.
