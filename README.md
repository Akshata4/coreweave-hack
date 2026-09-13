# coreweave-hack

Runs [SWE-bench](https://www.swebench.com/SWE-bench/) locally, using the `claude` CLI
(Claude Code) as the coding agent that generates patches for real GitHub issues, with
the agent's execution traced into [W&B Weave](https://wandb.ai/site/weave) — both as a
nested Calls trace and as an Agents/Conversations entry.

## What `agent_predict.py` does, per instance

1. Loads one SWE-bench instance (default: SWE-bench Lite) and clones its repo at the
   issue's `base_commit`.
2. Runs Claude Code headlessly (`claude -p`, restricted to `Read Edit Write Grep Glob`)
   against the clone, using only the issue's problem statement as context.
3. Captures the resulting `git diff` as the prediction patch.
4. Runs the SWE-bench Docker evaluation harness on that patch and reports resolved/unresolved.
5. Traces the whole run into Weave:
   - **Calls**: `run_instance → agent_session → agent_turn → tool_call`, each tool call
     tagged with an `outcome` (`success` / `error` / `permission_denied` / `unknown`).
   - **Agents**: the same transcript logged via Weave's live conversation API
     (`start_conversation` / `start_turn` / `start_tool`), so denied/failed tool calls
     show up as real errors there too.

## Setup

Dependencies (`datasets`, `weave`, and `swebench` as an editable install of `./SWE-bench`)
are managed with [uv](https://docs.astral.sh/uv/) via `pyproject.toml`/`uv.lock`.

```bash
git clone --depth 1 https://github.com/SWE-bench/SWE-bench.git
git clone --depth 1 https://github.com/SWE-bench/swe-bench-tasks.git ./swe-bench-tasks
uv sync
claude auth login   # the claude CLI needs its own login; this session's auth isn't inherited
```

## Run

```bash
uv run python3 agent_predict.py astropy__astropy-12907
```

Writes `runs/<instance_id>/predictions.jsonl` and the Docker harness's verdict under
`logs/evaluation/<run_id>/results.json`.
