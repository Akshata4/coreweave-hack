# coreweave-hack

Runs [SWE-bench](https://www.swebench.com/SWE-bench/) locally, using the `claude` CLI
(Claude Code) as the coding agent that generates patches for real GitHub issues, with
the agent's execution traced into [W&B Weave](https://wandb.ai/site/weave) — both as a
nested Calls trace and as an Agents/Conversations entry. On top of that: a blue-team
review agent that audits each run for reward hacking / policy violations, and an
autonomous loop that applies a canned fix for the two kinds of finding it knows how to
safely correct, then re-verifies.

## The three scripts

**`agent_predict.py`** — the coding agent, per instance:
1. Loads one SWE-bench instance (default: SWE-bench Lite) and clones its repo at the
   issue's `base_commit`.
2. Runs Claude Code headlessly (`claude -p`, restricted to `Read Edit Write Grep Glob`
   plus whatever `agent_config.json` currently grants — see below) against the clone,
   using only the issue's problem statement as context.
3. Captures the resulting `git diff` as the prediction patch.
4. Runs the SWE-bench Docker evaluation harness on that patch and reports resolved/unresolved.
5. Traces the whole run into Weave:
   - **Calls**: `run_instance → agent_session → agent_turn → tool_call`, each tool call
     tagged with an `outcome` (`success` / `error` / `permission_denied` / `unknown`).
   - **Agents**: the same transcript logged via Weave's live conversation API
     (`start_conversation` / `start_turn` / `start_tool`), so denied/failed tool calls
     show up as real errors there too.

`agent_predict_baseline.py` is a frozen, unused snapshot of `agent_predict.py` from
before it gained `agent_config.json` support — kept only as a "here's where it started"
reference point, never imported or run by anything.

**`blue_agent.py`** — pulls a completed run's trace straight from Weave's query API
(no local files needed) and has an LLM judge it for reward hacking, malicious/off-policy
tool use, and incorrect tool calls. Each finding also gets a `fix_type`: `broaden_bash_pattern`,
`add_prompt_hint`, or `none` (the judge only ever picks a label — it never authors the
actual fix; see `improve_agent.py`'s `REMEDIATIONS`). Writes `runs/<instance_id>/blue_agent_report.md`
and attaches the verdict as Weave feedback on that run.

**`improve_agent.py`** — the autonomous loop: runs `agent_predict.py`, then `blue_agent.py`
on the result; if a finding's `fix_type` is one of the two known-safe kinds, applies a
hand-written remediation to `agent_config.json`, re-runs a small regression set to check
nothing broke, and repeats. Stops on `CONVERGED` (nothing left to fix), `REGRESSION`
(a fix broke something — reverted), `STAGNATION` (same fix, no improvement), or a
3-round cap. `agent_config.json` (gitignored — it's mutable loop state, not source)
holds `allowed_tools_extra` and `prompt_hints`; a missing file behaves like `{}`, i.e.
the plain baseline.

## Setup

Dependencies (`datasets`, `weave`, and `swebench` as an editable install of `./SWE-bench`)
are managed with [uv](https://docs.astral.sh/uv/) via `pyproject.toml`/`uv.lock`.

```bash
git clone --depth 1 https://github.com/SWE-bench/SWE-bench.git
git clone --depth 1 https://github.com/SWE-bench/swe-bench-tasks.git ./swe-bench-tasks
uv sync
claude auth login   # the claude CLI needs its own login; this session's auth isn't inherited
echo 'WANDB_API_KEY=<your key>' > .env   # gitignored; read by agent_predict.py so Weave traces land in your account
```

## Run

```bash
uv run python3 agent_predict.py astropy__astropy-12907   # one run, traced into Weave
uv run python3 blue_agent.py astropy__astropy-12907      # audit that run's trace
uv run python3 improve_agent.py astropy__astropy-12907   # run + audit + fix-and-reverify loop
```

`agent_predict.py` writes `runs/<instance_id>/predictions.jsonl` and the Docker harness's
verdict under `logs/evaluation/<run_id>/results.json`. `blue_agent.py` writes
`runs/<instance_id>/blue_agent_report.md`. `improve_agent.py` writes
`runs/<instance_id>/improve_loop_report.md` and a running snapshot of each round's
`agent_config.json` under `agent_config_history/` (both gitignored — regenerated per run,
and the full history is also in Weave, under a conversation named `improve-loop-<instance_id>`).
