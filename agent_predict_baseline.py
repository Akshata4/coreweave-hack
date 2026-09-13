#!/usr/bin/env python3
"""
FROZEN BASELINE SNAPSHOT — not imported or run by anything else in this repo.

This is the "basic coding agent" reference point for the improvement-loop demo
(improve_agent.py): a copy of agent_predict.py taken before it gained
agent_config.json support. Kept as-is on purpose so a demo can always show
"here's where it started" without needing to regenerate it. The live pipeline
lives in agent_predict.py — edit that one, not this one.

Generate a SWE-bench prediction by letting the local `claude` CLI (Claude Code)
fix a real GitHub issue inside a fresh clone of the target repo, run the
SWE-bench Docker eval harness on the resulting patch, and trace the whole
thing into Weave — on both surfaces Weave offers:

  - Traces (Calls): a nested @weave.op() call tree, one trace per instance:

        run_instance
        ├── agent_session                  the whole `claude -p` invocation
        │   ├── agent_turn (x N)           one per assistant turn
        │   │   └── tool_call (x N)        one per tool the agent invoked,
        │   │                              tagged outcome: success | error |
        │   │                              permission_denied | unknown
        │   └── (emits a matching Weave conversation — see below)
        └── run_eval                       the Docker harness verdict

  - Agents (Conversations): the same parsed turns/tool-calls, additionally
    logged via weave.log_conversation() so this run also shows up under the
    Agents tab, not just Traces. Both surfaces share `instance_id` as their
    grouping id (weave.thread() for Calls, conversation_id for Agents).

Nothing about tool permissions is changed here — Claude Code still runs with
`--allowedTools "Read Edit Write Grep Glob"` and `--permission-mode acceptEdits`,
exactly as before. This only adds tracing on top of the existing flow.

Usage:
    python agent_predict.py <instance_id> [--dataset SWE-bench/SWE-bench_Lite] [--split test]

Writes: runs/<instance_id>/predictions.jsonl   (SWE-bench predictions schema)
        runs/<instance_id>/repo/               (the working clone, left in place)
        runs/<instance_id>/claude_stream.jsonl (raw stream-json event log, written once —
                                                 the trace itself only gets the per-turn
                                                 breakdown, not the whole transcript again)
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import weave
from weave.conversation import Message, Usage

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
AKSHATA_ENV_FILE = ROOT / ".env"
WEAVE_PROJECT = "swebench-claude-code-tracing"
ALLOWED_TOOLS = (
    "Read Edit Write Grep Glob "
    "Bash(python -c *) Bash(python3 -c *) Bash(pytest *)"
)  # Bash scoped to verification-only prefixes; anything else (rm, sudo, curl, git push,
   # shell chaining, ...) still falls outside the allow-list and gets denied like before
MAX_OUTPUT_CHARS = 20_000  # keep individual trace payloads sane


def _load_akshata_wandb_key():
    """Read WANDB_API_KEY from this project's own .env so Weave traces land in Akshata's
    account. Kept local to this repo (not an unrelated folder) so it can't silently go
    stale if some other project gets logged into a different account."""
    if not AKSHATA_ENV_FILE.exists():
        sys.exit(f"expected Akshata's W&B key at {AKSHATA_ENV_FILE}, but it's missing")
    for line in AKSHATA_ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("WANDB_API_KEY="):
            key = line.split("=", 1)[1].strip().strip('"').strip("'")
            os.environ["WANDB_API_KEY"] = key
            return
    sys.exit(f"WANDB_API_KEY not found in {AKSHATA_ENV_FILE}")


def sh(cmd, cwd=None, check=True):
    print(f"+ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=cwd, check=check, text=True)


def _truncate(value):
    if isinstance(value, str) and len(value) > MAX_OUTPUT_CHARS:
        return value[:MAX_OUTPUT_CHARS] + f"... [truncated, {len(value)} chars total]"
    return value


# ---------------------------------------------------------------------------
# Weave-traced building blocks. Calling one @weave.op() function from inside
# another nests it as a child span — that's what builds the Calls hierarchy.
# ---------------------------------------------------------------------------

@weave.op()
def tool_call(turn_index: int, tool_index: int, name: str, input_data: dict, output, outcome: str) -> dict:
    """One tool invocation Claude Code made (Read/Edit/Write/Grep/Glob/Bash/...).

    outcome distinguishes an attempt from an actual execution — a permission
    denial is not a successful tool run, even though the op still returns
    normally either way.
    """
    return {"name": name, "input": input_data, "output": _truncate(output), "outcome": outcome}


@weave.op()
def agent_turn(turn_index: int, thinking: str, text: str, tool_uses: list, model: str, usage: dict) -> dict:
    """One assistant turn: its reasoning/text, every tool call it made, and the model/usage
    the stream already reports for it — no extra API calls needed to get this."""
    for i, tu in enumerate(tool_uses):
        tool_call(turn_index, i, tu["name"], tu["input"], tu["output"], tu["outcome"])
    return {
        "thinking": thinking,
        "text": text,
        "tools_used": [tu["name"] for tu in tool_uses],
        "model": model,
        "usage": usage,
    }


def _pair_tool_results(events):
    """tool_use id -> {"content", "is_error"} from the tool_result that later answered it."""
    results = {}
    for ev in events:
        if ev.get("type") != "user":
            continue
        for block in ev.get("message", {}).get("content", []):
            if block.get("type") == "tool_result":
                results[block["tool_use_id"]] = {
                    "content": block.get("content"),
                    "is_error": bool(block.get("is_error")),
                }
    return results


def _extract_turns(events, results_by_id, denied_ids):
    turns = []
    for ev in events:
        if ev.get("type") != "assistant":
            continue
        msg = ev["message"]
        content = msg["content"]
        thinking = next((b.get("thinking", "") for b in content if b["type"] == "thinking"), "")
        text = next((b.get("text", "") for b in content if b["type"] == "text"), "")
        tool_uses = []
        for b in content:
            if b["type"] != "tool_use":
                continue
            result_entry = results_by_id.get(b["id"])
            if b["id"] in denied_ids:
                outcome = "permission_denied"
            elif result_entry is None:
                outcome = "unknown"  # session ended before a result ever came back
            elif result_entry["is_error"]:
                outcome = "error"
            else:
                outcome = "success"
            tool_uses.append({
                "id": b["id"],
                "name": b["name"],
                "input": b["input"],
                "output": result_entry["content"] if result_entry else None,
                "outcome": outcome,
            })
        if thinking or text or tool_uses:
            turns.append({
                "thinking": thinking,
                "text": text,
                "tool_uses": tool_uses,
                "model": msg.get("model"),
                "usage": msg.get("usage"),
            })
    return turns


def _log_agent_conversation(instance_id: str, prompt: str, turns: list):
    """Emit the same parsed transcript via Weave's *live* conversation API so this run
    shows up under the Agents tab, alongside (not instead of) the Calls trace above.

    This uses start_conversation/start_turn/start_tool rather than the simpler batch
    log_conversation(): only a span that's actually been started (via __enter__) can
    call record_error(), and record_error() is what makes a denied/failed tool call
    count as a real OTel-level error — which is what the Agents dashboard's "Errors"
    tile reads. The batch API builds fully-formed objects with no live span to call
    record_error() on, so it can never populate that tile no matter what field you set.
    """
    with weave.start_conversation(agent_name="claude-code", conversation_id=instance_id):
        conversation = weave.get_current_conversation()
        for i, turn_data in enumerate(turns):
            usage = turn_data.get("usage") or {}
            with conversation.start_turn(
                user_message=prompt if i == 0 else "",
                model=turn_data.get("model") or "",
                agent_name="claude-code",
            ) as turn:
                if turn_data.get("model"):
                    with turn.start_llm(model=turn_data["model"], provider_name="anthropic") as llm:
                        llm.usage = Usage(
                            input_tokens=usage.get("input_tokens", 0),
                            output_tokens=usage.get("output_tokens", 0),
                            cache_creation_input_tokens=usage.get("cache_creation_input_tokens", 0),
                            cache_read_input_tokens=usage.get("cache_read_input_tokens", 0),
                        )
                for tu in turn_data["tool_uses"]:
                    with turn.start_tool(
                        name=tu["name"], arguments=tu["input"], tool_call_id=tu["id"],
                    ) as tool:
                        tool.tool_type = tu["outcome"]
                        tool.result = _truncate(tu["output"]) or ""
                        if tu["outcome"] != "success":
                            tool.record_error(RuntimeError(
                                f"{tu['outcome']}: {tool.result or 'tool did not execute'}"
                            ))
                turn.output_messages.append(
                    Message(role="assistant", content=turn_data["text"] or turn_data["thinking"])
                )


@weave.op()
def agent_session(instance_id: str, prompt: str, repo_dir: str, run_dir: str, model: str = None) -> dict:
    """Run Claude Code headlessly against the repo clone, tracing every turn and tool call."""
    cmd = [
        "claude", "-p", prompt,
        "--output-format", "stream-json",
        "--verbose",
        "--permission-mode", "acceptEdits",
        "--allowedTools", ALLOWED_TOOLS,
    ]
    if model:
        cmd += ["--model", model]
    result = subprocess.run(cmd, cwd=repo_dir, text=True, capture_output=True)

    events = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    # Persist the full raw transcript to disk once. The trace below only gets
    # the per-turn/tool breakdown, not this whole thing a second time.
    Path(run_dir, "claude_stream.jsonl").write_text("\n".join(json.dumps(e) for e in events))
    if result.stderr:
        Path(run_dir, "claude_stderr.log").write_text(result.stderr)

    result_event = next((e for e in events if e.get("type") == "result"), {})
    denied_ids = {d["tool_use_id"] for d in result_event.get("permission_denials", [])}

    results_by_id = _pair_tool_results(events)
    turns = _extract_turns(events, results_by_id, denied_ids)
    for i, turn in enumerate(turns):
        agent_turn(i, turn["thinking"], turn["text"], turn["tool_uses"], turn.get("model"), turn.get("usage"))

    final_text = next((t["text"] for t in reversed(turns) if t["text"]), "")

    _log_agent_conversation(instance_id, prompt, turns)

    return {
        "final_text": final_text,
        "num_turns": result_event.get("num_turns"),
        "total_cost_usd": result_event.get("total_cost_usd"),
        "usage": result_event.get("usage"),
        "permission_denials": result_event.get("permission_denials"),
        "is_error": result_event.get("is_error"),
        "returncode": result.returncode,
    }


@weave.op()
def run_eval(instance_id: str, predictions_path: str, run_id: str, dataset_alias: str, task_repo: str) -> dict:
    """Run the SWE-bench Docker harness on the generated patch and return the verdict."""
    swebench_bin = str(ROOT / ".venv" / "bin" / "swebench")
    cmd = [
        swebench_bin, "eval", dataset_alias,
        "-p", predictions_path,
        "--run-id", run_id,
        "-i", instance_id,
        "-j", "1",
        "--task-repo", task_repo,
    ]
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    report_path = ROOT / "logs" / "evaluation" / run_id / "results.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    return {
        "resolved": instance_id in report.get("resolved_ids", []),
        "results_summary": report,
        "returncode": result.returncode,
        "stdout_tail": result.stdout[-2000:],
        "stderr_tail": result.stderr[-2000:],
    }


@weave.op()
def run_instance(instance_id: str, dataset: str, split: str, run_label: str, model: str = None) -> dict:
    from datasets import load_dataset

    ds = load_dataset(dataset, split=split)
    rows = [r for r in ds if r["instance_id"] == instance_id]
    if not rows:
        raise ValueError(f"instance_id {instance_id!r} not found in {dataset}:{split}")
    inst = rows[0]

    run_dir = RUNS / instance_id
    repo_dir = run_dir / "repo"
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    sh(["git", "clone", f"https://github.com/{inst['repo']}.git", str(repo_dir)])
    sh(["git", "checkout", inst["base_commit"]], cwd=repo_dir)

    prompt = f"""You are fixing a real GitHub issue in this repository ({inst['repo']}).

Read the problem statement below, find the root cause in the codebase, and make
the minimal source code change that fixes it. Do not add new tests, do not touch
test files, do not run the test suite, and do not create commits — just edit the
source files needed to fix the bug.

--- PROBLEM STATEMENT ---
{inst['problem_statement']}
--- END PROBLEM STATEMENT ---

When you are done, stop; do not summarize.
"""
    (run_dir / "prompt.txt").write_text(prompt)

    session = agent_session(instance_id, prompt, str(repo_dir), str(run_dir), model)

    if session.get("returncode") != 0:
        print(f"claude exited with code {session['returncode']}; see {run_dir}/claude_stderr.log", file=sys.stderr)

    diff = subprocess.run(
        ["git", "diff"], cwd=repo_dir, text=True, capture_output=True, check=True
    ).stdout
    if not diff.strip():
        print("WARNING: empty diff — Claude Code made no changes.", file=sys.stderr)

    pred = {"instance_id": instance_id, "model_name_or_path": "claude-code", "model_patch": diff}
    pred_file = run_dir / "predictions.jsonl"
    pred_file.write_text(json.dumps(pred) + "\n")

    # The eval run-id is derived from the patch content: an identical patch
    # safely reuses the harness's cached result, but a changed patch always
    # gets a fresh Docker evaluation instead of silently inheriting whatever
    # a previous, different patch resolved to under the same run-id.
    patch_hash = hashlib.sha256(diff.encode()).hexdigest()[:10]
    eval_run_id = f"{run_label}-{patch_hash}"

    task_repo = str(ROOT / "swe-bench-tasks")
    dataset_alias = "lite" if "Lite" in dataset else dataset
    eval_result = run_eval(instance_id, str(pred_file), eval_run_id, dataset_alias, task_repo)

    return {
        "instance_id": instance_id,
        "resolved": eval_result["resolved"],
        "eval_run_id": eval_run_id,
        "patch_hash": patch_hash,
        "patch_chars": len(diff),
        "patch_diff": diff,  # the actual fix, kept small enough here to duplicate freely
        "agent_num_turns": session.get("num_turns"),
        "agent_cost_usd": session.get("total_cost_usd"),
        "agent_permission_denials": session.get("permission_denials"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("instance_id")
    ap.add_argument("--dataset", default="SWE-bench/SWE-bench_Lite")
    ap.add_argument("--split", default="test")
    ap.add_argument(
        "--run-id", dest="run_label", default=None,
        help="Prefix for the eval run id — a hash of the patch content is appended "
             "automatically so re-runs with a different patch never reuse a stale eval result",
    )
    ap.add_argument("--model", default=None, help="Claude model alias to pass to `claude --model`")
    args = ap.parse_args()

    _load_akshata_wandb_key()
    weave.init(WEAVE_PROJECT)

    run_label = args.run_label or f"claude-code-{args.instance_id}"
    # Same id groups both surfaces: weave.thread for the Calls trace, conversation_id
    # (inside agent_session) for the Agents tab — so one instance_id finds both.
    with weave.thread(args.instance_id):
        result = run_instance(args.instance_id, args.dataset, args.split, run_label, args.model)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
