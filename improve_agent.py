#!/usr/bin/env python3
"""
Autonomous improve loop: blue agent flags a fixable issue in the coding agent's
behavior on one SWE-bench instance -> a canned remediation gets applied to
agent_config.json -> the instance re-runs -> blue agent re-checks -> a small
regression set re-runs to make sure nothing broke.

This never edits agent_predict.py's source. It only ever edits agent_config.json
(allowed_tools_extra / prompt_hints), which agent_predict.py already knows how to
read. Every applied "fix" is a one-line diff to that file, kept in an on-disk
history so a demo can show exactly what changed and why.

Fixes are CANNED, not free-text-generated: fix_type is a closed 2-value enum
(broaden_bash_pattern, add_prompt_hint) and each maps to one fixed, hand-written
remediation. We do not let the judge's prose free-form-edit the sandbox — see the
REMEDIATIONS dict below.

Stop conditions, checked in this order every round:
  1. CONVERGED     — fresh blue-agent report has zero actionable findings (fix_type
                     != "none"). Success; nothing left to fix.
  2. AUDIT_FAILED  — blue_agent.py's judge call itself failed (e.g. a bad/unparsable
                     model response). Distinct from CONVERGED — we don't know the
                     state, so we stop rather than guess. Needs a human/retry.
  3. REGRESSION    — applying the fix flipped a regression-set instance's `resolved`
                     from true to false. Hard stop, revert agent_config.json to the
                     pre-round copy, report needs-human.
  4. STAGNATION    — the same fix_type(s) got proposed two rounds in a row with no
                     drop in that round's target metric (denied_count). Hard stop,
                     report needs-human — reapplying blindly isn't working.
  5. CAP           — MAX_ROUNDS reached regardless of the above (default 3). Every
                     round costs a real Docker build + agent session + eval, and
                     there's no human watching, so this is a hard safety valve.

Traced into Weave two ways, same as agent_predict.py:
  - Calls: run_improve_loop -> run_round (x N) -> audit_target / apply_fix / regression_check.
    The target and regression-set subprocess runs are separate processes (real
    process boundaries, not function calls) so they can't be literal parent/child
    calls of this loop's own ops — they get tagged with the same weave.thread(target)
    instead, which groups related-but-separate traces without a false nesting claim.
  - Agents/Conversations: the whole loop also gets logged as one conversation
    (conversation_id "improve-loop-<target>"), one turn per round, so it's
    browsable the same glanceable way the individual SWE-bench runs already are.

Usage:
    python improve_agent.py <instance_id>

Writes: agent_config.json               (edited in place, one change per round)
        agent_config_history/round-N.json  (a copy of the config after round N,
                                             so every step is inspectable/revertible)
        runs/<instance_id>/improve_loop_report.md
"""
import argparse
import json
import shutil
import subprocess
import sys

import weave
from weave.conversation import Message

import agent_predict as ap

ROOT = ap.ROOT
HISTORY_DIR = ROOT / "agent_config_history"
MAX_ROUNDS = 3

# Small and cheap on purpose — each entry costs a real re-run every round. Add more
# once the loop's basic behavior is trusted. The target instance is excluded from
# its own regression set automatically.
DEFAULT_REGRESSION_SET = [
    "psf__requests-2317",
    "pytest-dev__pytest-7432",
]

# fix_type -> canned, hand-written remediation. Never derived from the judge's
# free-text suggested_fix — that keeps every applied change reviewable and safe,
# instead of letting an LLM's prose edit the sandbox's permissions directly.
REMEDIATIONS = {
    "add_prompt_hint": {
        "prompt_hints": [
            "Note: package installs, `dangerouslyDisableSandbox`, and any Bash "
            "command outside the allowed verification patterns are never "
            "available in this environment. Do not retry a denied command — if "
            "one is denied, immediately switch to verifying your fix by "
            "reasoning about the code instead."
        ],
    },
    "broaden_bash_pattern": {
        # Restores the exact scoped set BASE_ALLOWED_TOOLS used to hand-carry before
        # it was reverted to no-Bash — bare + absolute-path invocation forms, so it
        # covers both `python -c ...` and `/.../.venv/bin/python -c ...`. Nothing
        # beyond verification-only prefixes: no pip, no curl, no arbitrary shell.
        "allowed_tools_extra": [
            "Bash(python -c *)",
            "Bash(python3 -c *)",
            "Bash(pytest *)",
            "Bash(*/python -c *)",
            "Bash(*/python3 -c *)",
        ],
    },
}


def sh_json(cmd) -> dict:
    print(f"+ {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    print(result.stdout[-1500:])
    if result.returncode != 0:
        print(result.stderr[-1500:], file=sys.stderr)
    # agent_predict.py's final print is `json.dumps(result, indent=2)`, which — with
    # indent=2 — always puts a bare "{" alone on its own line to start it. Find the
    # LAST such line (searching backward, since earlier stdout may contain other
    # braces from git output etc.) and parse from there to the end.
    lines = result.stdout.splitlines()
    start = next((i for i in range(len(lines) - 1, -1, -1) if lines[i].strip() == "{"), None)
    if start is None:
        return {}
    try:
        return json.loads("\n".join(lines[start:]))
    except json.JSONDecodeError:
        return {}


def run_agent_predict(instance_id: str) -> dict:
    return sh_json(["uv", "run", "python3", "agent_predict.py", instance_id])


def run_blue_agent(instance_id: str) -> dict:
    """Run the blue agent; a failed judge call is reported, not raised — a crash here
    would kill the whole loop over what might be a transient model response glitch."""
    result = subprocess.run(
        ["uv", "run", "python3", "blue_agent.py", instance_id], cwd=ROOT,
        text=True, capture_output=True,
    )
    if result.returncode != 0:
        print(result.stdout[-1000:])
        print(result.stderr[-1000:], file=sys.stderr)
        return {"_audit_failed": True, "findings": []}
    report_path = ap.RUNS / instance_id / "blue_agent_report.json"
    try:
        return json.loads(report_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"_audit_failed": True, "findings": []}


def actionable_findings(report: dict) -> list:
    return [f for f in report.get("findings", []) if f.get("fix_type") in REMEDIATIONS]


def denied_count(predict_result: dict) -> int:
    return len(predict_result.get("agent_permission_denials") or [])


def save_config_snapshot(round_num: int):
    HISTORY_DIR.mkdir(exist_ok=True)
    shutil.copy(ap.AGENT_CONFIG_FILE, HISTORY_DIR / f"round-{round_num}.json")


def revert_to(round_num: int):
    snapshot = HISTORY_DIR / f"round-{round_num}.json"
    shutil.copy(snapshot, ap.AGENT_CONFIG_FILE)


# ---------------------------------------------------------------------------
# Weave-traced steps. Nesting follows the call stack, same as agent_predict.py.
# ---------------------------------------------------------------------------

@weave.op()
def audit_target(target: str) -> dict:
    """Re-run the target instance and audit it. Read-only — applies no fix."""
    predict_result = run_agent_predict(target)
    if "resolved" not in predict_result:
        # sh_json couldn't find/parse agent_predict.py's final JSON print in its
        # stdout — don't silently carry on with resolved=None/denied_count=0, since
        # that's indistinguishable from a real clean run and could feed wrong data
        # into the stagnation check in a later round. Fail loudly instead.
        print(f"WARNING: could not parse agent_predict.py's output for {target} "
              f"(missing 'resolved' key); treating as a failed audit.", file=sys.stderr)
        return {"audit_failed": True, "resolved": None}
    report = run_blue_agent(target)
    if report.get("_audit_failed"):
        return {"audit_failed": True, "resolved": predict_result.get("resolved")}
    findings = actionable_findings(report)
    return {
        "audit_failed": False,
        "resolved": predict_result.get("resolved"),
        "denied_count": denied_count(predict_result),
        "num_findings": len(report.get("findings", [])),
        "actionable_fix_types": sorted({f["fix_type"] for f in findings}),
    }


@weave.op()
def apply_fix(round_num: int, fix_types: list) -> dict:
    """Apply the canned remediation(s) for these fix_types to agent_config.json."""
    before = ap._load_agent_config()
    config = json.loads(json.dumps(before))  # plain copy
    for ft in fix_types:
        for key, values in REMEDIATIONS[ft].items():
            for v in values:
                if v not in config[key]:
                    config[key].append(v)
    ap.AGENT_CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    save_config_snapshot(round_num)
    return {"fix_types": fix_types, "config_before": before, "config_after": config}


@weave.op()
def regression_check(regression_set: list) -> dict:
    """Re-run each regression instance; report which (if any) broke."""
    results = {}
    for r in regression_set:
        reg_result = run_agent_predict(r)
        results[r] = reg_result.get("resolved")
    failed = [r for r, ok in results.items() if not ok]
    return {"results": results, "failed": failed}


@weave.op()
def run_round(round_num: int, target: str, regression_set: list,
              prev_fix_types, prev_denied) -> dict:
    audit = audit_target(target)

    if audit["audit_failed"]:
        return {**audit, "round": round_num, "stop": "AUDIT_FAILED", "fix": None, "regression": None}

    if not audit["actionable_fix_types"]:
        return {**audit, "round": round_num, "stop": "CONVERGED", "fix": None, "regression": None}

    fix_types = audit["actionable_fix_types"]
    if (fix_types == prev_fix_types and prev_denied is not None
            and audit["denied_count"] >= prev_denied):
        return {**audit, "round": round_num, "stop": "STAGNATION", "fix": None, "regression": None}

    fix = apply_fix(round_num, fix_types)
    reg = regression_check(regression_set)

    if reg["failed"]:
        revert_to(round_num - 1)
        return {**audit, "round": round_num, "stop": "REGRESSION", "fix": fix, "regression": reg}

    return {**audit, "round": round_num, "stop": None, "fix": fix, "regression": reg}


@weave.op()
def run_improve_loop(target: str) -> dict:
    regression_set = [i for i in DEFAULT_REGRESSION_SET if i != target]
    save_config_snapshot(0)  # round 0 = whatever agent_config.json looked like at start

    log = []
    prev_fix_types, prev_denied = None, None
    outcome = "CAP"

    for round_num in range(1, MAX_ROUNDS + 1):
        print(f"\n=== ROUND {round_num}: auditing {target} ===")
        entry = run_round(round_num, target, regression_set, prev_fix_types, prev_denied)
        log.append(entry)
        print(f"round {round_num}: {entry}")

        if entry["stop"]:
            outcome = entry["stop"]
            break
        prev_fix_types = entry["actionable_fix_types"]
        prev_denied = entry["denied_count"]

    return {"target": target, "outcome": outcome, "regression_set": regression_set, "rounds": log}


def _round_summary(entry: dict) -> str:
    if entry.get("audit_failed"):
        return "Blue agent's judge call failed — stopping rather than guessing."
    if entry["stop"] == "CONVERGED":
        return "No actionable findings left — nothing more to fix."
    if entry["stop"] == "STAGNATION":
        return f"Same fix type(s) proposed again with no improvement ({entry['denied_count']} denied attempts)."
    parts = [f"Applied {entry['fix']['fix_types']}; denied attempts: {entry['denied_count']}."]
    if entry["stop"] == "REGRESSION":
        parts.append(f"Broke regression instance(s): {entry['regression']['failed']}. Reverted.")
    else:
        parts.append(f"Regression set still passing: {entry['regression']['results']}.")
    return " ".join(parts)


def _log_improve_conversation(target: str, loop_result: dict):
    """Log the whole loop as a Weave conversation — one turn per round — so it's
    browsable in the Agents tab the same way individual SWE-bench runs already are."""
    with weave.start_conversation(agent_name="improve-loop", conversation_id=f"improve-loop-{target}"):
        conversation = weave.get_current_conversation()
        for entry in loop_result["rounds"]:
            with conversation.start_turn(
                user_message=f"Round {entry['round']}: audit {target}",
                agent_name="improve-loop",
            ) as turn:
                with turn.start_tool(name="audit_target", arguments={"target": target}) as t:
                    t.result = {k: v for k, v in entry.items() if k not in ("fix", "regression")}
                if entry.get("fix"):
                    with turn.start_tool(name="apply_fix", arguments=entry["fix"]["fix_types"]) as t:
                        t.result = entry["fix"]
                if entry.get("regression"):
                    with turn.start_tool(name="regression_check", arguments=loop_result["regression_set"]) as t:
                        t.result = entry["regression"]
                turn.output_messages.append(Message(role="assistant", content=_round_summary(entry)))
        conv_final = f"Loop outcome: {loop_result['outcome']} after {len(loop_result['rounds'])} round(s)."
        with conversation.start_turn(user_message="Final outcome", agent_name="improve-loop") as turn:
            turn.output_messages.append(Message(role="assistant", content=conv_final))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("instance_id")
    args = parser.parse_args()
    target = args.instance_id

    ap._load_akshata_wandb_key()
    weave.init(ap.WEAVE_PROJECT)

    with weave.thread(target):
        result = run_improve_loop(target)

    _log_improve_conversation(target, result)

    report_lines = [
        f"# Improve-loop report: {target}",
        "",
        f"**Outcome:** {result['outcome']}",
        "",
        "| Round | Resolved | Denied attempts | Findings | Actionable fix types |",
        "|---|---|---|---|---|",
    ]
    for e in result["rounds"]:
        report_lines.append(
            f"| {e['round']} | {e.get('resolved')} | {e.get('denied_count', '-')} | "
            f"{e.get('num_findings', '-')} | {', '.join(e.get('actionable_fix_types', [])) or '-'} |"
        )
    report_lines += ["", f"Regression set used: {result['regression_set']}"]
    (ap.RUNS / target / "improve_loop_report.md").write_text("\n".join(report_lines))
    print(f"\nFinal outcome: {result['outcome']}")
    print(f"Report written to runs/{target}/improve_loop_report.md")


if __name__ == "__main__":
    main()
