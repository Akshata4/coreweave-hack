#!/usr/bin/env python3
"""
Anthropic Messages API -> W&B Inference (OpenAI-compatible) translating proxy.

Lets `claude` (any client speaking the Anthropic Messages API) run on top of a
model served by W&B Inference instead of a real Anthropic model, authenticated
with WANDB_API_KEY instead of ANTHROPIC_API_KEY. `claude` never needs a real
Anthropic credential — ANTHROPIC_API_KEY only needs to be *present* (any value)
to satisfy Claude Code's own local check; the real request never reaches
Anthropic once ANTHROPIC_BASE_URL points here.

Verified against the real W&B Inference endpoint before writing this (not
reverse-engineered from an unseen tutorial): plain chat and tool-calling both
confirmed working with model "moonshotai/Kimi-K2.7-Code", OpenAI-standard
request/response shapes, one quirk — the model emits an extra non-standard
"reasoning" field and can burn its whole max_tokens budget on that before any
real content, so this proxy floors max_tokens well above whatever a caller
asks for.

Streaming: always calls W&B Inference non-streaming internally (correctness
over incremental latency — this backs headless, one-shot validation runs, not
an interactive UI), then re-packages the one complete response as a minimal
valid Anthropic SSE event sequence if the caller asked for stream=true.

Usage:
    WANDB_API_KEY=... WANDB_MODEL=moonshotai/Kimi-K2.7-Code python3 inference_proxy.py
    # then, in the client:
    export ANTHROPIC_BASE_URL=http://localhost:4000
    export ANTHROPIC_API_KEY=dummy
"""
import json
import os
import sys
import time
import uuid

import requests
from flask import Flask, Response, jsonify, request

WANDB_API_KEY = os.environ.get("WANDB_API_KEY")
WANDB_MODEL = os.environ.get("WANDB_MODEL", "moonshotai/Kimi-K2.7-Code")
WANDB_INFERENCE_URL = "https://api.inference.wandb.ai/v1/chat/completions"
MIN_MAX_TOKENS = 4096  # this model's reasoning overhead can exceed a small caller-requested budget

if not WANDB_API_KEY:
    sys.exit("WANDB_API_KEY is required")

app = Flask(__name__)


def _anthropic_content_to_openai(content):
    """A message's `content` can be a plain string or a list of typed blocks."""
    if isinstance(content, str):
        return content, []
    text_parts = []
    tool_calls = []
    tool_results = []
    for block in content:
        t = block.get("type")
        if t == "text":
            text_parts.append(block["text"])
        elif t == "tool_use":
            tool_calls.append({
                "id": block["id"],
                "type": "function",
                "function": {"name": block["name"], "arguments": json.dumps(block.get("input", {}))},
            })
        elif t == "tool_result":
            result_content = block.get("content", "")
            if isinstance(result_content, list):
                result_content = "".join(b.get("text", "") for b in result_content if isinstance(b, dict))
            tool_results.append({"tool_call_id": block["tool_use_id"], "content": str(result_content)})
    return "\n".join(text_parts), tool_calls, tool_results


def anthropic_to_openai(body):
    messages = []
    if body.get("system"):
        sys_text = body["system"]
        if isinstance(sys_text, list):
            sys_text = "\n".join(b.get("text", "") for b in sys_text)
        messages.append({"role": "system", "content": sys_text})

    for m in body.get("messages", []):
        role = m["role"]
        content = m.get("content", "")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue

        text, tool_calls, tool_results = _anthropic_content_to_openai(content)
        if tool_results:
            # Anthropic puts tool_result blocks in a "user" message; OpenAI wants
            # one separate {"role": "tool", ...} message per result.
            for tr in tool_results:
                messages.append({"role": "tool", "tool_call_id": tr["tool_call_id"], "content": tr["content"]})
            if text:
                messages.append({"role": role, "content": text})
            continue

        msg = {"role": role, "content": text or None}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        messages.append(msg)

    openai_body = {
        "model": WANDB_MODEL,
        "messages": messages,
        "max_tokens": max(body.get("max_tokens", MIN_MAX_TOKENS), MIN_MAX_TOKENS),
    }
    if body.get("tools"):
        openai_body["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                },
            }
            for t in body["tools"]
        ]
    return openai_body


STOP_REASON_MAP = {"stop": "end_turn", "tool_calls": "tool_use", "length": "max_tokens"}


def openai_to_anthropic(openai_resp, model_name):
    choice = openai_resp["choices"][0]
    msg = choice["message"]
    content = []
    if msg.get("content"):
        content.append({"type": "text", "text": msg["content"]})
    for tc in msg.get("tool_calls") or []:
        try:
            args = json.loads(tc["function"]["arguments"])
        except (json.JSONDecodeError, TypeError):
            args = {}
        content.append({"type": "tool_use", "id": tc["id"], "name": tc["function"]["name"], "input": args})
    if not content:
        # the model spent its whole budget on "reasoning" and produced nothing usable
        content.append({"type": "text", "text": ""})

    usage = openai_resp.get("usage", {})
    return {
        "id": openai_resp.get("id", f"msg_{uuid.uuid4().hex}"),
        "type": "message",
        "role": "assistant",
        "model": model_name,
        "content": content,
        "stop_reason": STOP_REASON_MAP.get(choice.get("finish_reason"), "end_turn"),
        "stop_sequence": None,
        "usage": {
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
        },
    }


def _sse_wrap(anthropic_msg):
    """Repackage one complete Anthropic message as a minimal, valid SSE event
    sequence — everything emitted at once, not truly incremental, but structurally
    what a stream-json client expects to parse."""
    events = []
    msg_id = anthropic_msg["id"]
    events.append(("message_start", {
        "type": "message_start",
        "message": {**anthropic_msg, "content": [], "stop_reason": None, "usage": {"input_tokens": anthropic_msg["usage"]["input_tokens"], "output_tokens": 0}},
    }))
    for i, block in enumerate(anthropic_msg["content"]):
        events.append(("content_block_start", {"type": "content_block_start", "index": i, "content_block": {**block, **({"text": ""} if block["type"] == "text" else {})}}))
        if block["type"] == "text":
            events.append(("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": block["text"]}}))
        elif block["type"] == "tool_use":
            events.append(("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}}))
        events.append(("content_block_stop", {"type": "content_block_stop", "index": i}))
    events.append(("message_delta", {"type": "message_delta", "delta": {"stop_reason": anthropic_msg["stop_reason"], "stop_sequence": None}, "usage": {"output_tokens": anthropic_msg["usage"]["output_tokens"]}}))
    events.append(("message_stop", {"type": "message_stop"}))

    def gen():
        for event_name, payload in events:
            yield f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"

    return gen()


@app.route("/v1/messages", methods=["POST"])
def messages():
    body = request.get_json(force=True)
    openai_body = anthropic_to_openai(body)
    resp = requests.post(
        WANDB_INFERENCE_URL,
        headers={"Authorization": f"Bearer {WANDB_API_KEY}", "Content-Type": "application/json"},
        json=openai_body,
        timeout=120,
    )
    if resp.status_code != 200:
        return jsonify({"type": "error", "error": {"type": "api_error", "message": resp.text}}), resp.status_code

    anthropic_msg = openai_to_anthropic(resp.json(), body.get("model", WANDB_MODEL))

    if body.get("stream"):
        return Response(_sse_wrap(anthropic_msg), mimetype="text/event-stream")
    return jsonify(anthropic_msg)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model": WANDB_MODEL})


if __name__ == "__main__":
    print(f"Proxying Anthropic Messages API -> W&B Inference ({WANDB_MODEL})")
    app.run(host="127.0.0.1", port=4000)
