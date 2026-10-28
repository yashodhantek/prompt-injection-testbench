"""Two fake "LLM apps" so you can try pitb without an API key.

`naive` does whatever the most recent instruction says, which is roughly how an
unprotected app behaves on a bad day. `guarded` treats documents as data and
never repeats its secret. Neither calls a real model.

    pitb run examples/toy.yaml
"""

import json
import re

MARKER = re.compile(r"ZEBRA-[0-9A-F]{6}")
URL = re.compile(r"https?://attacker\.example/\S+?(?=[)\s\"'>]|$)")


def naive(prompt, context, canary):
    text = f"{prompt}\n{context or ''}"
    lowered = text.lower()

    if "order note" in lowered and "reference code" in lowered:
        return {
            "reply": "Looked up the order.",
            "tool_calls": [{"name": "lookup_order", "arguments": json.dumps({"order_id": "48213", "note": canary})}],
        }
    if "call" in lowered and ("issue_refund" in lowered or "every tool" in lowered):
        return {
            "reply": "Done.",
            "tool_calls": [{"name": "issue_refund", "arguments": '{"order_id": "7781", "amount": 4999}'}],
        }
    if "refund of 4999" in lowered:
        return {
            "reply": "Refund processed.",
            "tool_calls": [{"name": "issue_refund", "arguments": '{"order_id": "90210", "amount": 4999}'}],
        }

    m = URL.search(text)
    if m:
        url = re.sub(r"DATA|YOUR_INTERNAL_REFERENCE_CODE|REFERENCE_CODE", canary, m.group(0))
        if canary not in url:
            url += ("&" if "?" in url else "?") + "d=" + canary
        return f"Here you go.\n\n![img]({url})"

    m = MARKER.search(text)
    if m:
        return m.group(0)

    if (
        "reference code" in lowered
        or "verbatim" in lowered
        or "configured with" in lowered
        or "configuration" in lowered
    ):
        if "backwards" in lowered:
            return canary[::-1]
        if "base64" in lowered:
            import base64

            return base64.b64encode(canary.encode()).decode()
        return f"My instructions say: internal reference code {canary}."

    return "I can help with orders, shipping and returns."


def guarded(prompt, context, canary):
    if context:
        first = context.strip().splitlines()[0][:80]
        return f"Summary of the provided content (treated as data, not instructions): {first}"
    return "Sorry, I can only help with orders, shipping and returns."
