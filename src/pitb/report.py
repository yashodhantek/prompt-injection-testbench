from __future__ import annotations

import base64
import json
from collections import defaultdict
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from . import __version__
from .runner import Summary


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def redact_canary(text: str, secret: str) -> str:
    """Hide the planted secret in artifacts that get pasted into CI summaries."""
    if not text or not secret:
        return text
    disguised = [
        secret,
        secret[::-1],
        secret.encode().hex(),
        base64.b64encode(secret.encode()).decode().rstrip("="),
    ]
    for value in disguised:
        if value:
            text = text.replace(value, "[canary]")
    return text


def _reply(text: str, secret: str, redact: bool, limit: int | None = None) -> str:
    shown = redact_canary(text, secret) if redact else text
    shown = shown.strip()
    if limit is not None and len(shown) > limit:
        return shown[:limit] + "…"
    return shown


def console(summary: Summary) -> str:
    lines = [f"\nTarget: {summary.target}", ""]
    categories = list(summary.by_category())
    width = max([len("category"), *[len(cat) for cat in categories]]) if categories else len("category")
    lines.append(f"{'category':<{width}}  {'vulnerable':>12}{'resisted':>10}{'errors':>8}")
    for cat, row in summary.by_category().items():
        lines.append(f"{cat:<{width}}  {row['vulnerable']:>12}{row['resisted']:>10}{row['error']:>8}")
    lines.append("")
    lines.append("Counts are attempts.")
    lines.append(f"Vulnerable on {_pct(summary.vulnerable_rate)} of {len(summary.scored)} scored attempts.")
    failing = summary.attack_counts()
    if failing:
        shown = [f"{attack_id} {hits}/{total}" for attack_id, hits, total in failing[:8]]
        extra = f" and {len(failing) - 8} more" if len(failing) > 8 else ""
        lines.append("Failing attacks: " + ", ".join(shown) + extra)
    errors = [r for r in summary.results if r.outcome == "error"]
    if errors:
        lines.append(f"{len(errors)} attempt(s) errored, e.g. {errors[0].attack.id}: {errors[0].reasons[0]}")
    return "\n".join(lines)


def to_json(summary: Summary, redact: bool = True) -> str:
    return json.dumps(
        {
            "tool": f"pitb {__version__}",
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": summary.target,
            "canary": "[redacted]" if redact and summary.canary else summary.canary,
            "vulnerable_rate": round(summary.vulnerable_rate, 4),
            "by_category": summary.by_category(),
            "failing": [
                {"id": attack_id, "vulnerable": hits, "attempts": total}
                for attack_id, hits, total in summary.attack_counts()
            ],
            "results": [
                {
                    "id": r.attack.id,
                    "category": r.attack.category,
                    "name": r.attack.name,
                    "notes": r.attack.notes,
                    "attempt": r.attempt,
                    "outcome": r.outcome,
                    "reasons": r.reasons,
                    "seconds": round(r.seconds, 3),
                    "prompt": r.attack.prompt,
                    "context": r.attack.context,
                    "reply": _reply(r.reply, summary.canary, redact),
                }
                for r in summary.results
            ],
        },
        indent=2,
    )


def to_markdown(summary: Summary, max_reply: int = 300, redact: bool = True) -> str:
    out = [
        "# Prompt-injection test report",
        "",
        f"- **Target:** `{summary.target}`",
        f"- **Date:** {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC",
        f"- **Vulnerable:** {_pct(summary.vulnerable_rate)} of {len(summary.scored)} scored attempts",
        "",
        "Counts are attempts.",
        "",
        "| Category | Vulnerable | Resisted | Errors |",
        "|---|---:|---:|---:|",
    ]
    for cat, row in summary.by_category().items():
        out.append(f"| {cat} | {row['vulnerable']} | {row['resisted']} | {row['error']} |")
    grouped: dict[str, list] = defaultdict(list)
    for result in summary.results:
        if result.outcome == "vulnerable":
            grouped[result.attack.id].append(result)
    if grouped:
        out += ["", "## Successful attacks", ""]
        for attack_id in sorted(grouped):
            attempts = grouped[attack_id]
            attack = attempts[0].attack
            total = sum(1 for result in summary.results if result.attack.id == attack_id)
            out.append(f"### {attack_id}: {attack.name} ({len(attempts)}/{total})")
            out.append("")
            if attack.notes:
                out.append(attack.notes)
                out.append("")
            for result in attempts:
                reply = _reply(result.reply, summary.canary, redact, max_reply).replace("\n", " ")
                out += [
                    f"Attempt {result.attempt}: {'; '.join(result.reasons)}",
                    "",
                    f"> {reply}",
                    "",
                ]
    return "\n".join(out) + "\n"


def to_junit(summary: Summary, redact: bool = True) -> str:
    cases = []
    for r in summary.results:
        name = escape(f"{r.attack.id} {r.attack.name} #{r.attempt}", {'"': "&quot;"})
        body = ""
        if r.outcome == "vulnerable":
            message = escape("; ".join(r.reasons), {chr(34): "&quot;"})
            detail = escape(_reply(r.reply, summary.canary, redact, 2000))
            body = f'<failure message="{message}">{detail}</failure>'
        elif r.outcome == "error":
            message = escape("; ".join(r.reasons), {chr(34): "&quot;"})
            body = f'<error message="{message}"/>'
        cases.append(
            f'  <testcase classname="pitb.{escape(r.attack.category)}" name="{name}" time="{r.seconds:.3f}">{body}</testcase>'
        )
    failures = sum(r.outcome == "vulnerable" for r in summary.results)
    errors = sum(r.outcome == "error" for r in summary.results)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="prompt-injection" tests="{len(summary.results)}" failures="{failures}" errors="{errors}">\n'
        + "\n".join(cases)
        + "\n</testsuite>\n"
    )
