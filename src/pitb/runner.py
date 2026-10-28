from __future__ import annotations

import secrets
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .attacks import Attack
from .detectors import run_detectors
from .targets import Target


@dataclass
class Result:
    attack: Attack
    attempt: int
    outcome: str  # "vulnerable", "resisted" or "error"
    reasons: list[str] = field(default_factory=list)
    reply: str = ""
    seconds: float = 0.0


@dataclass
class Summary:
    target: str
    results: list[Result]
    canary: str = ""

    @property
    def scored(self) -> list[Result]:
        return [r for r in self.results if r.outcome != "error"]

    @property
    def vulnerable_rate(self) -> float:
        scored = self.scored
        return sum(r.outcome == "vulnerable" for r in scored) / len(scored) if scored else 0.0

    def by_category(self) -> dict[str, dict[str, int]]:
        table: dict[str, dict[str, int]] = defaultdict(lambda: {"vulnerable": 0, "resisted": 0, "error": 0})
        for r in self.results:
            table[r.attack.category][r.outcome] += 1
        return dict(sorted(table.items()))

    def failing_attacks(self) -> list[str]:
        return sorted({r.attack.id for r in self.results if r.outcome == "vulnerable"})

    def attack_counts(self) -> list[tuple[str, int, int]]:
        """(id, vulnerable attempts, total attempts) for attacks that failed at least once."""
        totals: dict[str, int] = defaultdict(int)
        vulnerable: dict[str, int] = defaultdict(int)
        for result in self.results:
            totals[result.attack.id] += 1
            if result.outcome == "vulnerable":
                vulnerable[result.attack.id] += 1
        return [(attack_id, vulnerable[attack_id], totals[attack_id]) for attack_id in sorted(vulnerable)]


def _one(target: Target, attack: Attack, attempt: int) -> Result:
    # Each attempt gets a fresh marker so a cached answer can't fake a pass.
    rendered = attack.render("ZEBRA-" + secrets.token_hex(3).upper())
    start = time.perf_counter()
    try:
        reply = target.send(rendered.prompt, rendered.context)
    except Exception as exc:  # noqa: BLE001 - network errors, bad config, rate limits all count as "error"
        return Result(rendered, attempt, "error", [f"{type(exc).__name__}: {exc}"], seconds=time.perf_counter() - start)
    source = f"{rendered.prompt}\n{rendered.context or ''}"
    try:
        hits = run_detectors(
            rendered.detect,
            reply.text,
            reply.tool_calls,
            target.canary,
            source=source,
            allowed_tools=target.allowed_tools,
        )
    except Exception as exc:  # noqa: BLE001 - a bad detector should be an attempt error, not a crash
        return Result(
            rendered,
            attempt,
            "error",
            [f"detector {type(exc).__name__}: {exc}"],
            reply.text,
            time.perf_counter() - start,
        )
    return Result(
        rendered,
        attempt,
        "vulnerable" if hits else "resisted",
        hits,
        reply.text,
        time.perf_counter() - start,
    )


def run(target: Target, attacks: list[Attack], repeat: int = 1, workers: int = 4, on_result=None) -> Summary:
    jobs = [(a, i) for a in attacks for i in range(1, repeat + 1)]
    order = {attack.id: index for index, attack in enumerate(attacks)}
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(_one, target, attack, attempt) for attack, attempt in jobs]
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            if on_result:
                on_result(res)
    results.sort(key=lambda res: (order.get(res.attack.id, 0), res.attempt))
    return Summary(target=target.label, results=results, canary=target.canary)
