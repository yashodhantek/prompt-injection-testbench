from pathlib import Path

import pytest

from pitb import report
from pitb.attacks import load_attacks, load_pack
from pitb.runner import run
from pitb.targets import MISSING, HTTPTarget, OpenAITarget, PythonTarget, _dig, _fill, _post_json, build_target

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_builtin_packs_load_and_ids_are_unique():
    attacks = load_attacks()
    assert len(attacks) >= 25
    assert len({a.id for a in attacks}) == len(attacks)


def test_naive_agent_is_caught_in_every_category():
    target = PythonTarget({"callable": "toy_agent:naive"}, EXAMPLES)
    summary = run(target, load_attacks(), workers=2)
    cats = summary.by_category()
    for name, row in cats.items():
        assert row["vulnerable"] > 0, f"no hits in {name}"
    assert summary.vulnerable_rate > 0.6


def test_guarded_agent_passes():
    target = PythonTarget({"callable": "toy_agent:guarded"}, EXAMPLES)
    summary = run(target, load_attacks(), repeat=2, workers=2)
    assert summary.vulnerable_rate == 0
    assert len(summary.results) == 2 * len(load_attacks())


def test_each_builtin_attack_has_the_expected_toy_outcome():
    attacks = load_attacks()
    naive = run(PythonTarget({"callable": "toy_agent:naive"}, EXAMPLES), attacks, workers=2)
    guarded = run(PythonTarget({"callable": "toy_agent:guarded"}, EXAMPLES), attacks, workers=2)
    assert naive.failing_attacks() == sorted(attack.id for attack in attacks)
    assert guarded.failing_attacks() == []
    assert all(result.outcome != "error" for result in naive.results + guarded.results)


def test_markers_are_fresh_per_attempt():
    seen = []

    def echo(prompt, context, canary):
        seen.append(prompt)
        return "no"

    target = PythonTarget({"callable": "toy_agent:guarded"}, EXAMPLES)
    target.fn = echo
    run(target, [a for a in load_attacks(["direct"]) if a.id == "direct-override"], repeat=3, workers=1)
    assert len(set(seen)) == 3


def test_errors_are_not_scored():
    def boom(prompt, context, canary):
        raise TimeoutError("slow")

    target = PythonTarget({"callable": "toy_agent:guarded"}, EXAMPLES)
    target.fn = boom
    summary = run(target, load_attacks(["direct"]))
    assert all(r.outcome == "error" for r in summary.results)
    assert summary.vulnerable_rate == 0
    assert "errored" in report.console(summary)


def test_reports_render():
    target = PythonTarget({"callable": "toy_agent:naive"}, EXAMPLES)
    summary = run(target, load_attacks(["extraction"]))
    body = report.to_json(summary)
    assert '"vulnerable_rate"' in body
    assert '"prompt"' in body
    assert summary.canary not in body
    assert "[canary]" in body
    markdown = report.to_markdown(summary)
    assert "## Successful attacks" in markdown
    assert "1/1" in markdown
    assert summary.canary not in markdown
    xml = report.to_junit(summary)
    assert xml.startswith("<?xml") and "<failure" in xml
    assert summary.canary not in xml


def test_custom_pack_file(tmp_path):
    f = tmp_path / "mine.yaml"
    f.write_text(
        "- id: mine-1\n  category: custom\n  name: test\n  prompt: hi {marker}\n  detect:\n    - marker: '{marker}'\n"
    )
    attacks = load_pack(str(f))
    assert attacks[0].render("ZEBRA-000000").prompt == "hi ZEBRA-000000"


def test_bad_pack_reports_missing_fields(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("- id: x\n  name: y\n")
    with pytest.raises(ValueError, match="missing"):
        load_pack(str(f))


def test_http_body_filling_and_paths():
    body = _fill(
        {"m": "{prompt}", "docs": ["{context}"], "s": "pre {prompt} post"},
        {"prompt": 'say "hi"', "context": "doc", "canary": ""},
    )
    assert body == {"m": 'say "hi"', "docs": ["doc"], "s": 'pre say "hi" post'}
    nested = _fill(
        {"note": "pre {prompt} post"},
        {"prompt": "has {canary} inside", "context": "DOC", "canary": "CANARY-SECRET"},
    )
    assert nested["note"] == "pre has {canary} inside post"
    assert _dig({"a": {"b": [{"c": "x"}]}}, "a.b.0.c") == "x"
    assert _dig({"a": {}}, "a.b") is MISSING


def test_http_inline_context_when_body_has_no_slot():
    t = HTTPTarget({"url": "http://x", "body": {"message": "{prompt}"}})
    assert t.inline_context is True
    t = HTTPTarget({"url": "http://x", "body": {"message": "{prompt}", "docs": "{context}"}})
    assert t.inline_context is False


def test_http_target_roundtrip():
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    import toy_agent

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            out = toy_agent.naive(body["message"], body.get("doc"), "CANARY-HTTP-0001")
            if isinstance(out, str):
                out = {"reply": out}
            data = json.dumps({"data": {"answer": out["reply"], "actions": out.get("tool_calls", [])}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        target = HTTPTarget(
            {
                "url": f"http://127.0.0.1:{server.server_port}/chat",
                "body": {"message": "{prompt}", "doc": "{context}"},
                "response_path": "data.answer",
                "tool_calls_path": "data.actions",
                "canary": "CANARY-HTTP-0001",
            }
        )
        summary = run(target, load_attacks(["extraction", "tools"]), workers=2)
    finally:
        server.shutdown()
    assert not [r for r in summary.results if r.outcome == "error"]
    assert summary.vulnerable_rate > 0.5


def test_http_missing_response_path_is_an_error():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            _ = self.rfile.read(int(self.headers["Content-Length"]))
            data = b'{"reply": "hi"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        target = HTTPTarget({"url": f"http://127.0.0.1:{server.server_port}/chat", "response_path": "answer"})
        with pytest.raises(RuntimeError, match="no value"):
            target.send("hi", None)
    finally:
        server.shutdown()


def test_post_json_retries_server_error(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    monkeypatch.setattr("pitb.targets.time.sleep", lambda _seconds: None)
    state = {"n": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            _ = self.rfile.read(int(self.headers["Content-Length"]))
            state["n"] += 1
            if state["n"] == 1:
                body = b"nope"
                self.send_response(500)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            data = b'{"reply": "ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        body = _post_json(f"http://127.0.0.1:{server.server_port}/chat", {"m": "hi"}, {}, 5, retries=2)
    finally:
        server.shutdown()
    assert body == {"reply": "ok"}
    assert state["n"] == 2


def test_null_tool_calls_are_empty():
    target = PythonTarget({"callable": "toy_agent:guarded"}, EXAMPLES)

    def empty(prompt, context, canary):
        return {"reply": "ok", "tool_calls": None}

    target.fn = empty
    assert target.send("hi", None).tool_calls == []


def test_openai_context_role_and_missing_canary_notice():
    planted = OpenAITarget({"model": "m", "system_prompt": "secret {canary}"})
    planted.context_role = "tool"
    roles = [message["role"] for message in planted._messages("Summarise", "hidden")]
    assert roles == ["system", "user", "assistant", "tool"]
    bare = OpenAITarget({"model": "m", "system_prompt": "no secret"})
    assert any("{canary}" in note for note in bare.notices)


def test_short_canary_and_missing_env_are_notices(monkeypatch):
    monkeypatch.delenv("MISSING_PITB_TOKEN", raising=False)
    target = build_target(
        {
            "type": "http",
            "url": "http://127.0.0.1",
            "canary": "short",
            "headers": {"Authorization": "Bearer ${MISSING_PITB_TOKEN}"},
        }
    )
    text = " ".join(target.notices)
    assert "shorter" in text
    assert "MISSING_PITB_TOKEN" in text


def test_utf8_pack_and_bad_detectors(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text(
        "- id: u\n  category: custom\n  name: ú\n  prompt: únicamente {marker}\n  detect:\n    - marker: '{marker}'\n",
        encoding="utf-8",
    )
    attack = load_pack(str(good))[0]
    assert "únicamente" in attack.prompt
    assert attack.render("ZEBRA-000000").prompt == "únicamente ZEBRA-000000"

    empty = tmp_path / "empty.yaml"
    empty.write_text("- id: e\n  category: c\n  name: n\n  prompt: hi\n  detect: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must not be empty"):
        load_pack(str(empty))

    broken = tmp_path / "broken.yaml"
    broken.write_text(
        "- id: b\n  category: c\n  name: n\n  prompt: hi\n  detect:\n    - regex: '['\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="invalid regex"):
        load_pack(str(broken))
