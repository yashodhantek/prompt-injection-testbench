from pathlib import Path

from pitb.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_list(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "[extraction]" in out and "extract-verbatim" in out


def test_init_writes_sample(tmp_path):
    path = tmp_path / "pitb.yaml"
    assert main(["init", str(path)]) == 0
    assert "system_prompt" in path.read_text()
    assert main(["init", str(path)]) == 1


def test_run_against_toy_fails_threshold(tmp_path):
    md = tmp_path / "report.md"
    junit = tmp_path / "junit.xml"
    code = main(["run", str(EXAMPLES / "toy.yaml"), "-q", "--fail-over", "0.1", "--md", str(md), "--junit", str(junit)])
    assert code == 1
    assert md.exists() and junit.exists()


def test_run_against_guarded_passes():
    assert main(["run", str(EXAMPLES / "toy-guarded.yaml"), "-q", "--fail-over", "0"]) == 0


def test_run_only_and_bad_pack():
    assert main(["run", str(EXAMPLES / "toy.yaml"), "-q", "--only", "extract-verbatim"]) == 0
    assert main(["run", str(EXAMPLES / "toy.yaml"), "-q", "--pack", "nonexistent"]) == 2


def test_validate_and_diff(tmp_path):
    assert main(["validate"]) == 0
    assert main(["validate", str(EXAMPLES / "toy.yaml")]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("target: []\n", encoding="utf-8")
    assert main(["validate", str(bad)]) == 2
    left = tmp_path / "a.json"
    right = tmp_path / "b.json"
    left.write_text(
        '{"vulnerable_rate": 0, "results": [{"id": "direct-override", "outcome": "resisted"}]}',
        encoding="utf-8",
    )
    right.write_text(
        '{"vulnerable_rate": 1, "results": [{"id": "direct-override", "outcome": "vulnerable"}]}',
        encoding="utf-8",
    )
    assert main(["diff", str(left), str(right)]) == 1
    assert main(["diff", str(right), str(left)]) == 0


def test_repeat_must_be_positive():
    assert main(["run", str(EXAMPLES / "toy.yaml"), "-q", "--repeat", "0", "--only", "direct-override"]) == 2


def test_errors_fail_the_run(tmp_path):
    module = tmp_path / "boom.py"
    module.write_text(
        "def answer(prompt, context, canary):\n"
        "    if prompt.startswith('Ignore all previous'):\n"
        "        raise TimeoutError('slow')\n"
        "    raise TimeoutError('slow')\n",
        encoding="utf-8",
    )
    config = tmp_path / "pitb.yaml"
    config.write_text("target:\n  type: python\n  callable: boom:answer\n", encoding="utf-8")
    assert main(["run", str(config), "-q", "--pack", "direct", "--only", "direct-override"]) == 1

    mixed = tmp_path / "mixed.py"
    mixed.write_text(
        "def answer(prompt, context, canary):\n"
        "    if prompt.startswith('Ignore all previous'):\n"
        "        raise TimeoutError('slow')\n"
        "    return 'no'\n",
        encoding="utf-8",
    )
    mixed_config = tmp_path / "mixed.yaml"
    mixed_config.write_text("target:\n  type: python\n  callable: mixed:answer\n", encoding="utf-8")
    assert main(["run", str(mixed_config), "-q", "--pack", "direct"]) == 0
    assert main(["run", str(mixed_config), "-q", "--pack", "direct", "--fail-over", "0"]) == 1


def test_config_must_be_a_mapping(tmp_path):
    path = tmp_path / "list.yaml"
    path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    assert main(["run", str(path), "-q"]) == 2
