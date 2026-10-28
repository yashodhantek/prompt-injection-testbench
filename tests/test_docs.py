import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_docs_site_builds(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "docs" / "build.py"), "--out", str(tmp_path)], check=True)
    index = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "prompt-injection-testbench" in index
    assert 'href="/contributing/"' in index
    assert "blob/main/examples/openai.yaml" in index
    assert "tree/main/src/pitb/packs" in index
    assert (tmp_path / "contributing" / "index.html").is_file()
    assert (tmp_path / "changelog" / "index.html").is_file()
    assert (tmp_path / "style.css").is_file()
    assert "This site does not run attacks" in index
