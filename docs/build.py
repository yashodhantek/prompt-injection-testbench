"""Build the static documentation site from the repository Markdown."""

from __future__ import annotations

import argparse
import html
import re
import shutil
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
GITHUB = "https://github.com/yashodhantek/prompt-injection-testbench"
PAGES = (
    ("README.md", "index.html", "Guide"),
    ("CONTRIBUTING.md", "contributing/index.html", "Contributing"),
    ("CHANGELOG.md", "changelog/index.html", "Changelog"),
)
DOC_HREFS = {
    "README.md": "/",
    "CONTRIBUTING.md": "/contributing/",
    "CHANGELOG.md": "/changelog/",
}


def _github_href(url: str) -> str:
    path, _, anchor = url.partition("#")
    kind = "tree" if (ROOT / path).is_dir() else "blob"
    href = f"{GITHUB}/{kind}/main/{path}"
    if anchor:
        href += f"#{anchor}"
    return href


def _rewrite_links(text: str) -> str:
    def one(part: str) -> str:
        def repl(match: re.Match[str]) -> str:
            label, url = match.group(1), match.group(2)
            if url.startswith(("http://", "https://", "mailto:", "#", "/")):
                return match.group(0)
            href = DOC_HREFS.get(url, _github_href(url))
            return f"[{label}]({href})"

        return re.sub(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", repl, part)

    pieces = re.split(r"(```.*?```)", text, flags=re.DOTALL)
    return "".join(piece if piece.startswith("```") else one(piece) for piece in pieces)


def _title(text: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else fallback


def _nav(current: str) -> str:
    items = []
    for _source, _dest, label in PAGES:
        href = DOC_HREFS[_source]
        if label == current:
            items.append(f'<a href="{href}" aria-current="page">{label}</a>')
        else:
            items.append(f'<a href="{href}">{label}</a>')
    return "\n".join(items)


def _page(title: str, nav: str, body: str, template: str) -> str:
    return template.replace("__TITLE__", html.escape(title)).replace("__NAV__", nav).replace("__BODY__", body)


def build(out: Path) -> None:
    template = (ROOT / "docs" / "template.html").read_text(encoding="utf-8")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    shutil.copyfile(ROOT / "docs" / "style.css", out / "style.css")
    for source, dest, label in PAGES:
        raw = (ROOT / source).read_text(encoding="utf-8")
        body = markdown.markdown(_rewrite_links(raw), extensions=["extra", "sane_lists"])
        target = out / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_page(_title(raw, label), _nav(label), body, template), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the pitb documentation site.")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "site")
    args = parser.parse_args()
    build(args.out)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
