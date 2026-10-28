# Contributing

Thanks for taking a look.

## Setup

```
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

## Adding an attack

1. Put it in the pack that fits (`src/pitb/packs/*.yaml`) or start a new one if it's genuinely a new category.
2. Use an id of the form `<pack>-<short-name>`.
3. Prefer `canary`, `marker` and `tool` detectors over `regex`. Regexes on free text cause false positives.
4. If it's a known technique, add a `notes:` line with where it comes from.
5. Make sure `pytest` still passes. The toy agents are deliberately simple and you don't need to make the
   naive one fall for your new attack.

Please don't add attacks that need real harmful content to work. The point is to test whether the app follows
injected instructions, and a harmless marker shows that just as well.

## Bugs

Include your pitb version (`pitb --version`), the target type and, if you can, the attack id and the reply
that was misclassified.
