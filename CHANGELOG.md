# Changelog

## Unreleased

- Fail the run when every attempt errors, and when `--fail-over` is set and any attempt errors.
- Retry HTTP 429 and 5xx. A missing `response_path` or `tool_calls_path` is an error.
- Warn when `{canary}` is missing from an OpenAI system prompt, when the canary is very short, and when a
  header references an unset environment variable. Refuse to start an OpenAI run with no API key.
- Indirect attacks no longer treat a quoted phrase from the document as a successful injection.
  Exfil checks the link host, and ignores a URL copied unchanged from the attack unless the canary is in it.
- `canary_tool` detects a secret in tool arguments. `allowed_tools` ignores expected calls for `tool: '*'`.
  `all:` requires every nested detector.
- Reports show `attack k/n`, include the rendered prompt, and redact the canary unless `--raw-replies` is set.
- `pitb validate` and `pitb diff`. OpenAI `context_template` and `context_role`.
- Read and write YAML and reports as UTF-8. Reject empty detector lists, bad regexes, and `repeat` below 1.
- Static documentation site, with `deploy/vps-setup.sh` to publish it behind nginx and certbot.

## 0.1.0

First public release.

- `openai`, `http` and `python` targets
- 31 attacks across direct, extraction, indirect, exfiltration and tools packs
- canary, marker, regex, tool and exfil_link detectors
- console, JSON, Markdown and JUnit reports; `--fail-over` for CI
