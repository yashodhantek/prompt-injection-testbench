"""Ways of talking to the thing under test.

Every target takes (prompt, context) and returns a Reply. `context` is set for
indirect attacks: it is the untrusted document, web page or tool output the
attack is hidden in.

The Python callable is invoked from a thread pool. It needs to be safe to call
concurrently, or the run should use ``--workers 1``.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

_PLACEHOLDER = re.compile(r"\{(prompt|context|canary)\}")
_ENV = re.compile(r"\$\{([A-Z0-9_]+)\}")


@dataclass
class Reply:
    text: str
    tool_calls: list[dict] = field(default_factory=list)


def new_canary() -> str:
    return "CANARY-" + secrets.token_hex(4).upper()


class _Missing:
    """A JSON path that was not present. Distinct from a present null."""


MISSING = _Missing()


def _expand_env(value, missing: list[str] | None = None):
    if isinstance(value, str):

        def repl(match):
            name = match.group(1)
            if name not in os.environ:
                if missing is not None and name not in missing:
                    missing.append(name)
                return ""
            return os.environ[name]

        return _ENV.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v, missing) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v, missing) for v in value]
    return value


def _fill(template, values: dict):
    """Replace {prompt}/{context}/{canary} without substituting inside inserted values."""
    if isinstance(template, str):
        if template in {"{prompt}", "{context}", "{canary}"}:
            return values[template[1:-1]]

        def repl(match):
            return values.get(match.group(1)) or ""

        return _PLACEHOLDER.sub(repl, template)
    if isinstance(template, dict):
        return {k: _fill(v, values) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill(v, values) for v in template]
    return template


def _dig(data, path: str | None):
    """Walk a dotted path. Missing keys and bad indexes return MISSING, not None."""
    if not path:
        return data
    for part in path.split("."):
        if isinstance(data, list):
            try:
                data = data[int(part)]
            except (ValueError, IndexError):
                return MISSING
        elif isinstance(data, dict):
            if part not in data:
                return MISSING
            data = data[part]
        else:
            return MISSING
    return data


def _retry_after(headers, attempt: int) -> float:
    raw = headers.get("Retry-After") if headers else None
    if raw:
        try:
            return min(float(raw), 5.0)
        except ValueError:
            pass
    return min(0.25 * (2**attempt), 5.0)


def _post_json(url: str, body: dict, headers: dict, timeout: float, retries: int = 2) -> dict:
    payload = json.dumps(body).encode()
    last_error: Exception | None = None
    attempts = max(0, retries) + 1
    for attempt in range(attempts):
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            message = f"HTTP {e.code} from {url}: {detail}"
            retryable = e.code == 429 or 500 <= e.code <= 599
            if retryable and attempt + 1 < attempts:
                last_error = RuntimeError(message)
                time.sleep(_retry_after(e.headers, attempt))
                continue
            raise RuntimeError(message) from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"request to {url} failed: {e.reason}") from None
    raise RuntimeError(str(last_error) if last_error else f"request to {url} failed")


def _string_headers(headers: dict) -> dict[str, str]:
    return {str(key): "" if value is None else str(value) for key, value in headers.items()}


class Target:
    """Base class. Subclasses call ``Target.__init__`` so list fields are not shared."""

    canary: str = ""
    canary_in_prompt: bool = True

    def __init__(self):
        self.allowed_tools: list[str] = []
        self.context_template: str | None = None
        self.context_role = "user"
        self.notices: list[str] = []
        self.canary_in_prompt = True

    def send(self, prompt: str, context: str | None) -> Reply:  # pragma: no cover
        raise NotImplementedError

    @property
    def label(self) -> str:  # pragma: no cover
        return self.__class__.__name__


def wrap_context(prompt: str, context: str | None, template: str | None = None) -> str:
    if not context:
        return prompt
    template = template or "{prompt}\n\n<document>\n{context}\n</document>"
    return _fill(template, {"prompt": prompt, "context": context.strip(), "canary": ""})


def _flatten_content(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                parts.append(str(part.get("text") or ""))
        return "\n".join(parts)
    return str(content)


class OpenAITarget(Target):
    """Any OpenAI-compatible /chat/completions endpoint (OpenAI, Azure OpenAI, vLLM, Ollama, LiteLLM...)."""

    def __init__(self, cfg: dict):
        super().__init__()
        self.base_url = cfg.get("base_url", "https://api.openai.com/v1").rstrip("/")
        self.model = cfg["model"]
        self.key_env = cfg.get("api_key_env", "OPENAI_API_KEY")
        self.api_key = os.environ.get(self.key_env, "")
        self.missing_env: list[str] = []
        self.headers = _string_headers(_expand_env(cfg.get("headers") or {}, self.missing_env))
        for name in self.missing_env:
            self.notices.append(f"environment variable {name} is not set; substituting an empty string")
        if self.api_key and "Authorization" not in self.headers and "api-key" not in self.headers:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
        self.canary = cfg.get("canary") or new_canary()
        system_prompt = cfg.get("system_prompt", "")
        if not isinstance(system_prompt, str):
            raise ValueError("system_prompt must be a string")
        self.canary_in_prompt = "{canary}" in system_prompt
        self.system = system_prompt.replace("{canary}", self.canary)
        if not self.canary_in_prompt:
            self.notices.append("system_prompt does not contain {canary}; extraction attacks cannot detect leaks")
        if not self.api_key and "Authorization" not in self.headers and "api-key" not in self.headers:
            self.notices.append(f"{self.key_env} is not set")
        self.tools = cfg.get("tools") or []
        self.temperature = cfg.get("temperature")
        self.timeout = float(cfg.get("timeout", 60))
        self.retries = int(cfg.get("retries", 2))
        path = cfg.get("path", "/chat/completions")
        self.path = path if str(path).startswith("/") else "/" + str(path)

    @property
    def label(self) -> str:
        return f"openai:{self.model}"

    def _messages(self, prompt: str, context: str | None) -> list[dict]:
        messages = []
        if self.system:
            messages.append({"role": "system", "content": self.system})
        if context and self.context_role == "tool":
            messages.append({"role": "user", "content": prompt})
            messages.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "pitb-ctx",
                            "type": "function",
                            "function": {"name": "read_document", "arguments": "{}"},
                        }
                    ],
                }
            )
            messages.append({"role": "tool", "tool_call_id": "pitb-ctx", "content": context})
            return messages
        messages.append({"role": "user", "content": wrap_context(prompt, context, self.context_template)})
        return messages

    def send(self, prompt, context):
        body = {"model": self.model, "messages": self._messages(prompt, context)}
        if self.tools:
            body["tools"] = self.tools
        if self.temperature is not None:
            body["temperature"] = self.temperature
        data = _post_json(self.base_url + self.path, body, self.headers, self.timeout, self.retries)
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"response has no choices[0].message ({exc})") from None
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function", {}) if isinstance(c, dict) else {}
            calls.append({"name": fn.get("name"), "arguments": fn.get("arguments", "")})
        return Reply(text=_flatten_content(msg.get("content")), tool_calls=calls)


class HTTPTarget(Target):
    """Your own API. Describe the request body and where to find the answer."""

    def __init__(self, cfg: dict):
        super().__init__()
        self.url = cfg["url"]
        self.missing_env: list[str] = []
        self.headers = _string_headers(_expand_env(cfg.get("headers", {}), self.missing_env))
        for name in self.missing_env:
            self.notices.append(f"environment variable {name} is not set; substituting an empty string")
        self.body = cfg.get("body", {"message": "{prompt}"})
        self.response_path = cfg.get("response_path", "reply")
        self.tool_calls_path = cfg.get("tool_calls_path")
        self.timeout = float(cfg.get("timeout", 60))
        self.retries = int(cfg.get("retries", 2))
        # For black-box targets you cannot template the system prompt, so plant a
        # known secret in the app yourself and tell us what it is.
        self.canary = cfg.get("canary", "")
        self.canary_in_prompt = bool(self.canary)
        self.inline_context = cfg.get("inline_context", "{context}" not in json.dumps(self.body))

    @property
    def label(self) -> str:
        return f"http:{self.url}"

    def send(self, prompt, context):
        if self.inline_context:
            prompt, context = wrap_context(prompt, context, self.context_template), None
        body = _fill(self.body, {"prompt": prompt, "context": context or "", "canary": self.canary})
        data = _post_json(self.url, body, self.headers, self.timeout, self.retries)
        text = _dig(data, self.response_path)
        if text is MISSING:
            raise RuntimeError(f"response has no value at {self.response_path!r}")
        if self.tool_calls_path:
            calls = _dig(data, self.tool_calls_path)
            if calls is MISSING:
                raise RuntimeError(f"response has no value at {self.tool_calls_path!r}")
        else:
            calls = []
        if calls is None:
            calls = []
        if not isinstance(calls, list) or any(not isinstance(c, dict) for c in calls):
            raise RuntimeError("tool_calls must be a list of objects with name and arguments")
        if text is None:
            rendered = ""
        elif isinstance(text, str):
            rendered = text
        else:
            rendered = json.dumps(text)
        return Reply(text=rendered, tool_calls=list(calls))


class PythonTarget(Target):
    """A function in your codebase: fn(prompt, context, canary) -> str | dict.

    Called from a worker thread. Use ``--workers 1`` if it is not thread-safe.
    """

    def __init__(self, cfg: dict, base_dir: Path | None = None):
        super().__init__()
        spec = cfg["callable"]
        module_name, _, attr = spec.partition(":")
        if not module_name or not attr:
            raise ValueError(f"callable must be module:function (got {spec!r})")
        if base_dir and str(base_dir) not in sys.path:
            sys.path.insert(0, str(base_dir))
        self.fn = getattr(importlib.import_module(module_name), attr)
        self.spec = spec
        self.canary = cfg.get("canary") or new_canary()

    @property
    def label(self) -> str:
        return f"python:{self.spec}"

    def send(self, prompt, context):
        out = self.fn(prompt, context, self.canary)
        if isinstance(out, dict):
            calls = out.get("tool_calls") or []
            if not isinstance(calls, list) or any(not isinstance(c, dict) for c in calls):
                raise RuntimeError("tool_calls must be a list of objects with name and arguments")
            reply = out.get("reply") or ""
            return Reply(text=reply if isinstance(reply, str) else str(reply), tool_calls=list(calls))
        return Reply(text=str(out))


def build_target(cfg: dict, base_dir: Path | None = None) -> Target:
    if not isinstance(cfg, dict):
        raise ValueError("target must be a mapping")
    kind = cfg.get("type")
    if kind == "openai":
        target = OpenAITarget(cfg)
    elif kind == "http":
        target = HTTPTarget(cfg)
    elif kind == "python":
        target = PythonTarget(cfg, base_dir)
    else:
        raise ValueError(f"target.type must be openai, http or python (got {kind!r})")
    allowed = cfg.get("allowed_tools") or []
    if not isinstance(allowed, list) or any(not isinstance(name, str) for name in allowed):
        raise ValueError("allowed_tools must be a list of tool names")
    target.allowed_tools = list(allowed)
    template = cfg.get("context_template")
    if template is not None and not isinstance(template, str):
        raise ValueError("context_template must be a string")
    target.context_template = template
    role = cfg.get("context_role", "user")
    if role not in ("user", "tool"):
        raise ValueError("context_role must be 'user' or 'tool'")
    target.context_role = role
    if target.canary and len(target.canary) < 8:
        target.notices.append("canary is shorter than 8 characters and may match unrelated text")
    return target
