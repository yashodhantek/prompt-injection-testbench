from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from .detectors import validate_detect


@dataclass
class Attack:
    id: str
    category: str
    name: str
    prompt: str
    context: str | None = None
    detect: list[dict] = field(default_factory=list)
    notes: str = ""

    def render(self, marker: str) -> Attack:
        """Fill in the {marker} placeholder used by indirect attacks."""

        def sub(value):
            if isinstance(value, str):
                return value.replace("{marker}", marker)
            if isinstance(value, list):
                return [sub(item) for item in value]
            if isinstance(value, dict):
                return {key: sub(item) for key, item in value.items()}
            return value

        return Attack(
            id=self.id,
            category=self.category,
            name=self.name,
            prompt=self.prompt.replace("{marker}", marker),
            context=self.context.replace("{marker}", marker) if self.context else None,
            detect=[sub(item) for item in self.detect],
            notes=self.notes,
        )


def _parse(raw, source: str) -> list[Attack]:
    if not isinstance(raw, list):
        raise ValueError(f"{source}: pack must be a list of attacks")
    attacks = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError(f"{source}: each attack must be a mapping")
        missing = {"id", "category", "name", "prompt", "detect"} - item.keys()
        if missing:
            raise ValueError(f"{source}: attack {item.get('id', '?')} is missing {', '.join(sorted(missing))}")
        attack_id = item["id"]
        if not isinstance(attack_id, str) or not attack_id:
            raise ValueError(f"{source}: attack id must be a non-empty string")
        if not isinstance(item["prompt"], str):
            raise ValueError(f"{source}: attack {attack_id} prompt must be a string")
        context = item.get("context")
        if context is not None and not isinstance(context, str):
            raise ValueError(f"{source}: attack {attack_id} context must be a string")
        detect_raw = item["detect"]
        if not isinstance(detect_raw, list):
            raise ValueError(f"{source}: attack {attack_id} detect must be a list")
        validate_detect(detect_raw, f"{source}: {attack_id}")
        detect = []
        for entry in detect_raw:
            if isinstance(entry, dict):
                if "all" in entry:
                    nested = []
                    for sub in entry["all"]:
                        nested.append(sub if isinstance(sub, dict) else {sub: True})
                    detect.append({"all": nested})
                else:
                    detect.append(entry)
            else:
                detect.append({entry: True})
        notes = item.get("notes", "")
        if not isinstance(notes, str):
            raise ValueError(f"{source}: attack {attack_id} notes must be a string")
        attacks.append(
            Attack(
                id=attack_id,
                category=str(item["category"]),
                name=str(item["name"]),
                prompt=item["prompt"].strip(),
                context=context,
                detect=detect,
                notes=notes,
            )
        )
    return attacks


def builtin_packs() -> list[str]:
    files = resources.files("pitb").joinpath("packs").iterdir()
    return sorted(p.name.removesuffix(".yaml") for p in files if p.name.endswith(".yaml"))


def load_pack(name_or_path: str) -> list[Attack]:
    path = Path(name_or_path)
    if path.suffix in (".yaml", ".yml") and path.exists():
        return _parse(yaml.safe_load(path.read_text(encoding="utf-8")) or [], str(path))
    res = resources.files("pitb").joinpath("packs", f"{name_or_path}.yaml")
    if not res.is_file():
        raise ValueError(f"unknown pack '{name_or_path}' (built-in packs: {', '.join(builtin_packs())})")
    return _parse(yaml.safe_load(res.read_text(encoding="utf-8")) or [], name_or_path)


def load_attacks(packs: list[str] | None = None) -> list[Attack]:
    names = packs or builtin_packs()
    attacks: list[Attack] = []
    for name in names:
        attacks.extend(load_pack(name))
    ids = [a.id for a in attacks]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate attack ids: {', '.join(sorted(dupes))}")
    return attacks
