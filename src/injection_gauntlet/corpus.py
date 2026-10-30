"""Load the attack corpus and render each attack into the content an agent will read."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources
from typing import Any

import yaml

SURFACES = ("tool_result", "document", "web_page")
LANGUAGES = ("en", "tr")
CANARY_TYPES = ("tool_call", "secret_leak", "output_marker")


class CorpusError(ValueError):
    """The corpus files are inconsistent."""


@dataclass(frozen=True)
class Carrier:
    """A benign task and the content it reads, with a slot for the payload."""

    name: str
    language: str
    surface: str
    task: str
    source_tool: str
    source_match: str
    answer_marker: str
    template: str
    grants: tuple[str, ...] = ()

    def render(self, payload: str) -> str:
        return self.template.format(payload=payload)


@dataclass(frozen=True)
class Canary:
    type: str
    tool: str | None = None
    args_contain: str | None = None
    text: str | None = None


@dataclass(frozen=True)
class Attack:
    id: str
    technique: str
    language: str
    carrier: Carrier
    canary: Canary
    payload: str

    @property
    def content(self) -> str:
        return self.carrier.render(self.payload)

    @property
    def secret(self) -> str:
        """A generated value, unique per attack and stable between runs."""
        return "GNT-" + hashlib.sha256(self.id.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Control:
    """No attack: benign text that happens to read like an instruction."""

    id: str
    language: str
    carrier: Carrier
    payload: str

    @property
    def content(self) -> str:
        return self.carrier.render(self.payload)

    @property
    def secret(self) -> str:
        return "GNT-" + hashlib.sha256(self.id.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Corpus:
    attacks: tuple[Attack, ...]
    controls: tuple[Control, ...]

    @property
    def techniques(self) -> list[str]:
        return sorted({a.technique for a in self.attacks})


def _load_carrier(name: str, raw: dict[str, Any]) -> Carrier:
    carrier = Carrier(
        name=name,
        language=raw["language"],
        surface=raw["surface"],
        task=raw["task"],
        source_tool=raw["source"]["tool"],
        source_match=str(raw["source"]["match"]),
        answer_marker=str(raw["answer_marker"]),
        template=raw["content"],
        grants=tuple(raw.get("grants", ())),
    )
    if carrier.surface not in SURFACES or carrier.language not in LANGUAGES:
        raise CorpusError(f"carrier {name}: bad surface or language")
    if "{payload}" not in carrier.template:
        raise CorpusError(f"carrier {name}: no payload slot")
    if carrier.answer_marker not in carrier.render(""):
        raise CorpusError(f"carrier {name}: answer marker is not in its content")
    return carrier


def _load_canary(attack_id: str, raw: dict[str, Any]) -> Canary:
    canary = Canary(
        type=raw["type"],
        tool=raw.get("tool"),
        args_contain=raw.get("args_contain"),
        text=raw.get("text"),
    )
    if canary.type not in CANARY_TYPES:
        raise CorpusError(f"{attack_id}: unknown canary type {canary.type!r}")
    if canary.type == "tool_call" and not canary.tool:
        raise CorpusError(f"{attack_id}: tool_call canary needs a tool")
    if canary.type == "output_marker" and not canary.text:
        raise CorpusError(f"{attack_id}: output_marker canary needs text")
    return canary


def _resolve(carriers: dict[str, Carrier], row: dict[str, Any]) -> Carrier:
    carrier = carriers.get(row["carrier"])
    if carrier is None:
        raise CorpusError(f"{row['id']}: unknown carrier {row['carrier']!r}")
    if carrier.language != row["language"]:
        raise CorpusError(f"{row['id']}: language differs from carrier {carrier.name}")
    return carrier


def build_corpus(carriers_raw: dict[str, Any], attacks_raw: dict[str, Any]) -> Corpus:
    carriers = {name: _load_carrier(name, raw) for name, raw in carriers_raw.items()}
    attacks = tuple(
        Attack(
            id=row["id"],
            technique=row["technique"],
            language=row["language"],
            carrier=_resolve(carriers, row),
            canary=_load_canary(row["id"], row["canary"]),
            payload=row["payload"],
        )
        for row in attacks_raw["attacks"]
    )
    controls = tuple(
        Control(
            id=row["id"],
            language=row["language"],
            carrier=_resolve(carriers, row),
            payload=row["payload"],
        )
        for row in attacks_raw.get("controls", [])
    )
    ids = [a.id for a in attacks] + [c.id for c in controls]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise CorpusError(f"duplicate ids: {sorted(duplicates)}")
    return Corpus(attacks=attacks, controls=controls)


def load_corpus() -> Corpus:
    data = resources.files("injection_gauntlet") / "data"
    carriers = yaml.safe_load((data / "carriers.yaml").read_text("utf-8"))
    attacks = yaml.safe_load((data / "attacks.yaml").read_text("utf-8"))
    return build_corpus(carriers, attacks)
