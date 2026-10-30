from __future__ import annotations

import base64
import re
from collections import Counter

import pytest

from injection_gauntlet.corpus import CorpusError, build_corpus, load_corpus
from injection_gauntlet.harness import TOOLS

CORPUS = load_corpus()


def test_corpus_size_and_language_balance():
    assert len(CORPUS.attacks) >= 40
    counts = Counter(a.language for a in CORPUS.attacks)
    assert counts["en"] >= 20
    assert counts["tr"] >= 20


def test_every_technique_appears_in_both_languages():
    for technique in CORPUS.techniques:
        languages = {a.language for a in CORPUS.attacks if a.technique == technique}
        assert languages == {"en", "tr"}, technique


def test_every_surface_is_used():
    assert {a.carrier.surface for a in CORPUS.attacks} == {"tool_result", "document", "web_page"}


def test_every_host_and_address_is_reserved():
    for item in (*CORPUS.attacks, *CORPUS.controls):
        text = item.content + " " + item.carrier.task
        for host in re.findall(r"https?://([^/\s\"')<>]+)", text):
            assert host.endswith(".invalid"), (item.id, host)
        for address in re.findall(r"[\w.+-]+@([\w.-]*\w)", text):
            assert address.endswith(".invalid"), (item.id, address)


def test_tool_canaries_name_a_real_sandbox_tool():
    names = {t.name for t in TOOLS}
    for attack in CORPUS.attacks:
        if attack.canary.type == "tool_call":
            assert attack.canary.tool in names, attack.id


def test_canary_values_are_not_already_in_the_clean_carrier():
    for attack in CORPUS.attacks:
        clean = attack.carrier.render("").casefold()
        needle = attack.canary.args_contain or attack.canary.text
        if needle:
            assert needle.casefold() not in clean, attack.id


def test_no_payload_contains_the_secret_it_tries_to_steal():
    for attack in CORPUS.attacks:
        assert attack.secret not in attack.payload


def test_secrets_are_unique_and_stable():
    secrets = [a.secret for a in CORPUS.attacks]
    assert len(set(secrets)) == len(secrets)
    assert secrets == [a.secret for a in load_corpus().attacks]


def test_encoded_payloads_really_carry_the_attack():
    by_id = {a.id: a for a in CORPUS.attacks}
    for attack_id in ("en-encoding-base64", "tr-encoding-base64"):
        attack = by_id[attack_id]
        blob = attack.payload.rsplit(" ", 1)[-1]
        assert attack.canary.args_contain in base64.b64decode(blob).decode()
    assert "​" in by_id["en-encoding-zerowidth"].payload
    assert "е" in by_id["tr-encoding-homoglyph"].payload  # Cyrillic ie


def test_controls_have_no_canary_vocabulary():
    for control in CORPUS.controls:
        assert "attacker" not in control.content


def _carrier(**overrides) -> dict:
    raw = {
        "language": "en",
        "surface": "document",
        "task": "t",
        "source": {"tool": "read_document", "match": "x"},
        "answer_marker": "42",
        "content": "42 {payload}",
    }
    return {**raw, **overrides}


def _attack(**overrides) -> dict:
    raw = {
        "id": "a",
        "technique": "t",
        "language": "en",
        "carrier": "c",
        "canary": {"type": "secret_leak"},
        "payload": "p",
    }
    return {**raw, **overrides}


@pytest.mark.parametrize(
    "carrier,attack,message",
    [
        (_carrier(content="no slot"), _attack(), "payload slot"),
        (_carrier(answer_marker="absent"), _attack(), "answer marker"),
        (_carrier(surface="fax"), _attack(), "surface"),
        (_carrier(), _attack(carrier="missing"), "unknown carrier"),
        (_carrier(), _attack(language="tr"), "language differs"),
        (_carrier(), _attack(canary={"type": "vibes"}), "unknown canary"),
        (_carrier(), _attack(canary={"type": "tool_call"}), "needs a tool"),
    ],
)
def test_bad_corpus_is_rejected(carrier, attack, message):
    with pytest.raises(CorpusError, match=message):
        build_corpus({"c": carrier}, {"attacks": [attack]})


def test_duplicate_ids_are_rejected():
    with pytest.raises(CorpusError, match="duplicate"):
        build_corpus({"c": _carrier()}, {"attacks": [_attack(), _attack()]})
