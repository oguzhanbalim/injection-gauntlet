"""Run an agent through the gauntlet and print a canary report."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from injection_gauntlet.corpus import load_corpus
from injection_gauntlet.demo_agents import defended_agent, idle_agent, naive_agent
from injection_gauntlet.harness import Agent, GauntletResult, run_gauntlet
from injection_gauntlet.scoring import FIRED

BUILTIN = {"naive": naive_agent, "defended": defended_agent, "idle": idle_agent}
DEMO_NOTICE = (
    "Demo agent: a fake, rule-based agent with no model behind it. "
    "These numbers test the harness and say nothing about any real model."
)


def load_agent(spec: str) -> Agent:
    if spec in BUILTIN:
        return BUILTIN[spec]
    target, sep, attr = spec.rpartition(":")
    if not sep:
        raise ValueError(f"expected {sorted(BUILTIN)}, module:callable or file.py:callable")
    if target.endswith(".py"):
        path = Path(target).resolve()
        module_spec = importlib.util.spec_from_file_location(path.stem, path)
        if module_spec is None or module_spec.loader is None:
            raise ValueError(f"cannot load {path}")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
    else:
        module = importlib.import_module(target)
    return getattr(module, attr)


def _rate(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:5.0%}"


def _table(title: str, groups: dict[str, dict[str, Any]]) -> list[str]:
    head = f"{title:26} {'attacks':>7} {'fired':>5} {'resist':>6} {'unseen':>6} {'error':>5} "
    lines = [head + f"{'ASR':>5} {'task ok':>7}"]
    for name, b in groups.items():
        lines.append(
            f"{name:26} {b['attacks']:7} {b['fired']:5} {b['resisted']:6} {b['not_exposed']:6} "
            f"{b['errors']:5} {_rate(b['attack_success_rate'])} {b['task_completed']:7}"
        )
    return lines


def render(result: GauntletResult, *, show_fired: bool) -> str:
    lines = [f"agent: {result.agent}"]
    lines += _table("technique", result.grouped("technique"))
    lines += [""] + _table("language", result.grouped("language"))
    lines += [""] + _table("surface", result.grouped("surface"))
    lines += [""] + _table("overall", {"all": result.overall})
    c = result.controls_summary
    lines += [
        "",
        f"controls (no attack): {c['controls']}  task ok {c['task_completed']}  "
        f"unrequested side effects {c['with_unrequested_side_effects']}  errors {c['errors']}",
    ]
    if show_fired:
        lines += ["", "fired:"]
        lines += [f"  {s.id}: {s.evidence}" for s in result.attacks if s.status == FIRED]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="injection-gauntlet", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="run an agent through the corpus")
    run.add_argument("--agent", required=True, help="naive, defended, idle or module:callable")
    run.add_argument("--json", action="store_true")
    run.add_argument("--show-fired", action="store_true", help="list evidence for each hit")
    run.add_argument("--max-asr", type=float, help="exit 1 above this attack success rate")
    run.set_defaults(func=cmd_run)

    listing = commands.add_parser("list", help="list the attacks in the corpus")
    listing.add_argument("--technique")
    listing.add_argument("--language", choices=["en", "tr"])
    listing.set_defaults(func=cmd_list)
    return parser


def cmd_run(args: argparse.Namespace) -> int:
    agent = load_agent(args.agent)
    result = run_gauntlet(agent, load_corpus(), name=args.agent)
    if args.agent in BUILTIN:
        print(DEMO_NOTICE, file=sys.stderr)
    print(result.to_json() if args.json else render(result, show_fired=args.show_fired))
    if args.max_asr is None:
        return 0
    asr = result.overall["attack_success_rate"]
    # An agent that never read anything has not passed. There is no rate to gate on.
    return 0 if asr is not None and asr <= args.max_asr else 1


def cmd_list(args: argparse.Namespace) -> int:
    for attack in load_corpus().attacks:
        if args.technique and attack.technique != args.technique:
            continue
        if args.language and attack.language != args.language:
            continue
        print(
            f"{attack.id:32} {attack.technique:24} {attack.carrier.surface:12} "
            f"{attack.canary.type}"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError, AttributeError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
