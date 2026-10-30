"""A prompt-injection test bench for tool-using agents, scored by canaries."""

from injection_gauntlet.corpus import Attack, Carrier, Control, Corpus, load_corpus
from injection_gauntlet.harness import (
    AgentRequest,
    GauntletResult,
    ToolSpec,
    Trace,
    run_gauntlet,
)
from injection_gauntlet.scoring import AttackScore, score_attack

__all__ = [
    "AgentRequest",
    "Attack",
    "AttackScore",
    "Carrier",
    "Control",
    "Corpus",
    "GauntletResult",
    "ToolSpec",
    "Trace",
    "load_corpus",
    "run_gauntlet",
    "score_attack",
]
