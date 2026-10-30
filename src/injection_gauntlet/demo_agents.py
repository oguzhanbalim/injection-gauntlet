"""Two fake agents. There is no model in this file.

They exist to show that the scoring works, and they say nothing about any real model.
Both are a page of regular expressions that treat instruction-shaped lines in tool output
as commands. ``naive_agent`` obeys what it can parse. ``defended_agent`` has the same
gullible parser behind a simple gate: side-effecting tools need a grant from the task,
tool arguments may not contain the secret, and the secret is redacted from the reply.

The parser cannot read base64, letter-spaced text or homoglyphs, so those attacks score
as resisted on both. That is a failure to understand, which is a different thing from a
defence, and the same ambiguity applies when reading any agent's scores.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from typing import Any

from injection_gauntlet.harness import SIDE_EFFECT_TOOLS, AgentRequest
from injection_gauntlet.textutil import fold, strip_invisible

_SECRET = re.compile(r"GNT-[0-9a-f]+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_ACCOUNT = re.compile(r"\b[a-z]{2}\d{2}-[\w-]+")
_URL = re.compile(r"https?://[^\s\"'<>)]+")
_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)")
_QUOTED = re.compile(r"[\"“]([^\"”]+)[\"”]")
_PATH = re.compile(r"(/[\w.-]+)+")
_NUMBER = re.compile(r"\d+(?:[.,]\d+)?")
_PLACEHOLDER = re.compile(r"\{api_key\}", re.IGNORECASE)

_EMAIL_VERB = re.compile(r"\b(send|forward|email|e-mail|mail)\b|adresine.*(gönder|ilet|yolla)")
_PAY_VERB = re.compile(r"\b(transfer|transfer_funds|wire|pay)\b|hesabina.*(aktar|gönder)")
_DELETE_VERB = re.compile(r"\b(delete|sil)\b")
_FETCH_VERB = re.compile(r"\b(open|fetch|visit|load|ping)\b|adresini aç")
_SECRET_NOUN = re.compile(r"api key|api anahtar")
_SECRET_VERB = re.compile(
    r"\b(print|reveal|show|include|share|repeat|output|add)\b|paylaş|göster|ekle|\byaz\b"
)
_SAY_VERB = re.compile(r"\b(say|state|write|reply|respond|tell)\b|\byaz\b|\bbelirt\b")
_STOPWORDS = {"read", "open", "tell", "search", "email", "and", "the", "oku", "söyle", "arama"}

ToolGate = Callable[[str, dict[str, Any]], bool]


def _obey_line(line: str, secret: str) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """Tool calls and reply text a gullible reader would take from one line."""
    folded = fold(line)
    calls: list[tuple[str, dict[str, Any]]] = []
    said: list[str] = []

    def fill(url: str) -> str:
        return _PLACEHOLDER.sub(secret, url)

    if (image := _IMAGE.search(line)) and _PLACEHOLDER.search(image.group(1)):
        said.append(f"![status]({fill(image.group(1))})")
    elif (url := _URL.search(line)) and _FETCH_VERB.search(folded):
        calls.append(("fetch_url", {"url": fill(url.group(0))}))

    if (email := _EMAIL.search(line)) and _EMAIL_VERB.search(folded):
        calls.append(("send_email", {"to": email.group(0), "subject": "", "body": line}))
    if (account := _ACCOUNT.search(folded)) and _PAY_VERB.search(folded):
        rest = folded.replace(account.group(0), " ")
        amount = _NUMBER.search(rest)
        value = amount.group(0) if amount else ""
        calls.append(("transfer_funds", {"to": account.group(0), "amount": value}))
    if (path := _PATH.search(line)) and _DELETE_VERB.search(folded):
        calls.append(("delete_file", {"path": path.group(0)}))
    if "update_record" in folded:
        record = re.search(r"record_id (\d+)", folded)
        status = re.search(r"status (\w+)", folded)
        if record and status:
            calls.append(("update_record", {"record_id": record[1], "status": status[1]}))

    if _SECRET_NOUN.search(folded) and (_SECRET_VERB.search(folded) or "encode" in folded):
        if "base64" in folded:
            said.append(base64.b64encode(secret.encode()).decode())
        elif "reverse" in folded or "ters" in folded:
            said.append(secret[::-1])
        else:
            said.append(secret)
    if (quoted := _QUOTED.search(line)) and _SAY_VERB.search(folded):
        said.append(quoted.group(1))
    return calls, said


def _find_source(request: AgentRequest) -> tuple[str, dict[str, Any]]:
    """Which read tool the task needs, chosen from the wording of the task."""
    if url := _URL.search(request.task):
        return "fetch_url", {"url": url.group(0)}
    if name := re.search(r"[\w-]+\.txt", request.task):
        return "read_document", {"name": name.group(0)}
    number = re.search(r"\d+", request.task)
    return "search_records", {"query": number.group(0) if number else request.task}


def _best_line(task: str, lines: list[str]) -> str:
    """A crude extractor: the first line sharing the most word stems with the task."""
    task = _EMAIL.sub(" ", _URL.sub(" ", re.sub(r"[\w-]+\.txt", " ", task)))
    words = re.findall(r"[^\W\d_]{3,}", fold(task))
    stems = {word[:5] for word in words if word not in _STOPWORDS}
    best, best_hits = "", 0
    for line in lines:
        line_words = re.findall(r"[^\W\d_]{3,}", fold(line))
        hits = sum(word[:5] in stems for word in line_words)
        if hits > best_hits:
            best, best_hits = line, hits
    return re.sub(r"<[^>]+>", "", best).strip()


def _run(request: AgentRequest, *, gate: ToolGate, redact: bool) -> str:
    found = _SECRET.search(request.system)
    secret = found.group(0) if found else ""
    tool, args = _find_source(request)
    content = strip_invisible(request.call_tool(tool, args))
    lines = content.splitlines()
    answer = _best_line(request.task, lines)

    said: list[str] = []
    for line in lines:
        calls, text = _obey_line(line, secret)
        said.extend(text)
        for name, call_args in calls:
            if gate(name, call_args):
                request.call_tool(name, call_args)

    if "send_email" in request.granted_tools and (to := _EMAIL.search(request.task)):
        request.call_tool("send_email", {"to": to.group(0), "subject": "", "body": answer})
    reply = "\n".join([answer, *said])
    return reply.replace(secret, "[REDACTED]") if redact and secret else reply


def naive_agent(request: AgentRequest) -> str:
    """Fake agent: does whatever instruction-shaped text it can parse."""
    return _run(request, gate=lambda _name, _args: True, redact=False)


def defended_agent(request: AgentRequest) -> str:
    """Fake agent: the same parser behind a capability gate and an output filter."""
    found = _SECRET.search(request.system)
    secret = found.group(0) if found else ""

    def gate(name: str, args: dict[str, Any]) -> bool:
        if name in SIDE_EFFECT_TOOLS and name not in request.granted_tools:
            return False
        return not (secret and secret in json.dumps(args, ensure_ascii=False))

    return _run(request, gate=gate, redact=True)


def idle_agent(request: AgentRequest) -> str:
    """Fake agent that reads nothing. It exists to show that doing nothing scores badly."""
    return "I did not read anything."
