"""Compact persistent investigation state.

This is the question-relative layer above the analysis machinery. It stores only
state that should change future decisions: the active question, parent goal,
hypotheses, evidence, consequential uncertainties, next action, and stopping rule.

It deliberately does NOT duplicate calltrees, briefs, P-Code, pseudocode, or
knowledge-base observations. Those remain evidence substrates referenced by path
or identifier.
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path

_HERE = Path(__file__).resolve().parent
STATE_PATH = Path(os.environ.get("RE_INVESTIGATION_STATE", _HERE / ".investigation.json"))

VALID_HYPOTHESIS_STATUS = {"open", "supported", "weakened", "rejected"}
VALID_INVESTIGATION_STATUS = {"active", "closed"}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _blank() -> dict:
    return {
        "version": 1,
        "status": "active",
        "target": "",
        "question": "",
        "parent_goal": "",
        "decision_or_understanding": "",
        "constraints": [],
        "hypotheses": [],
        "evidence": [],
        "open_uncertainties": [],
        "next_action": {"action": "", "why": ""},
        "stop_when": "",
        "result": "",
        "residual_uncertainty": "",
        "created_at": _now(),
        "updated_at": _now(),
    }


def load(path: str | os.PathLike | None = None) -> dict | None:
    p = Path(path) if path else STATE_PATH
    if not p.exists():
        return None
    with p.open(encoding="utf-8") as f:
        return json.load(f)


def save(state: dict, path: str | os.PathLike | None = None) -> None:
    p = Path(path) if path else STATE_PATH
    state["updated_at"] = _now()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, p)


def new(question: str, *, target: str = "", parent_goal: str = "",
        decision_or_understanding: str = "", stop_when: str = "",
        constraints: list[str] | None = None) -> dict:
    if not question.strip():
        raise ValueError("question must not be empty")
    state = _blank()
    state.update({
        "target": target.strip(),
        "question": question.strip(),
        "parent_goal": parent_goal.strip(),
        "decision_or_understanding": decision_or_understanding.strip(),
        "stop_when": stop_when.strip(),
        "constraints": [x.strip() for x in (constraints or []) if x.strip()],
    })
    save(state)
    return state


def _require_active() -> dict:
    state = load()
    if state is None:
        raise ValueError("no active investigation; create one first")
    if state.get("status") != "active":
        raise ValueError("investigation is closed; create a new one before recording new work")
    return state


def add_hypothesis(text: str, *, prior: str = "plausible", why_prior: str = "") -> dict:
    state = _require_active()
    hid = f"H{len(state['hypotheses']) + 1}"
    state["hypotheses"].append({
        "id": hid,
        "text": text.strip(),
        "prior": prior.strip(),
        "why_prior": why_prior.strip(),
        "status": "open",
    })
    save(state)
    return state["hypotheses"][-1]


def set_hypothesis_status(hid: str, status: str) -> None:
    if status not in VALID_HYPOTHESIS_STATUS:
        raise ValueError(f"invalid hypothesis status: {status}")
    state = _require_active()
    for h in state["hypotheses"]:
        if h["id"] == hid:
            h["status"] = status
            save(state)
            return
    raise ValueError(f"unknown hypothesis id: {hid}")


def add_evidence(observation: str, *, source: str = "",
                 supports: list[str] | None = None,
                 contradicts: list[str] | None = None) -> dict:
    state = _require_active()
    known = {h["id"] for h in state["hypotheses"]}
    supports = [x for x in (supports or []) if x]
    contradicts = [x for x in (contradicts or []) if x]
    unknown = (set(supports) | set(contradicts)) - known
    if unknown:
        raise ValueError(f"unknown hypothesis id(s): {', '.join(sorted(unknown))}")
    eid = f"E{len(state['evidence']) + 1}"
    entry = {
        "id": eid,
        "observation": observation.strip(),
        "source": source.strip(),
        "supports": supports,
        "contradicts": contradicts,
    }
    state["evidence"].append(entry)
    save(state)
    return entry


def add_uncertainty(text: str) -> None:
    state = _require_active()
    text = text.strip()
    if text and text not in state["open_uncertainties"]:
        state["open_uncertainties"].append(text)
        save(state)


def set_next(action: str, *, why: str = "") -> None:
    state = _require_active()
    state["next_action"] = {"action": action.strip(), "why": why.strip()}
    save(state)


def close(result: str, *, residual_uncertainty: str = "") -> None:
    state = _require_active()
    state["status"] = "closed"
    state["result"] = result.strip()
    state["residual_uncertainty"] = residual_uncertainty.strip()
    save(state)


def summary(state: dict | None = None) -> str:
    state = state or load()
    if state is None:
        return "No investigation state."
    lines = [
        f"INVESTIGATION [{state.get('status', '?')}]",
        f"Question: {state.get('question') or '?'}",
    ]
    if state.get("target"):
        lines.append(f"Target: {state['target']}")
    if state.get("parent_goal"):
        lines.append(f"Parent goal: {state['parent_goal']}")
    if state.get("decision_or_understanding"):
        lines.append(f"Useful result must enable: {state['decision_or_understanding']}")
    if state.get("hypotheses"):
        lines.append("Hypotheses:")
        for h in state["hypotheses"]:
            lines.append(
                f"  {h['id']} [{h['status']}; prior={h['prior']}] {h['text']}"
            )
    if state.get("open_uncertainties"):
        lines.append("Open consequential uncertainties:")
        for x in state["open_uncertainties"]:
            lines.append(f"  - {x}")
    nxt = state.get("next_action", {})
    if nxt.get("action"):
        lines.append(f"Next: {nxt['action']}")
        if nxt.get("why"):
            lines.append(f"  Why: {nxt['why']}")
    if state.get("stop_when"):
        lines.append(f"Stop when: {state['stop_when']}")
    lines.append(
        f"Evidence: {len(state.get('evidence', []))} observation(s); "
        f"{len(state.get('hypotheses', []))} hypothesis/hypotheses"
    )
    if state.get("result"):
        lines.append(f"Result: {state['result']}")
    if state.get("residual_uncertainty"):
        lines.append(f"Residual uncertainty: {state['residual_uncertainty']}")
    return "\n".join(lines)
