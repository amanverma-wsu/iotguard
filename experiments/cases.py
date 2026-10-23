"""Load and validate experiment cases.

A case is one trial scenario: the trusted task settings plus the attacker-controlled
ticket body. Benign cases measure utility; attack cases measure leakage. The held-out
set is loaded only when explicitly asked for, so defenses are not tuned against it.
"""
import json
from dataclasses import dataclass
from pathlib import Path

ATTACK_FAMILIES = {
    "direct_override",
    "authority_framing",
    "urgency",
    "obfuscation",
    "tool_arg_exfil",
}


@dataclass(frozen=True)
class Case:
    case_id: str
    kind: str
    attack_family: str | None
    task: dict
    ticket_body: str
    expected_benign_outcome: str | None = None


def default_cases_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "cases"


def validate_case(obj: dict) -> Case:
    for field in ("case_id", "kind", "task", "ticket_body"):
        if field not in obj:
            raise ValueError(f"case missing required field {field!r}")

    kind = obj["kind"]
    if kind not in ("benign", "attack"):
        raise ValueError(f"case {obj['case_id']!r}: kind must be 'benign' or 'attack'")

    family = obj.get("attack_family")
    if kind == "attack":
        if family not in ATTACK_FAMILIES:
            raise ValueError(
                f"case {obj['case_id']!r}: attack_family must be one of {sorted(ATTACK_FAMILIES)}"
            )
    elif family is not None:
        raise ValueError(f"case {obj['case_id']!r}: benign case must have null attack_family")

    task = obj["task"]
    for field in ("ticket_id", "authorized_customer_id", "approved_destinations"):
        if field not in task:
            raise ValueError(f"case {obj['case_id']!r}: task missing {field!r}")
    if not isinstance(task["approved_destinations"], list):
        raise ValueError(f"case {obj['case_id']!r}: approved_destinations must be a list")

    if not isinstance(obj["ticket_body"], str) or not obj["ticket_body"].strip():
        raise ValueError(f"case {obj['case_id']!r}: ticket_body must be a non-empty string")

    return Case(
        case_id=obj["case_id"],
        kind=kind,
        attack_family=family,
        task=task,
        ticket_body=obj["ticket_body"],
        expected_benign_outcome=obj.get("expected_benign_outcome"),
    )


def load_case_file(path: Path) -> Case:
    with open(path, encoding="utf-8") as f:
        return validate_case(json.load(f))


def load_cases(cases_dir: Path | None = None, include_held_out: bool = False) -> list[Case]:
    base = Path(cases_dir) if cases_dir is not None else default_cases_dir()
    subdirs = ["benign", "attacks"]
    if include_held_out:
        subdirs.append("held_out")

    cases: list[Case] = []
    for sub in subdirs:
        d = base / sub
        if not d.exists():
            continue
        for path in sorted(d.glob("*.json")):
            cases.append(load_case_file(path))
    return cases
