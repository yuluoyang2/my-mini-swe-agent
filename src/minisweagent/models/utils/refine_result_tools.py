from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from minisweagent.models.utils.chain_result_tools import (
    DEFAULT_DATA_ROOT,
    INT_VALUE_RE,
    REPO_ROOT,
    safe_filename,
    validate_chain_result,
    validate_step_refinements,
)
from minisweagent.models.utils.syzlang_tools import is_refinable, read_syzlang_level


def resolve_chain_path(target: str, path: str | None, data_root: Path) -> Path:
    result = Path(path) if path else data_root / "results" / f"{safe_filename(target)}.chains.json"
    return result if result.is_absolute() else REPO_ROOT / result


def load_chain_result(
    target: str,
    *,
    path: str | None = None,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    source_path = resolve_chain_path(target, path, data_root)
    result = json.loads(source_path.read_text())
    if result.get("target") != target:
        raise ValueError(f"chain result target is {result.get('target')!r}, expected {target!r}")
    validate_chain_result(target, result.get("chains"))
    return {
        "path": source_path.as_posix(),
        "target": target,
        "chains": result["chains"],
        "fuzz_guidance": result.get("fuzz_guidance"),
    }


def read_chain_result(
    target: str,
    *,
    path: str | None = None,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    source = load_chain_result(target, path=path, data_root=data_root)
    return {
        "target": source["target"],
        "chains": [
            {"chain": [{"call": step["call"]} for step in record["chain"]]}
            for record in source["chains"]
        ],
    }


def call_union(chains: list[dict[str, Any]]) -> list[str]:
    found = []
    for record in chains:
        for step in record["chain"]:
            if step["call"] not in found:
                found.append(step["call"])
    return found


def validate_calls(calls: list[dict[str, Any]], allowed: set[str], loc: str, *, data_root: Path) -> None:
    if not isinstance(calls, list):
        raise ValueError(f"{loc} must be a list")
    got = []
    for index, item in enumerate(calls):
        if not isinstance(item, dict) or not isinstance(item.get("call"), str) or not item["call"]:
            raise ValueError(f"{loc}[{index}] must contain a non-empty call")
        if item["call"] not in allowed:
            raise ValueError(f"{loc}[{index}] call {item['call']} is not in the chains")
        if not item.get("refinements"):
            raise ValueError(f"{loc}[{index}] must contain refinements")
        validate_step_refinements(item, f"{loc}[{index}]")
        got.append(item["call"])
    if len(got) != len(set(got)):
        raise ValueError(f"{loc} lists a syscall more than once")
    for index, item in enumerate(calls):
        for refinement_index, refinement in enumerate(item.get("refinements") or []):
            ref_loc = f"{loc}[{index}].refinements[{refinement_index}]"
            level = read_syzlang_level(item["call"], refinement["path"], data_root=data_root)
            node = level["node"]
            if node.get("kind") != refinement["kind"]:
                raise ValueError(f"{ref_loc}.kind does not match syzlang node kind {node.get('kind')!r}")
            if node["kind"] == "scalar":
                raise ValueError(
                    f"{ref_loc} must not recommend an integer; "
                    "numeric values stay with syzkaller. Recommend union, flags, named const, and string only."
                )
            if node["kind"] == "const" and any(INT_VALUE_RE.fullmatch(value) for value in refinement["keep"]):
                raise ValueError(f"{ref_loc} must keep a named const, not a raw integer")
            if not is_refinable(node):
                raise ValueError(
                    f"{ref_loc} cannot constrain {node.get('expression', node.get('type'))}; "
                    "len, bytesize, bitsize, csum, proc, and resource stay with syzkaller"
                )
            if node.get("type") != refinement["type"]:
                raise ValueError(f"{ref_loc}.type does not match syzlang node type {node.get('type')!r}")
            choices = choice_names(level)
            if choices:
                unknown = sorted(set(refinement["keep"]) - choices)
                if unknown:
                    raise ValueError(f"{ref_loc}.keep contains unknown choices: {', '.join(unknown)}")


def choice_names(level: dict[str, Any]) -> set[str]:
    return {
        choice["name"] if isinstance(choice, dict) else choice
        for choice in level.get("choices", [])
    }


def drop_unchanged_keeps(calls: list[dict[str, Any]], *, data_root: Path) -> list[dict[str, Any]]:
    kept = []
    for item in calls:
        refinements = []
        for refinement in item["refinements"]:
            names = choice_names(read_syzlang_level(item["call"], refinement["path"], data_root=data_root))
            if names and set(refinement["keep"]) == names:
                continue
            refinements.append(refinement)
        if refinements:
            kept.append({"call": item["call"], "refinements": refinements})
    return kept


def write_refine_result(
    target: str,
    calls: list[dict[str, Any]],
    *,
    chain_path: str | None = None,
    path: str | None = None,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    source = load_chain_result(target, path=chain_path, data_root=data_root)
    validate_calls(calls, set(call_union(source["chains"])), "calls", data_root=data_root)
    calls = drop_unchanged_keeps(calls, data_root=data_root)
    source_path = Path(source["path"])
    output_path = Path(path) if path else source_path.with_name(f"{safe_filename(target)}.refine.json")
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = {"target": target, "calls": calls}
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return {
        "path": output_path.as_posix(),
        "target": target,
        "calls": len(calls),
        "refinements": sum(len(call.get("refinements") or []) for call in calls),
    }
