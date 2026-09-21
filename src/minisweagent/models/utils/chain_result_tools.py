from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_ROOT = REPO_ROOT / "data/linux-6.6"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data/linux-6.6/results"


def safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "target"


@lru_cache
def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text())


def syscall_names(data_root: Path) -> set[str]:
    index = read_json(str(data_root / "syzlang/syzlang.index.json"))
    return {
        name
        for name, records in index.items()
        if any(record.get("kind") == "syscall" for record in records)
    }


def syscall_deps(data_root: Path) -> dict[str, dict[str, Any]]:
    return {
        record["syscall"]: {
            "depend": [item["syscall"] for item in record.get("depend", [])],
            "depended": [item["syscall"] for item in record.get("depended", [])],
        }
        for record in read_json(str(data_root / "syzlang/syz_depend_inout.json"))
    }


def step_calls(chain: list[dict[str, Any]]) -> list[str]:
    return [step["call"] for step in chain]


def step_fingerprint(step: dict[str, Any]) -> str:
    return json.dumps(step, sort_keys=True, ensure_ascii=False)


PARAM_KINDS = {"union", "const", "flags"}


def validate_step_params(step: dict[str, Any], loc: str) -> None:
    params = step.get("params")
    if params is None:
        return
    if not isinstance(params, list):
        raise ValueError(f"{loc}.params must be a list")
    for param_index, param in enumerate(params):
        prefix = f"{loc}.params[{param_index}]"
        if not isinstance(param, dict):
            raise ValueError(f"{prefix} must be an object")
        kind = str(param.get("kind") or "").lower()
        if kind not in PARAM_KINDS:
            raise ValueError(f"{prefix}.kind must be union, const, or flags")
        if kind == "union" and not param.get("path"):
            raise ValueError(f"{prefix} union requires path")
        if kind in {"const", "flags"}:
            values = param.get("values")
            if not isinstance(values, list) or not values:
                raise ValueError(f"{prefix} {kind} requires a non-empty values list")


def is_producer(call: str, deps: dict[str, dict[str, Any]]) -> bool:
    return bool(deps.get(call, {}).get("depended"))


def is_generic_syscall(call: str) -> bool:
    return "$" not in call


def resource_group_satisfied(calls: list[str], deps: dict[str, dict[str, Any]]) -> bool:
    needs_resource = False
    satisfied = False
    earlier: list[str] = []
    for call in calls:
        need = set(deps.get(call, {}).get("depend", []))
        if need:
            needs_resource = True
            if any(prev in need for prev in earlier):
                satisfied = True
            elif is_generic_syscall(call) and any(is_producer(prev, deps) for prev in earlier):
                satisfied = True
        earlier.append(call)
    return (not needs_resource) or satisfied


def validate_chain_result(target: str, chains: list[dict[str, Any]]) -> None:
    if not target:
        raise ValueError("target must not be empty")
    if not chains:
        raise ValueError("chains must contain at least one candidate chain")
    for chain_index, record in enumerate(chains):
        if not isinstance(record, dict):
            raise ValueError(f"chains[{chain_index}] must be an object")
        chain = record.get("chain")
        if not isinstance(chain, list) or not chain:
            raise ValueError(f"chains[{chain_index}].chain must be a non-empty list")
        for step_index, step in enumerate(chain):
            if not isinstance(step, dict) or not isinstance(step.get("call"), str) or not step["call"]:
                raise ValueError(f"chains[{chain_index}].chain[{step_index}] must contain a non-empty call")
            validate_step_params(step, f"chains[{chain_index}].chain[{step_index}]")
        evidence = record.get("evidence", [])
        if evidence is not None and not isinstance(evidence, list):
            raise ValueError(f"chains[{chain_index}].evidence must be a list when present")


def validate_chain_semantics(chains: list[dict[str, Any]], *, data_root: Path) -> list[dict[str, Any]]:
    known = syscall_names(data_root)
    deps = syscall_deps(data_root)
    missing = sorted({
        step["call"]
        for record in chains
        for step in record["chain"]
        if step["call"] not in known
    })
    if missing:
        raise ValueError(
            "Unknown syzkaller syscall(s): "
            + ", ".join(missing)
            + ". Use search_syzlang/read_syzlang_def to find real names."
        )

    warnings = []
    for chain_index, record in enumerate(chains):
        calls = step_calls(record["chain"])
        if not resource_group_satisfied(calls, deps):
            raise ValueError(
                f"chains[{chain_index}] has no satisfied resource-flow group: {calls}. "
                "At least one consumer must be paired with an earlier producer in the same chain."
            )

    fingerprints = {}
    for chain_index, record in enumerate(chains):
        fingerprint = tuple(step_fingerprint(step) for step in record["chain"])
        previous = fingerprints.setdefault(fingerprint, chain_index)
        if previous != chain_index:
            raise ValueError(
                f"chains[{chain_index}] repeats chains[{previous}] with the same syscall sequence: "
                f"{step_calls(record['chain'])}. Drop the duplicate and keep one copy. "
                "Same calls with different params are distinct; do not merge them."
            )
    return warnings


def validate_fuzz_guidance(fuzz_guidance: dict[str, Any] | None) -> None:
    if fuzz_guidance is None:
        return
    if not isinstance(fuzz_guidance, dict):
        raise ValueError("fuzz_guidance must be an object when present")
    limits = {
        "focus_target_functions": 1,
        "focus_hop1_functions": 3,
        "focus_hop2_functions": 3,
        "focus_subsystem_files": 3,
    }
    for key, limit in limits.items():
        value = fuzz_guidance.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"fuzz_guidance.{key} must be a list of strings")
        if len(value) > limit:
            raise ValueError(f"fuzz_guidance.{key} must contain at most {limit} items")
    for path in fuzz_guidance.get("focus_subsystem_files", []):
        if Path(path).suffix in {".h", ".hpp", ".hh", ".hxx"}:
            raise ValueError("fuzz_guidance.focus_subsystem_files must not contain header files")


def write_chain_result(
    target: str,
    chains: list[dict[str, Any]],
    *,
    fuzz_guidance: dict[str, Any] | None = None,
    path: str | None = None,
    data_root: Path = DEFAULT_DATA_ROOT,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    validate_chain_result(target, chains)
    validation_warnings = validate_chain_semantics(chains, data_root=data_root)
    validate_fuzz_guidance(fuzz_guidance)
    output_path = Path(path) if path else output_dir / f"{safe_filename(target)}.chains.json"
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = {"target": target, "chains": chains}
    if fuzz_guidance is not None:
        result["fuzz_guidance"] = fuzz_guidance
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return {
        "path": output_path.as_posix(),
        "target": target,
        "chains": len(chains),
        "has_fuzz_guidance": fuzz_guidance is not None,
        "validation_warnings": validation_warnings,
    }
