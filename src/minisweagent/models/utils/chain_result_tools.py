from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from minisweagent.models.utils.kernel_source_tools import read_json, source_dir
from minisweagent.models.utils.syzlang_tools import is_refinable, read_syzlang_level

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_ROOT = REPO_ROOT / "data/linux-6.6"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data/linux-6.6/results"
REFINEMENT_KINDS = {"union", "flags", "const", "scalar", "string"}
INT_VALUE_RE = re.compile(r"-?(?:0x[0-9a-fA-F]+|\d+)\Z")


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


def call_name(step: str | dict[str, Any]) -> str:
    return step if isinstance(step, str) else step["call"]


def step_calls(chain: list[str | dict[str, Any]]) -> list[str]:
    return [call_name(step) for step in chain]


def step_fingerprint(step: str | dict[str, Any]) -> str:
    return json.dumps(
        {"call": call_name(step), "refinements": step.get("refinements", []) if isinstance(step, dict) else []},
        sort_keys=True,
        ensure_ascii=False,
    )


def validate_step_refinements(step: dict[str, Any], loc: str) -> None:
    if "params" in step:
        raise ValueError(f"{loc} must use refinements instead of params")
    refinements = step.get("refinements", [])
    if not isinstance(refinements, list):
        raise ValueError(f"{loc}.refinements must be a list")
    for index, refinement in enumerate(refinements):
        ref_loc = f"{loc}.refinements[{index}]"
        if not isinstance(refinement, dict):
            raise ValueError(f"{ref_loc} must be an object")
        if refinement.get("kind") not in REFINEMENT_KINDS:
            raise ValueError(f"{ref_loc}.kind must be union, flags, const, scalar, or string")
        for key in ("path", "type"):
            if not isinstance(refinement.get(key), str) or not refinement[key]:
                raise ValueError(f"{ref_loc}.{key} must be a non-empty string")
        keep = refinement.get("keep")
        if not isinstance(keep, list) or not keep or not all(isinstance(value, str) and value for value in keep):
            raise ValueError(f"{ref_loc}.keep must be a non-empty list of strings")
        if len(keep) != len(set(keep)):
            raise ValueError(f"{ref_loc}.keep must not contain duplicates")


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
            if isinstance(step, str) and step:
                continue
            if isinstance(step, dict) and isinstance(step.get("call"), str) and step["call"]:
                validate_step_refinements(step, f"chains[{chain_index}].chain[{step_index}]")
                continue
            raise ValueError(f"chains[{chain_index}].chain[{step_index}] must contain a non-empty call")
        if "evidence" in record:
            raise ValueError(f"chains[{chain_index}] must not include evidence; write stack instead")
        stack = record.get("stack")
        if (
            not isinstance(stack, list)
            or not stack
            or len(stack) > 4
            or not all(isinstance(name, str) and name for name in stack)
        ):
            raise ValueError(f"chains[{chain_index}].stack must be 1 to 4 kernel function names")


def validate_stack_names(chains: list[dict[str, Any]], *, data_root: Path) -> None:
    index = read_json(str(source_dir(data_root) / "func.index.json"))
    for chain_index, record in enumerate(chains):
        missing = [name for name in record.get("stack") or [] if name not in index]
        if missing:
            raise ValueError(
                f"chains[{chain_index}].stack contains functions not in the kernel source: {', '.join(missing)}. "
                "Copy names from read_kernel_source."
            )


def validate_chain_semantics(chains: list[dict[str, Any]], *, data_root: Path) -> list[dict[str, Any]]:
    validate_stack_names(chains, data_root=data_root)
    known = syscall_names(data_root)
    deps = syscall_deps(data_root)
    missing = sorted({
        call_name(step)
        for record in chains
        for step in record["chain"]
        if call_name(step) not in known
    })
    if missing:
        raise ValueError(
            "Unknown syzkaller syscall(s): "
            + ", ".join(missing)
            + ". Use search_syzlang/read_syzlang_def to find real names."
        )

    for chain_index, record in enumerate(chains):
        for step_index, step in enumerate(record["chain"]):
            if isinstance(step, str):
                continue
            for refinement_index, refinement in enumerate(step.get("refinements", [])):
                loc = f"chains[{chain_index}].chain[{step_index}].refinements[{refinement_index}]"
                level = read_syzlang_level(step["call"], refinement["path"], data_root=data_root)
                node = level["node"]
                if node.get("kind") != refinement["kind"]:
                    raise ValueError(f"{loc}.kind does not match syzlang node kind {node.get('kind')!r}")
                if not is_refinable(node):
                    raise ValueError(
                        f"{loc} cannot constrain {node.get('expression', node.get('type'))}; "
                        "len, bytesize, bitsize, csum, proc, and resource stay with syzkaller"
                    )
                if node.get("type") != refinement["type"]:
                    raise ValueError(f"{loc}.type does not match syzlang node type {node.get('type')!r}")
                choices = {
                    choice["name"] if isinstance(choice, dict) else choice
                    for choice in level.get("choices", [])
                }
                if choices:
                    unknown = sorted(set(refinement["keep"]) - choices)
                    if unknown:
                        raise ValueError(f"{loc}.keep contains unknown choices: {', '.join(unknown)}")
                elif node["kind"] == "scalar":
                    bad = [value for value in refinement["keep"] if not INT_VALUE_RE.fullmatch(value)]
                    if bad:
                        raise ValueError(f"{loc}.keep contains non-integer values: {', '.join(bad)}")

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
                f"chains[{chain_index}] repeats chains[{previous}] with the same calls and refinements: "
                f"{step_calls(record['chain'])}. Drop the duplicate and keep one copy. "
                "The same calls with different refinements are distinct."
            )
    return warnings


def _function_sources(name: str, data_root: Path) -> list[str]:
    records = read_json(str(data_root / "source/func.index.json")).get(name, [])
    return [record["source"] for record in records if record.get("source")]


def _function_files(name: str, data_root: Path) -> list[str]:
    records = read_json(str(data_root / "source/func.index.json")).get(name, [])
    return [
        record["file"]
        for record in records
        if record.get("file") and Path(record["file"]).suffix == ".c"
    ]


def _source_edge(caller: str, callee: str, data_root: Path) -> bool:
    fields = _ops_fields(callee, data_root)
    return any(
        re.search(rf"\b{re.escape(callee)}\s*\(", source)
        or any(re.search(rf"(?:->|\.){re.escape(field)}\s*\(", source) for field in fields)
        for source in _function_sources(caller, data_root)
    )


def validate_focus_candidates(
    target: str,
    chains: list[dict[str, Any]],
    guidance: dict[str, Any] | None,
    *,
    data_root: Path,
) -> tuple[list[str], list[str]]:
    if guidance is None:
        guidance = {}
    if not isinstance(guidance, dict):
        raise ValueError("fuzz_guidance must be an object")
    unknown = set(guidance) - {"near_functions", "path_functions"}
    if unknown:
        raise ValueError(f"fuzz_guidance contains unsupported fields: {', '.join(sorted(unknown))}")
    near = guidance.get("near_functions", [])
    upstream = guidance.get("path_functions", [])
    index = read_json(str(source_dir(data_root) / "func.index.json"))
    for key, names in (("near_functions", near), ("path_functions", upstream)):
        if not isinstance(names, list) or len(names) > 3 or not all(isinstance(name, str) and name in index for name in names):
            raise ValueError(f"fuzz_guidance.{key} must contain at most 3 kernel function names from the source index")
        if len(names) != len(set(names)) or target in names:
            raise ValueError(f"fuzz_guidance.{key} must not repeat functions or contain the target")
    if set(near) & set(upstream):
        raise ValueError("B and C focus functions must not overlap")
    near_paths: list[str] = []
    upstream_paths: set[str] = set()
    for record in chains:
        stack = record["stack"]
        if stack[0] != target:
            raise ValueError("each stack must start with the target function")
        for distance, name in enumerate(stack[1:], start=1):
            if distance >= 3:
                upstream_paths.add(name)
            if distance > 2 or not _source_edge(name, stack[distance - 1], data_root):
                break
            if name not in near_paths:
                near_paths.append(name)
    invalid_near = set(near) - set(near_paths)
    if invalid_near:
        raise ValueError(f"B focus functions must be source-linked callers within 2 steps: {', '.join(sorted(invalid_near))}")
    if not near:
        near = near_paths[:1]
    if not near:
        raise ValueError("near_functions needs a source-linked caller within 2 steps; extend the stack")
    ops = read_json(str(source_dir(data_root) / "ops.index.json")).get("by_handler", {})
    target_tables = {record["table_key"] for record in ops.get(target, []) if record.get("table_key")}
    linked_callbacks = {
        name for name in upstream
        if target_tables & {record["table_key"] for record in ops.get(name, []) if record.get("table_key")}
    }
    invalid_upstream = set(upstream) - upstream_paths - linked_callbacks
    if invalid_upstream:
        raise ValueError(
            "C focus functions must be upstream stack functions or callbacks of the target's driver: "
            + ", ".join(sorted(invalid_upstream))
        )
    return near, upstream


def _ops_fields(handler: str, data_root: Path) -> list[str]:
    records = read_json(str(data_root / "source/ops.index.json")).get("by_handler", {}).get(handler, [])
    return [record["field"] for record in records if record.get("field")]


def validate_fuzz_guidance(fuzz_guidance: dict[str, Any] | None) -> None:
    if fuzz_guidance is None:
        return
    if not isinstance(fuzz_guidance, dict):
        raise ValueError("fuzz_guidance must be an object when present")
    limits = {
        "target_function": 1,
        "near_functions": 3,
        "path_functions": 3,
        "target_file": 1,
    }
    if set(fuzz_guidance) != set(limits):
        raise ValueError("fuzz_guidance must contain exactly the target, B, C, and target file fields")
    for key, limit in limits.items():
        value = fuzz_guidance.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"fuzz_guidance.{key} must be a list of strings")
        if len(value) > limit:
            raise ValueError(f"fuzz_guidance.{key} must contain at most {limit} items")
    if not fuzz_guidance["near_functions"]:
        raise ValueError("fuzz_guidance.near_functions must not be empty")
    for path in fuzz_guidance.get("target_file", []):
        if Path(path).suffix in {".h", ".hpp", ".hh", ".hxx"}:
            raise ValueError("fuzz_guidance.target_file must not contain header files")



def reject_chain_refinements(chains: list[dict[str, Any]]) -> None:
    for chain_index, record in enumerate(chains):
        for step_index, step in enumerate(record["chain"]):
            if isinstance(step, dict) and step.get("refinements"):
                raise ValueError(
                    f"chains[{chain_index}].chain[{step_index}] must not include refinements; "
                    "write the call sequence first, then refine parameters from that fixed chain"
                )


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
    reject_chain_refinements(chains)
    validation_warnings = validate_chain_semantics(chains, data_root=data_root)
    hop1, hop2 = validate_focus_candidates(target, chains, fuzz_guidance, data_root=data_root)
    target_files = sorted(set(_function_files(target, data_root)))
    if len(target_files) != 1:
        raise ValueError(f"target {target} must have exactly one defining .c file, found: {target_files}")
    guidance = {
        "target_function": [f"^{re.escape(target)}$"],
        "near_functions": [f"^{re.escape(name)}$" for name in hop1],
        "path_functions": [f"^{re.escape(name)}$" for name in hop2],
        "target_file": target_files,
    }
    validate_fuzz_guidance(guidance)
    fuzz_guidance = guidance
    output_path = Path(path) if path else output_dir / f"{safe_filename(target)}.chains.json"
    if not output_path.is_absolute():
        output_path = REPO_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = {"target": target, "chains": [{**record, "chain": step_calls(record["chain"])} for record in chains]}
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
