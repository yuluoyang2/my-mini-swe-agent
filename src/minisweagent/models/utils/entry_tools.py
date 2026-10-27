from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from minisweagent.models.utils import callgraph_tools, kernel_source_tools


DEFAULT_SYSCALL_TABLE = "arch/x86/entry/syscalls/syscall_64.tbl"
DEFAULT_SYSCALL_ABIS = ("common", "64")


def kernel_path(path: str, linux_root: Path) -> Path:
    resolved = (linux_root / path).resolve()
    resolved.relative_to(linux_root.resolve())
    return resolved


def validate_page(offset: int, limit: int) -> None:
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError("Expected offset >= 0 and 1 <= limit <= 100")


def search_kernel_source(
    query: str,
    *,
    path: str = ".",
    regex: bool = False,
    context: int = 3,
    offset: int = 0,
    limit: int = 20,
    linux_root: Path = kernel_source_tools.DEFAULT_LINUX_ROOT,
) -> dict[str, Any]:
    validate_page(offset, limit)
    if not query.strip() or not 0 <= context <= 20:
        raise ValueError("Supply a non-empty query and 0 <= context <= 20")
    search_path = kernel_path(path, linux_root)
    ripgrep = shutil.which("rg")
    if ripgrep:
        command = [ripgrep, "--json", "--sort", "path", *([] if regex else ["--fixed-strings"])]
    else:
        grep = shutil.which("grep")
        if grep is None:
            raise RuntimeError("Source search requires ripgrep (rg) or GNU grep in PATH")
        command = [grep, "-rInHZ", "-E" if regex else "-F", "--exclude-dir=.*", "--exclude=.*"]
    process = subprocess.run(
        [*command, "--", query, str(search_path)],
        cwd=linux_root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if process.returncode not in (0, 1):
        raise RuntimeError(process.stderr.strip())
    if ripgrep:
        matches = [json.loads(line) for line in process.stdout.splitlines()]
        matches = [record["data"] for record in matches if record["type"] == "match"]
    else:
        matches = []
        for row in process.stdout.splitlines():
            filename, match = row.split("\0", 1)
            line_number, source = match.split(":", 1)
            matches.append({"path": {"text": filename}, "line_number": int(line_number), "lines": {"text": source}})
        matches.sort(key=lambda match: (match["path"]["text"], match["line_number"]))
    records = []
    files: dict[str, list[str]] = {}
    for match in matches[offset : offset + limit]:
        source_path = kernel_path(match["path"]["text"], linux_root)
        relative = source_path.relative_to(linux_root.resolve()).as_posix()
        if relative not in files:
            files[relative] = source_path.read_text(errors="replace").splitlines()
        line = match["line_number"]
        records.append(
            {
                "path": relative,
                "line": line,
                "text": match["lines"]["text"].rstrip("\n"),
                "context": "\n".join(
                    f"{number}: {files[relative][number - 1]}"
                    for number in range(max(1, line - context), min(len(files[relative]), line + context) + 1)
                ),
            }
        )
    return {
        "query": query,
        "path": path,
        "records": records,
        "total_matches": len(matches),
        "next_offset": offset + limit if offset + limit < len(matches) else None,
    }


def get_func_neighbors(
    function: str,
    direction: str = "callers",
    *,
    file_hint: str | None = None,
    offset: int = 0,
    limit: int = 30,
    data_root: Path = kernel_source_tools.DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    validate_page(offset, limit)
    if direction not in {"callers", "callees"}:
        raise ValueError("direction must be callers or callees")
    records = []
    seen = set()
    index = callgraph_tools.callers_index(data_root) if direction == "callers" else callgraph_tools.callees_index(data_root)
    for record in index.get(function, []):
        if not callgraph_tools.matches_hint(record, file_hint):
            continue
        neighbors = [record["function"]] if direction == "callers" else record.get("called", [])
        for neighbor in neighbors:
            files = [record["file"]] if direction == "callers" else callgraph_tools.function_files(neighbor, data_root)
            key = (neighbor, tuple(files))
            if key not in seen:
                seen.add(key)
                records.append({"function": neighbor, "files": files})
    return {
        "function": function,
        "direction": direction,
        "records": records[offset : offset + limit],
        "total_matches": len(records),
        "next_offset": offset + limit if offset + limit < len(records) else None,
    }


def syscall_records(linux_root: Path, syscall_table: str, abis: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    records = []
    for line, raw in enumerate(kernel_path(syscall_table, linux_root).read_text().splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if len(fields) >= 3 and fields[0].isdigit() and fields[1] in abis:
            records.append(
                {
                    "number": int(fields[0]),
                    "abi": fields[1],
                    "name": fields[2],
                    "entry": fields[3] if len(fields) > 3 else None,
                    "line": line,
                    "raw": raw,
                }
            )
    return records


def lookup_syscall(
    query: str = "",
    *,
    abis: list[str] | None = None,
    offset: int = 0,
    limit: int = 30,
    linux_root: Path = kernel_source_tools.DEFAULT_LINUX_ROOT,
    syscall_table: str = DEFAULT_SYSCALL_TABLE,
    syscall_abis: list[str] | tuple[str, ...] = DEFAULT_SYSCALL_ABIS,
) -> dict[str, Any]:
    validate_page(offset, limit)
    records = [
        record
        for record in syscall_records(linux_root, syscall_table, syscall_abis if abis is None else abis)
        if query.lower() in record["raw"].lower()
    ]
    return {
        "table": syscall_table,
        "abis": list(syscall_abis if abis is None else abis),
        "records": records[offset : offset + limit],
        "total_matches": len(records),
        "next_offset": offset + limit if offset + limit < len(records) else None,
    }


def write_entry_result(
    target: str,
    entries: list[dict[str, Any]],
    *,
    data_root: Path = kernel_source_tools.DEFAULT_DATA_ROOT,
    linux_root: Path = kernel_source_tools.DEFAULT_LINUX_ROOT,
    syscall_table: str = DEFAULT_SYSCALL_TABLE,
    syscall_abis: list[str] | tuple[str, ...] = DEFAULT_SYSCALL_ABIS,
) -> dict[str, Any]:
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$]*", target):
        raise ValueError("target must be a function symbol without path separators")
    if not isinstance(entries, list):
        raise ValueError("entries must be a list")
    allowed = {record["name"] for record in syscall_records(linux_root, syscall_table, syscall_abis)}
    result = []
    seen = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"syscall", "resource"}:
            raise ValueError(f"entries[{index}] must contain exactly syscall, resource")
        for field in ("syscall", "resource"):
            if not isinstance(entry[field], list) or not all(isinstance(value, str) and value.strip() for value in entry[field]):
                raise ValueError(f"entries[{index}].{field} must be a list of non-empty strings")
        if not entry["syscall"] or set(entry["syscall"]) - allowed:
            raise ValueError(f"entries[{index}].syscall must contain Linux syscall names from {syscall_table}")
        normalized = {field: list(dict.fromkeys(entry[field])) for field in ("syscall", "resource")}
        key = (tuple(sorted(normalized["syscall"])), tuple(sorted(normalized["resource"])))
        if key not in seen:
            seen.add(key)
            result.append(normalized)
    output_path = data_root / "results" / f"{target}.entry.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"function": target, "entries": result}, indent=2, ensure_ascii=False) + "\n")
    return {"path": str(output_path), "entries": len(result)}
