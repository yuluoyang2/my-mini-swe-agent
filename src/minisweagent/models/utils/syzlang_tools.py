from __future__ import annotations

import argparse
import json
import re
from difflib import get_close_matches
from functools import lru_cache
from pathlib import Path
from typing import Any

from minisweagent.models.utils.syzlang_preprocess import (
    NAME_RE,
    TOKEN_RE,
    referenced_names,
    same_file_family,
    strip_comment,
)


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATA_ROOT = REPO_ROOT / "data/linux-6.6"
MEMBER_RE = re.compile(rf"^({NAME_RE})\s+(.+)$")
INT_TYPES = {
    "int8",
    "int16",
    "int32",
    "int64",
    "intptr",
    "int8be",
    "int16be",
    "int32be",
    "int64be",
}


@lru_cache
def read_json(path: str) -> Any:
    return json.loads(Path(path).read_text())


def syzlang_dir(data_root: Path) -> Path:
    return data_root / "syzlang"


def syzlang_index(data_root: Path) -> dict[str, list[dict[str, Any]]]:
    return read_json(str(syzlang_dir(data_root) / "syzlang.index.json"))


def syscall_deps(data_root: Path) -> dict[str, dict[str, Any]]:
    return {record["syscall"]: record for record in read_json(str(syzlang_dir(data_root) / "syz_depend_inout.json"))}


def matches_hint(record: dict[str, Any], file_hint: str | None) -> bool:
    if not file_hint:
        return True
    file = record.get("file", "")
    return file_hint in file or file.endswith(file_hint)


def limit_records(records: list[dict[str, Any]], max_results: int | None) -> list[dict[str, Any]]:
    if max_results is None or max_results <= 0:
        return records
    return records[:max_results]


def list_syzlang_files(query: str | None = None, *, data_root: Path = DEFAULT_DATA_ROOT) -> dict[str, Any]:
    files = sorted(path.relative_to(syzlang_dir(data_root)).as_posix() for path in (syzlang_dir(data_root) / "linux").glob("*.txt"))
    if not query:
        return {"query": query, "fallback": False, "files": files}
    matches = [path for path in files if query.lower() in path.lower()]
    return {"query": query, "fallback": not matches, "files": matches or files}


def search_syzlang(query: str, *, max_results: int = 50, data_root: Path = DEFAULT_DATA_ROOT) -> dict[str, Any]:
    if not query:
        raise ValueError("query must not be empty")
    query_lower = query.lower()
    records = []
    for name, definitions in syzlang_index(data_root).items():
        for definition in definitions:
            source = definition.get("source", "")
            file = definition.get("file", "")
            match_fields = [
                field
                for field, value in (("name", name), ("source", source), ("file", file))
                if query_lower in value.lower()
            ]
            if not match_fields:
                continue
            records.append({
                "name": name,
                "kind": definition.get("kind"),
                "file": file,
                "line": definition.get("line"),
                "source": source,
                "match_fields": match_fields,
            })
    records.sort(key=lambda record: (
        query_lower != record["name"].lower(),
        "name" not in record["match_fields"],
        "source" not in record["match_fields"],
        record["file"],
        record["line"] or 0,
        record["name"],
    ))
    return {"query": query, "records": limit_records(records, max_results)}


def read_syzlang_def(
    name: str,
    *,
    file_hint: str | None = None,
    full: bool = True,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    records = [dict(record) for record in syzlang_index(data_root).get(name, [])]
    hinted_records = [record for record in records if matches_hint(record, file_hint)]
    records = hinted_records or records
    for record in records:
        if full:
            record["source"] = record.get("full_source", record.get("source", ""))
        record.pop("full_source", None)
    return {"name": name, "file_hint": file_hint, "full": full, "records": records}


def read_syzlang_file(
    path: str,
    start_line: int,
    end_line: int,
    *,
    max_lines: int = 200,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    if start_line < 1 or end_line < start_line:
        raise ValueError("Expected 1 <= start_line <= end_line")
    if end_line - start_line + 1 > max_lines:
        end_line = start_line + max_lines - 1
    syzlang_path = syzlang_dir(data_root) / path
    lines = syzlang_path.read_text(errors="replace").splitlines()
    end_line = min(end_line, len(lines))
    return {
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "content": "\n".join(f"{line_no}: {lines[line_no - 1]}" for line_no in range(start_line, end_line + 1)),
    }


def validate_syzlang_candidates(
    names: list[str],
    *,
    max_suggestions: int = 5,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    index = syzlang_index(data_root)
    keys = sorted(index)
    records = []
    for name in names:
        if name in index:
            records.append({
                "name": name,
                "exists": True,
                "definitions": [
                    {key: record.get(key) for key in ("kind", "file", "line")}
                    for record in index[name]
                ],
            })
        else:
            records.append({
                "name": name,
                "exists": False,
                "suggestions": get_close_matches(name, keys, n=max_suggestions),
            })
    return {"names": names, "records": records}


def parse_union_arms(source: str) -> list[str]:
    arms = []
    in_body = False
    for line in source.splitlines():
        stripped = strip_comment(line).strip()
        if not in_body:
            if "[" in stripped:
                in_body = True
            continue
        if stripped.startswith("]"):
            break
        if match := TOKEN_RE.match(stripped):
            arms.append(match.group(0))
    return arms


def parse_flag_values(source: str) -> list[str]:
    _, _, rest = strip_comment(source).partition("=")
    values = []
    for part in rest.split(","):
        if match := TOKEN_RE.match(part.strip()):
            values.append(match.group(0))
    return values


def split_syzlang_list(source: str) -> list[str]:
    values = []
    start = 0
    depth = 0
    quote = ""
    for index, char in enumerate(source):
        if quote:
            if char == quote and (index == 0 or source[index - 1] != "\\"):
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "[({":
            depth += 1
        elif char in "])}":
            depth -= 1
        elif char == "," and depth == 0:
            values.append(source[start:index].strip())
            start = index + 1
    values.append(source[start:].strip())
    return [value for value in values if value]


def bracket_content(source: str, start: int) -> tuple[str, int]:
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "[":
            depth += 1
        elif source[index] == "]":
            depth -= 1
            if depth == 0:
                return source[start + 1 : index], index
    raise ValueError(f"Unclosed syzlang bracket in: {source}")


def parse_type_application(source: str) -> tuple[str, list[str]]:
    source = source.strip()
    match = TOKEN_RE.match(source)
    if not match:
        return source, []
    name = match.group(0)
    rest = source[match.end() :].lstrip()
    if not rest.startswith("["):
        return name, []
    content, _ = bracket_content(rest, 0)
    return name, split_syzlang_list(content)


def parse_members(source: str) -> list[tuple[str, str]]:
    members = []
    for line in source.splitlines()[1:]:
        stripped = strip_comment(line).strip()
        if not stripped or stripped[0] in "]}":
            continue
        if match := MEMBER_RE.match(stripped):
            members.append((match.group(1), match.group(2).strip()))
    return members


def parse_syscall_args(source: str) -> list[tuple[str, str]]:
    start = source.find("(")
    if start < 0:
        return []
    depth = 0
    end = -1
    for index in range(start, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end < 0:
        raise ValueError(f"Unclosed syscall arguments in: {source}")
    args = []
    for arg in split_syzlang_list(source[start + 1 : end]):
        if match := MEMBER_RE.match(arg):
            args.append((match.group(1), match.group(2).strip()))
    return args


def substitute_type_params(source: str, bindings: dict[str, str]) -> str:
    return TOKEN_RE.sub(lambda match: bindings.get(match.group(0), match.group(0)), source)


def parse_type_definition(source: str, name: str) -> tuple[list[str], str]:
    header = strip_comment(source.splitlines()[0]).strip()
    rest = header.removeprefix("type").strip().removeprefix(name).lstrip()
    params = []
    if rest.startswith("["):
        content, end = bracket_content(rest, 0)
        params = split_syzlang_list(content)
        rest = rest[end + 1 :].strip()
    return params, rest


def _non_const(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((record for record in records if record.get("kind") != "const"), records[0] if records else None)


def definition_for(
    name: str,
    index: dict[str, list[dict[str, Any]]],
    root_file: str,
) -> dict[str, Any] | None:
    records = index.get(name, [])
    local = [record for record in records if same_file_family(record["file"], root_file)]
    if local:
        return _non_const(local)
    others = [record for record in records if record.get("kind") != "const"]
    if len({record["file"] for record in others}) == 1:
        return others[0]
    return None


def resolve_syzlang_node(
    expression: str,
    *,
    index: dict[str, list[dict[str, Any]]],
    root_file: str,
    bindings: dict[str, str] | None = None,
    seen: set[str] | None = None,
) -> dict[str, Any]:
    bindings = bindings or {}
    expression = substitute_type_params(expression, bindings)
    name, args = parse_type_application(expression)
    if name in {"ptr", "ptr64"}:
        if len(args) < 2:
            return {"kind": "pointer", "expression": expression, "containers": ["pointer"]}
        node = resolve_syzlang_node(args[1], index=index, root_file=root_file, seen=seen)
        node["containers"] = ["pointer", *node.get("containers", [])]
        return node
    if name == "array":
        if not args:
            return {"kind": "array", "expression": expression, "containers": ["array"]}
        node = resolve_syzlang_node(args[0], index=index, root_file=root_file, seen=seen)
        node["containers"] = ["array", *node.get("containers", [])]
        return node
    if name == "flags":
        flag_type = args[0] if args else ""
        definition = definition_for(flag_type, index, root_file)
        return {
            "kind": "flags",
            "type": flag_type,
            "choices": parse_flag_values(definition["source"]) if definition else [],
            "expression": expression,
        }
    if name == "const":
        return {
            "kind": "const",
            "type": args[1] if len(args) > 1 else "const",
            "choices": [args[0]] if args else [],
            "expression": expression,
        }
    if name in {"len", "bytesize", "bitsize", "csum", "proc"}:
        return {"kind": "derived", "type": name, "expression": expression}
    if name == "string":
        quoted = [arg[1:-1] for arg in args if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] in {'"', "'"}]
        return {
            "kind": "string",
            "type": "string" if not args or quoted else args[0],
            "choices": quoted,
            "expression": expression,
        }

    definition = definition_for(name, index, root_file)
    if not definition:
        return {"kind": "scalar", "type": name, "expression": expression}
    kind = definition.get("kind")
    if kind == "resource":
        return {"kind": "resource", "type": name, "expression": expression}
    if kind == "flags":
        return {
            "kind": "flags",
            "type": name,
            "choices": parse_flag_values(definition["source"]),
            "expression": expression,
        }
    if kind in {"struct", "union"}:
        return {
            "kind": kind,
            "type": name,
            "members": parse_members(definition["source"]),
            "bindings": {},
            "expression": expression,
        }
    if kind != "type":
        return {"kind": "scalar", "type": name, "expression": expression}

    seen = set(seen or ())
    if name in seen:
        return {"kind": "recursive", "type": name, "expression": expression}
    seen.add(name)
    params, target = parse_type_definition(definition["source"], name)
    type_bindings = dict(zip(params, args))
    if target.startswith("{"):
        return {
            "kind": "struct",
            "type": name,
            "members": parse_members(definition["source"]),
            "bindings": type_bindings,
            "expression": expression,
        }
    return resolve_syzlang_node(
        target,
        index=index,
        root_file=root_file,
        bindings=type_bindings,
        seen=seen,
    )


def is_refinable(node: dict[str, Any]) -> bool:
    kind = node.get("kind")
    if kind in {"union", "flags"}:
        return True
    if kind == "const":
        return bool(node.get("choices"))
    if kind == "scalar":
        return node.get("type") in INT_TYPES
    if kind == "string":
        return bool(node.get("choices")) or node.get("type") == "string"
    return False


def syzlang_child(name: str, path: str, expression: str, node: dict[str, Any]) -> dict[str, Any]:
    child = {
        "name": name,
        "path": path,
        "kind": node["kind"],
        "expression": expression,
        "expandable": node["kind"] in {"struct", "union"},
        "prunable": is_refinable(node),
    }
    for key in ("type", "choices", "containers"):
        if node.get(key):
            child[key] = node[key]
    return child


def read_syzlang_level(
    call: str,
    path: str = "",
    *,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    index = syzlang_index(data_root)
    records = [record for record in index.get(call, []) if record.get("kind") == "syscall"]
    if not records:
        raise ValueError(f"Unknown syzkaller syscall: {call}")
    record = records[0]
    node: dict[str, Any] = {
        "kind": "syscall",
        "type": call,
        "members": parse_syscall_args(record["source"]),
        "bindings": {},
    }
    current_path = ""
    for segment in path.split(".") if path else []:
        if node["kind"] not in {"syscall", "struct", "union"}:
            raise ValueError(f"Syzlang path is not expandable at {current_path or '<root>'}: {path}")
        members = dict(node.get("members", []))
        if segment not in members:
            raise ValueError(f"Unknown syzlang child {segment!r} below {current_path or '<root>'}")
        expression = substitute_type_params(members[segment], node.get("bindings", {}))
        node = resolve_syzlang_node(expression, index=index, root_file=record["file"])
        current_path = f"{current_path}.{segment}" if current_path else segment

    result = {
        "call": call,
        "path": path,
        "node": {
            key: value
            for key, value in node.items()
            if key not in {"members", "bindings"} and value not in (None, [], {})
        },
    }
    if node["kind"] in {"syscall", "struct"}:
        result["children"] = [
            syzlang_child(
                name,
                f"{path}.{name}" if path else name,
                substitute_type_params(expression, node.get("bindings", {})),
                resolve_syzlang_node(
                    substitute_type_params(expression, node.get("bindings", {})),
                    index=index,
                    root_file=record["file"],
                ),
            )
            for name, expression in node.get("members", [])
        ]
    elif node["kind"] == "union":
        result["choices"] = [
            syzlang_child(
                name,
                f"{path}.{name}" if path else name,
                substitute_type_params(expression, node.get("bindings", {})),
                resolve_syzlang_node(
                    substitute_type_params(expression, node.get("bindings", {})),
                    index=index,
                    root_file=record["file"],
                ),
            )
            for name, expression in node.get("members", [])
        ]
    elif node["kind"] in {"flags", "const", "string"} and node.get("choices"):
        result["choices"] = node["choices"]
    return result


def _choice_names(node: dict[str, Any]) -> list[str]:
    if node.get("kind") == "union":
        return [name for name, _ in node.get("members", [])]
    if node.get("kind") == "string":
        return [choice for choice in node.get("choices", []) if isinstance(choice, str) and choice]
    if node.get("kind") == "flags":
        return [choice for choice in node.get("choices", []) if isinstance(choice, str) and TOKEN_RE.fullmatch(choice)]
    return []


def _collect_prunable(
    node: dict[str, Any],
    path: str,
    found: list[dict[str, Any]],
    *,
    index: dict[str, list[dict[str, Any]]],
    root_file: str,
    stack: tuple[str, ...],
) -> None:
    kind = node.get("kind")
    names = _choice_names(node)
    if path and kind in {"union", "flags", "string"} and len(names) >= 2:
        found.append({"path": path, "kind": kind, "type": node.get("type", kind), "choices": names})
    if kind not in {"syscall", "struct", "union"}:
        return
    type_name = str(node.get("type") or path or "<root>")
    if type_name in stack:
        return
    for name, expression in node.get("members", []):
        _collect_prunable(
            resolve_syzlang_node(
                substitute_type_params(expression, node.get("bindings", {})),
                index=index,
                root_file=root_file,
            ),
            f"{path}.{name}" if path else name,
            found,
            index=index,
            root_file=root_file,
            stack=(*stack, type_name),
        )


def list_prunable_nodes(calls: list[str] | str, *, data_root: Path = DEFAULT_DATA_ROOT) -> dict[str, Any]:
    names = [calls] if isinstance(calls, str) else list(calls)
    if not names:
        raise ValueError("calls must not be empty")
    index = syzlang_index(data_root)
    listed = {}
    for call in names:
        records = [record for record in index.get(call, []) if record.get("kind") == "syscall"]
        if not records:
            raise ValueError(f"Unknown syzkaller syscall: {call}")
        record = records[0]
        found: list[dict[str, Any]] = []
        _collect_prunable(
            {
                "kind": "syscall",
                "type": call,
                "members": parse_syscall_args(record["source"]),
                "bindings": {},
            },
            "",
            found,
            index=index,
            root_file=record["file"],
            stack=(),
        )
        listed[call] = found
    return {"calls": listed}


def _choices_for_syscall(name: str, index: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    records = [record for record in index.get(name, []) if record.get("kind") == "syscall"]
    if not records:
        raise ValueError(f"Unknown syzkaller syscall: {name}")
    record = records[0]
    known = set(index)
    unions: dict[str, list[str]] = {}
    flags: dict[str, list[str]] = {}
    visited: set[str] = set()

    def walk(ref: str) -> None:
        if ref in visited:
            return
        visited.add(ref)
        for definition in index.get(ref, []):
            if not same_file_family(definition["file"], record["file"]):
                continue
            kind = definition.get("kind")
            if kind == "union":
                unions[ref] = parse_union_arms(definition["source"])
            elif kind == "flags":
                flags[ref] = parse_flag_values(definition["source"])
            for next_name in referenced_names(definition["source"], known, ref):
                walk(next_name)

    for next_name in referenced_names(record["source"], known, name):
        walk(next_name)
    return {"source": record["source"], "unions": unions, "flags": flags}


def list_syzlang_choices(syscalls: list[str] | str, *, data_root: Path = DEFAULT_DATA_ROOT) -> dict[str, Any]:
    names = [syscalls] if isinstance(syscalls, str) else list(syscalls)
    if not names:
        raise ValueError("syscalls must not be empty")
    index = syzlang_index(data_root)
    return {"syscalls": {name: _choices_for_syscall(name, index) for name in names}}


def get_syscall_deps(
    syscalls: str | list[str],
    *,
    include_depend: bool = True,
    include_depended: bool = True,
    max_results: int = 50,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    names = [syscalls] if isinstance(syscalls, str) else list(syscalls)
    if not names:
        raise ValueError("syscalls must not be empty")
    deps = syscall_deps(data_root)
    records = {}
    for name in names:
        record = deps.get(name, {})
        records[name] = {
            "depend": limit_records(record.get("depend", []) if include_depend else [], max_results),
            "depended": limit_records(record.get("depended", []) if include_depended else [], max_results),
        }
    return {"syscalls": records}


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Query preprocessed syzkaller syzlang data.")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-files")
    list_parser.add_argument("--query")

    search_parser = subparsers.add_parser("search")
    search_parser.add_argument("query")
    search_parser.add_argument("--max-results", type=int, default=50)

    def_parser = subparsers.add_parser("read-def")
    def_parser.add_argument("name")
    def_parser.add_argument("--file-hint")
    def_parser.add_argument("--brief", action="store_true")

    file_parser = subparsers.add_parser("read-file")
    file_parser.add_argument("path")
    file_parser.add_argument("start_line", type=int)
    file_parser.add_argument("end_line", type=int)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("names", nargs="+")
    validate_parser.add_argument("--max-suggestions", type=int, default=5)

    deps_parser = subparsers.add_parser("deps")
    deps_parser.add_argument("syscall")
    deps_parser.add_argument("--no-depend", action="store_true")
    deps_parser.add_argument("--no-depended", action="store_true")
    deps_parser.add_argument("--max-results", type=int, default=50)

    args = parser.parse_args()
    if args.command == "list-files":
        print_json(list_syzlang_files(args.query, data_root=args.data_root))
    elif args.command == "search":
        print_json(search_syzlang(args.query, max_results=args.max_results, data_root=args.data_root))
    elif args.command == "read-def":
        print_json(read_syzlang_def(args.name, file_hint=args.file_hint, full=not args.brief, data_root=args.data_root))
    elif args.command == "read-file":
        print_json(read_syzlang_file(args.path, args.start_line, args.end_line, data_root=args.data_root))
    elif args.command == "validate":
        print_json(validate_syzlang_candidates(args.names, max_suggestions=args.max_suggestions, data_root=args.data_root))
    elif args.command == "deps":
        print_json(
            get_syscall_deps(
                args.syscall,
                include_depend=not args.no_depend,
                include_depended=not args.no_depended,
                max_results=args.max_results,
                data_root=args.data_root,
            )
        )


if __name__ == "__main__":
    main()
