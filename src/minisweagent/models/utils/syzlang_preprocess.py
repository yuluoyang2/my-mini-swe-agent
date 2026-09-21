from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


NAME_RE = r"[A-Za-z_][A-Za-z0-9_$]*"
TOKEN_RE = re.compile(NAME_RE)
SYSCALL_RE = re.compile(rf"^({NAME_RE})\s*\(")
RESOURCE_RE = re.compile(rf"^resource\s+({NAME_RE})")
DEFINE_RE = re.compile(rf"^define\s+({NAME_RE})\b")
TYPE_RE = re.compile(rf"^type\s+({NAME_RE})\b")
FLAGS_RE = re.compile(rf"^({NAME_RE})\s*=")
BLOCK_RE = re.compile(rf"^({NAME_RE})\s*([\[{{])")
CONST_RE = re.compile(rf"^({NAME_RE})\s*=")


def strip_comment(line: str) -> str:
    return line.split("#", 1)[0].rstrip()


def count_delta(line: str, open_ch: str, close_ch: str) -> int:
    return line.count(open_ch) - line.count(close_ch)


def detect_line(line: str) -> tuple[str, str, str] | None:
    stripped = strip_comment(line).strip()
    if not stripped or stripped.startswith("include "):
        return None
    if match := RESOURCE_RE.match(stripped):
        return match.group(1), "resource", "line"
    if match := DEFINE_RE.match(stripped):
        return match.group(1), "define", "line"
    if match := TYPE_RE.match(stripped):
        return match.group(1), "type", "block" if "{" in stripped else "line"
    if match := SYSCALL_RE.match(stripped):
        return match.group(1), "syscall", "line"
    if match := FLAGS_RE.match(stripped):
        return match.group(1), "flags", "line"
    if match := BLOCK_RE.match(stripped):
        return match.group(1), "union" if match.group(2) == "[" else "struct", "block"
    return None


def block_end(lines: list[str], start: int, opener: str) -> int:
    closer = "]" if opener == "[" else "}"
    depth = 0
    for index in range(start, len(lines)):
        depth += count_delta(strip_comment(lines[index]), opener, closer)
        if depth <= 0:
            return index
    return start


def read_source(lines: list[str], start: int, mode: str) -> tuple[int, str]:
    if mode == "line":
        return start, lines[start].rstrip()
    stripped = strip_comment(lines[start])
    opener = "{" if "{" in stripped else "["
    end = block_end(lines, start, opener)
    return end, "\n".join(line.rstrip() for line in lines[start : end + 1])


def parse_syzlang_file(path: Path, root: Path) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    lines = path.read_text(errors="replace").splitlines()
    rel_path = path.relative_to(root).as_posix()
    line_index = 0
    while line_index < len(lines):
        detected = detect_line(lines[line_index])
        if not detected:
            line_index += 1
            continue
        name, kind, mode = detected
        if name == "_":
            line_index += 1
            continue
        end, source = read_source(lines, line_index, mode)
        index.setdefault(name, []).append(
            {
                "kind": kind,
                "file": rel_path,
                "line": line_index + 1,
                "source": source,
            }
        )
        line_index = end + 1
    return index


def parse_const_file(path: Path, root: Path) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    rel_path = path.relative_to(root).as_posix()
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        stripped = strip_comment(line).strip()
        if not stripped or stripped.startswith("arches ="):
            continue
        if match := CONST_RE.match(stripped):
            index.setdefault(match.group(1), []).append(
                {
                    "kind": "const",
                    "file": rel_path,
                    "line": line_number,
                    "source": line.rstrip(),
                }
            )
    return index


def merge_index(target: dict[str, list[dict[str, Any]]], source: dict[str, list[dict[str, Any]]]) -> None:
    for name, definitions in source.items():
        target.setdefault(name, []).extend(definitions)


def referenced_names(source: str, known_names: set[str], self_name: str) -> list[str]:
    refs = []
    seen = set()
    for token in TOKEN_RE.findall(source):
        if token == self_name or token not in known_names or token in seen:
            continue
        refs.append(token)
        seen.add(token)
    return refs


def same_file_family(candidate: str, root_file: str) -> bool:
    return candidate == root_file or candidate == f"{root_file}.const"


def collect_dependency_sources(
    refs: list[str],
    index: dict[str, list[dict[str, Any]]],
    known_names: set[str],
    root_file: str,
    visited: set[str],
) -> list[str]:
    sources = []
    for ref in refs:
        if ref in visited:
            continue
        visited.add(ref)
        for ref_definition in index.get(ref, []):
            if not same_file_family(ref_definition["file"], root_file):
                continue
            sources.append(ref_definition["source"])
            sources.extend(
                collect_dependency_sources(
                    referenced_names(ref_definition["source"], known_names, ref),
                    index,
                    known_names,
                    root_file,
                    visited,
                )
            )
    return sources


def build_full_source(
    name: str,
    definition: dict[str, Any],
    index: dict[str, list[dict[str, Any]]],
    known_names: set[str],
) -> str:
    chunks = [definition["source"]]
    chunks.extend(
        collect_dependency_sources(
            referenced_names(definition["source"], known_names, name),
            index,
            known_names,
            definition["file"],
            {name},
        )
    )
    return "\n\n".join(chunks)


def build_index(syzlang_dir: Path) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(syzlang_dir.glob("*.txt")):
        merge_index(index, parse_syzlang_file(path, syzlang_dir.parent))
    for path in sorted(syzlang_dir.glob("*.txt.const")):
        merge_index(index, parse_const_file(path, syzlang_dir.parent))
    known_names = set(index)
    for name, definitions in index.items():
        for definition in definitions:
            definition["full_source"] = build_full_source(name, definition, index, known_names)
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a lightweight syzlang definition index.")
    parser.add_argument("syzlang_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(build_index(args.syzlang_dir), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
