from __future__ import annotations

import argparse
import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any

from minisweagent.models.utils.chain_result_tools import DEFAULT_DATA_ROOT, safe_filename
from minisweagent.models.utils.syzlang_preprocess import TOKEN_RE, detect_line, read_source, strip_comment
from minisweagent.models.utils.syzlang_tools import parse_flag_values, parse_union_arms, syzlang_index


def refinements(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    if "targetkcov" in document:
        records = [call for batch in document["targetkcov"] for call in batch.get("calls") or []]
    elif "calls" in document:
        records = document["calls"]
    else:
        records = [step for record in document["chains"] for step in record["chain"]]
    return [
        (record["call"], refinement)
        for record in records
        for refinement in record.get("refinements") or []
    ]


def grouped_type_refinements(
    items: list[tuple[str, dict[str, Any]]],
) -> dict[tuple[str, str], tuple[str, dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for call, refinement in items:
        if refinement["kind"] in {"union", "flags"}:
            grouped[(refinement["kind"], refinement["type"])].append((call, refinement))
    result = {}
    for key, entries in grouped.items():
        signatures = {
            (call, refinement["path"], tuple(refinement["keep"]))
            for call, refinement in entries
        }
        if len(signatures) != 1:
            locations = ", ".join(
                f"{call}:{refinement['path']}={refinement['keep']}"
                for call, refinement in entries
            )
            raise ValueError(f"conflicting refinements for shared {key[0]} {key[1]}: {locations}")
        result[key] = entries[0]
    return result


def trim_union(source: str, keep: list[str]) -> str:
    arms = parse_union_arms(source)
    missing = sorted(set(keep) - set(arms))
    if missing:
        raise ValueError(f"unknown union arms: {', '.join(missing)}")
    kept = set(keep)
    lines = []
    in_body = False
    for line in source.splitlines():
        stripped = strip_comment(line).strip()
        if not in_body:
            lines.append(line)
            if "[" in stripped:
                in_body = True
            continue
        if stripped.startswith("]"):
            lines.append(line)
            in_body = False
            continue
        match = TOKEN_RE.match(stripped)
        if match and match.group(0) in kept:
            lines.append(line)
    return "\n".join(lines)


def trim_flags(source: str, keep: list[str]) -> str:
    original = parse_flag_values(source)
    missing = sorted(set(keep) - set(original))
    if missing:
        raise ValueError(f"unknown flags values: {', '.join(missing)}")
    name = strip_comment(source.splitlines()[0]).split("=", 1)[0].rstrip()
    return f"{name} = {', '.join(value for value in original if value in set(keep))}"


def definition_spans(text: str) -> list[tuple[str, str, int, int, str]]:
    lines = text.splitlines()
    spans = []
    index = 0
    while index < len(lines):
        detected = detect_line(lines[index])
        if not detected or detected[0] == "_":
            index += 1
            continue
        name, kind, mode = detected
        stripped = strip_comment(lines[index])
        if kind == "type" and stripped.count("[") > stripped.count("]"):
            mode = "block"
        end, source = read_source(lines, index, mode)
        spans.append((name, kind, index, end, source))
        index = end + 1
    return spans


def definition_routes(texts: dict[str, str], target: str, limit: int = 64) -> tuple[list[list[str]], bool]:
    definitions = [
        (file, *span)
        for file, text in texts.items()
        for span in definition_spans(text)
    ]
    names = {name for _, name, _, _, _, _ in definitions}
    reverse: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    kinds: dict[str, set[str]] = defaultdict(set)
    for file, name, kind, start, _, source in definitions:
        kinds[name].add(kind)
        occurrence = 0
        for token in TOKEN_RE.findall("\n".join(strip_comment(line) for line in source.splitlines())):
            if token not in names or token == name:
                continue
            reverse[token].append((name, f"{file}:{start + 1}", occurrence))
            occurrence += 1

    routes: list[list[str]] = []
    truncated = False

    def walk(name: str, route: list[str], visited: set[tuple[str, str, int]]) -> None:
        nonlocal truncated
        for parent, location, occurrence in reverse.get(name, []):
            edge = (parent, location, occurrence)
            if edge in visited:
                continue
            next_route = [parent, *route]
            if "syscall" in kinds[parent]:
                routes.append(next_route)
                if len(routes) >= limit:
                    truncated = True
                    return
            else:
                walk(parent, next_route, {*visited, edge})
                if truncated:
                    return

    walk(target, [target], set())
    return routes, truncated


CHECKED_KINDS = {"struct", "union", "flags", "type", "resource"}


def reachable(texts: dict[str, str]) -> set[str]:
    definitions = [span for text in texts.values() for span in definition_spans(text)]
    names = {name for name, _, _, _, _ in definitions}
    refs: dict[str, set[str]] = {}
    for name, _, _, _, source in definitions:
        found = refs.setdefault(name, set())
        for line in source.splitlines():
            for token in TOKEN_RE.findall(strip_comment(line)):
                if token in names and token != name:
                    found.add(token)
    pending = [name for name, kind, _, _, _ in definitions if kind == "syscall"]
    used: set[str] = set()
    while pending:
        name = pending.pop()
        if name in used:
            continue
        used.add(name)
        pending.extend(refs.get(name, ()))
    return used


def drop_unused_definitions(text: str, used: set[str]) -> tuple[str, int]:
    lines = text.splitlines()
    removed = 0
    for name, kind, start, end, _ in reversed(definition_spans(text)):
        if kind not in CHECKED_KINDS or name in used:
            continue
        del lines[start : end + 1]
        removed += 1
    suffix = "\n" if text.endswith("\n") else ""
    return "\n".join(lines) + suffix, removed


def apply_edits(text: str, edits: list[tuple[int, str, str]]) -> str:
    lines = text.splitlines()
    for start, old, new in sorted(edits, key=lambda item: item[0], reverse=True):
        count = len(old.splitlines())
        lines[start - 1 : start - 1 + count] = new.splitlines()
    suffix = "\n" if text.endswith("\n") else ""
    return "\n".join(lines) + suffix


def validate_output_path(output: Path, data_root: Path) -> None:
    resolved = output.resolve()
    protected = {
        Path("/").resolve(),
        data_root.resolve(),
        (data_root / "results").resolve(),
        (data_root / "syzlang").resolve(),
        (data_root / "syzlang/linux").resolve(),
    }
    if resolved in protected or output.name in {"", ".", ".."}:
        raise ValueError(f"unsafe output directory: {output}")


def trim_syzlang(
    refine: Path,
    *,
    data_root: Path = DEFAULT_DATA_ROOT,
    output: Path | None = None,
    drop_unused: bool = False,
) -> dict[str, Any]:
    document = json.loads(refine.read_text())
    items = refinements(document)
    index = syzlang_index(data_root)
    syzlang = data_root / "syzlang/linux"
    texts = {path.name: path.read_text() for path in sorted(syzlang.glob("*.txt"))}
    notes = []
    edits: dict[str, list[tuple[int, str, str]]] = {}

    def add_edit(record: dict[str, Any], updated: str, note: str) -> None:
        edits.setdefault(record["file"], []).append((record["line"], record["source"], updated))
        notes.append(note)

    for (kind, type_name), (call, refinement) in grouped_type_refinements(items).items():
        routes, truncated = definition_routes(texts, type_name)
        if truncated or len(routes) != 1 or routes[0][0] != call:
            roots = sorted({route[0] for route in routes})
            suffix = "+" if truncated else ""
            notes.append(
                f"skipped {call}:{refinement['path']} ({type_name}): shared across {len(routes)}{suffix} routes"
                + (f" from {', '.join(roots[:8])}" if roots else "")
            )
            continue
        records = [record for record in index.get(type_name, []) if record["kind"] == kind]
        if len(records) != 1:
            notes.append(
                f"skipped {call}:{refinement['path']} ({type_name}): {len(records)} matching definitions"
            )
            continue
        record = records[0]
        keep = refinement["keep"]
        updated = trim_union(record["source"], keep) if kind == "union" else trim_flags(record["source"], keep)
        before = parse_union_arms(record["source"]) if kind == "union" else parse_flag_values(record["source"])
        add_edit(
            record,
            updated,
            f"{call}:{refinement['path']} ({type_name}): {len(before)} -> {len(keep)} ({', '.join(keep)})",
        )

    scalar_or_const = [
        (call, refinement)
        for call, refinement in items
        if refinement["kind"] in {"scalar", "const"}
    ]
    notes.extend(
        f"skipped {call}:{refinement['path']}: path-local scalar/const rewriting is not implemented"
        for call, refinement in scalar_or_const
    )

    for name, file_edits in edits.items():
        texts[Path(name).name] = apply_edits(texts[Path(name).name], file_edits)

    if drop_unused:
        used = reachable(texts)
        for name, text in list(texts.items()):
            texts[name], removed = drop_unused_definitions(text, used)
            if removed:
                notes.append(f"{name}: removed {removed} unused definitions")

    output = output or data_root / "results" / f"{safe_filename(document['target'])}.syzlang"
    validate_output_path(output, data_root)
    shutil.rmtree(output, ignore_errors=True)
    for name, text in texts.items():
        if text == (syzlang / name).read_text():
            continue
        target = output / "linux" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    output.mkdir(parents=True, exist_ok=True)
    (output / "CHANGED.txt").write_text("\n".join(notes) + "\n")
    return {"output": output.as_posix(), "notes": notes, "edited_files": sorted(Path(name).name for name in edits)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Trim syzlang definitions from a refine result.")
    parser.add_argument("refine", type=Path)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--drop-unused", action="store_true")
    args = parser.parse_args()
    result = trim_syzlang(
        args.refine,
        data_root=args.data_root,
        output=args.output,
        drop_unused=args.drop_unused,
    )
    print(f"wrote {result['output']}")
    print("\n".join(result["notes"]))


if __name__ == "__main__":
    main()
