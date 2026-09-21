# Kernel Source Analyzer

This directory contains a two-stage source analyzer for kernel-focused tools.

1. `ast_analyzer` reads a Linux `compile_commands.json` with Clang AST and emits raw JSONL facts:
   - `func.jsonl`
   - `struct.jsonl`
   - `enum.jsonl`
   - `struct-typedef.jsonl`
   - `enum-typedef.jsonl`
   - `ops.jsonl`
2. `preprocess.py` converts those JSONL files into compact indexes for agent tools:
   - `func.index.json`
   - `type.index.json`
   - `ops.index.json`

Build:

```bash
make
```

Run AST extraction:

```bash
./ast_analyzer -p /path/to/compile_commands.json --out-dir /tmp/kernel-facts
```

Build indexes:

```bash
python preprocess.py build /tmp/kernel-facts /tmp/kernel-index --linux-root /path/to/linux
```
