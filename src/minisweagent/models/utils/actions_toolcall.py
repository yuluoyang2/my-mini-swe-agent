"""Parse actions & format observations with toolcalls"""

import json
import time

from jinja2 import StrictUndefined, Template

from minisweagent.exceptions import FormatError
from minisweagent.models.utils.openai_multimodal import expand_multimodal_content

BASH_TOOL = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": "Execute a bash command",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute",
                }
            },
            "required": ["command"],
        },
    },
}

READ_KERNEL_SOURCE_TOOL = {
    "type": "function",
    "function": {
        "name": "read_kernel_source",
        "description": (
            "Read Linux kernel source by function name, type name, or file path. "
            "Supply exactly one of func, type_name, or path. File mode includes numbered lines, comments, macros, and .tbl files."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "func": {"type": "string", "description": "Function name to look up."},
                "type_name": {"type": "string", "description": "struct/union/enum/typedef name to look up."},
                "path": {"type": "string", "description": "Source file path. Pair with line, or start_line and end_line."},
                "kind": {
                    "type": "string",
                    "enum": ["struct", "enum", "struct_typedef", "enum_typedef", "any"],
                    "description": "Type index to query when type_name is set. Default any.",
                },
                "file_hint": {"type": "string", "description": "Optional file path hint to disambiguate duplicate names."},
                "line": {"type": "integer", "description": "1-based line number for path mode; returns nearby context."},
                "context": {"type": "integer", "description": "Lines of context around line in path mode. Default 40."},
                "start_line": {"type": "integer", "description": "First line to read in path mode."},
                "end_line": {"type": "integer", "description": "Last line to read in path mode."},
                "max_results": {"type": "integer", "description": "Maximum matching definitions to return."},
            },
        },
    },
}

LOOKUP_OPS_TOOL = {
    "type": "function",
    "function": {
        "name": "lookup_ops",
        "description": (
            "Look up kernel ops/init tables. Supply exactly one of handler or table. "
            "Finds struct field registrations such as ops.ioctl, not array dispatch tables like table[CMD]."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "handler": {"type": "string", "description": "Handler function name referenced by an initialization table field."},
                "table": {"type": "string", "description": "Initialization table variable name."},
                "field": {"type": "string", "description": "Optional field filter, such as ioctl, probe, or connect."},
                "table_type": {"type": "string", "description": "Optional table type filter, such as struct file_operations."},
                "file_hint": {"type": "string", "description": "Optional source file path hint."},
                "max_results": {"type": "integer", "description": "Maximum matching table fields to return."},
            },
        },
    },
}

KERNEL_SOURCE_TOOLS = [
    READ_KERNEL_SOURCE_TOOL,
    LOOKUP_OPS_TOOL,
]

ENTRY_PAGE_PROPERTIES = {
    "offset": {"type": "integer", "minimum": 0, "description": "Pagination offset. Default 0."},
    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Maximum records per page."},
}

ENTRY_TOOLS = KERNEL_SOURCE_TOOLS + [
    {
        "type": "function",
        "function": {
            "name": "search_kernel_source",
            "description": (
                "Search the kernel source tree, including comments, function references, dispatch arrays, "
                "registrations, macros, and syscall .tbl files. Returns matching lines with context and next_offset. "
                "Matches are text references; inspect source to identify their meaning."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1},
                    "path": {"type": "string", "description": "File or directory within the kernel tree. Default entire tree."},
                    "regex": {"type": "boolean", "description": "Treat query as regex. Default false (literal search)."},
                    "context": {"type": "integer", "minimum": 0, "maximum": 20, "description": "Context lines on each side. Default 3."},
                    **ENTRY_PAGE_PROPERTIES,
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_func_neighbors",
            "description": (
                "Query one layer of MLTA callers or callees, with candidate source files and pagination. "
                "Callgraph edges may be spurious or missing; use source references and registrations to interpret them. "
                "Callee file lists may contain multiple definitions with the same name."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function": {"type": "string", "minLength": 1},
                    "direction": {"type": "string", "enum": ["callers", "callees"], "description": "Default callers."},
                    "file_hint": {"type": "string", "description": "Filter caller files: returned callers, or the start definition in callees mode."},
                    **ENTRY_PAGE_PROPERTIES,
                },
                "required": ["function"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_syscall",
            "description": (
                "Search the configured architecture's syscall .tbl, returning Linux names, ABI, entry symbols, "
                "source lines, and original rows. Empty query lists entries. Original tables can also be read with read_kernel_source."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Literal substring of a table row, e.g. a syscall name or entry symbol."},
                    "abis": {"type": "array", "items": {"type": "string"}, "description": "Optional ABI override. Defaults to environment syscall_abis."},
                    **ENTRY_PAGE_PROPERTIES,
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_entry_result",
            "description": (
                "Write interface-grouped Linux syscall mappings to results/<target>.entry.json and finish. "
                "The output has top-level function (from target) and entries; each entry contains syscall and resource. "
                "Syscall names are checked against the configured table and ABI. "
                "Resource contains key interface parameter identifiers, values, device paths, or user-interface structure names. "
                "Multiple related parameters are allowed; omit explanations, call chains, internal handlers, and code snippets. "
                "Entries contain only syscall names and key resource parameters. Group alternative interfaces separately."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "minLength": 1},
                    "entries": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "syscall": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
                                "resource": {
                                    "type": "array",
                                    "description": (
                                        "Key interface parameter identifiers, values, device paths, or structure names. "
                                        "Multiple related parameters are allowed; omit explanations and code."
                                    ),
                                    "items": {"type": "string", "minLength": 1},
                                },
                            },
                            "required": ["syscall", "resource"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["target", "entries"],
            },
        },
    },
]

FUNC_BFS_TOOL = {
    "type": "function",
    "function": {
        "name": "func_bfs",
        "description": (
            "Bounded BFS over an MLTA callgraph. Edges are a hint: indirect calls can be "
            "spurious or missing. Confirm a path in source before treating it as real. "
            "Default direction is reverse. depth=1 reverse is direct callers; depth=1 forward is direct callees."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "start": {
                    "type": "string",
                    "description": "Function name to start BFS from, usually the target.",
                },
                "direction": {
                    "type": "string",
                    "enum": ["forward", "reverse"],
                    "description": "reverse = callers (default). forward = callees.",
                },
                "file_hint": {
                    "type": "string",
                    "description": "Optional start-function source file path hint used to disambiguate duplicate names.",
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum BFS depth. Default 3.",
                },
                "max_nodes": {
                    "type": "integer",
                    "description": "Maximum number of function nodes to return across all layers.",
                },
                "include_source": {
                    "type": "boolean",
                    "description": "Include truncated source for the nearest nodes. Default true.",
                },
                "source_limit": {
                    "type": "integer",
                    "description": "Maximum number of source characters to attach per node.",
                },
            },
            "required": ["start"],
        },
    },
}

FUNC_GRAPH_TOOLS = [
    FUNC_BFS_TOOL,
]

SEARCH_SYZLANG_TOOL = {
    "type": "function",
    "function": {
        "name": "search_syzlang",
        "description": "Search syzkaller syzlang definition names, top-level definition sources, and file paths by keyword. Only real keyword matches are returned.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Keyword to search for, such as an ioctl command, protocol name, type name, device name, or subsystem keyword.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of matching definitions to return.",
                },
            },
            "required": ["query"],
        },
    },
}

READ_SYZLANG_DEF_TOOL = {
    "type": "function",
    "function": {
        "name": "read_syzlang_def",
        "description": "Read a syzkaller syzlang definition by name. Default full=true includes the precomputed related type/flags/resource group.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Syzlang definition name from search_syzlang, such as a syscall, type, flags, resource, or const.",
                },
                "file_hint": {
                    "type": "string",
                    "description": "Optional syzlang file path hint used to disambiguate duplicate definition names.",
                },
                "full": {
                    "type": "boolean",
                    "description": "True (default) returns the full definition group; false returns only the top-level definition.",
                },
            },
            "required": ["name"],
        },
    },
}

LIST_SYZLANG_CHOICES_TOOL = {
    "type": "function",
    "function": {
        "name": "list_syzlang_choices",
        "description": (
            "List union arms and flags values reachable from one or more syscalls. "
            "Use this when refining selected chain calls. "
            "Returns compact choice names, not full nested struct bodies."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "syscalls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Syzlang syscall names, usually every unique call in the candidate chains.",
                },
            },
            "required": ["syscalls"],
        },
    },
}

READ_SYZLANG_LEVEL_TOOL = {
    "type": "function",
    "function": {
        "name": "read_syzlang_level",
        "description": (
            "Read exactly one level of a syscall's syzlang parameter tree. Start with an empty path, "
            "then expand only paths returned by the previous result. Recommend union, flags, "
            "named const, and string choices that can reach the target. Drop choices that cannot. "
            "Integers, len, bytesize, bitsize, csum, proc, and resource stay with syzkaller."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "call": {
                    "type": "string",
                    "description": "Existing syzkaller syscall name.",
                },
                "path": {
                    "type": "string",
                    "description": "Path returned by an earlier read_syzlang_level call. Omit for syscall arguments.",
                },
            },
            "required": ["call"],
        },
    },
}

GET_SYSCALL_DEPS_TOOL = {
    "type": "function",
    "function": {
        "name": "get_syscall_deps",
        "description": "Read explicit depend/depended edges for one or more syzkaller syscalls. The graph has only explicit resource links (e.g. socket$foo → bind$foo) and does not include implicit dependencies.",
        "parameters": {
            "type": "object",
            "properties": {
                "syscalls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Syzlang syscall names, usually every step in a candidate chain. The graph only contains explicit resource edges, not implicit ones.",
                },
                "include_depend": {
                    "type": "boolean",
                    "description": "Whether to include syscalls each name depends on.",
                },
                "include_depended": {
                    "type": "boolean",
                    "description": "Whether to include syscalls that depend on each name.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of dependencies to return for each direction.",
                },
            },
            "required": ["syscalls"],
        },
    },
}

SYZLANG_TOOLS = [
    SEARCH_SYZLANG_TOOL,
    READ_SYZLANG_DEF_TOOL,
    GET_SYSCALL_DEPS_TOOL,
]

LIST_PRUNABLE_NODES_TOOL = {
    "type": "function",
    "function": {
        "name": "list_prunable_nodes",
        "description": (
            "List prunable parameter nodes for syscalls on the chain. "
            "Each node is a union, flags, or string with at least two named choices. "
            "path, kind, type, and choices can be copied into write_refine_result. "
            "keep must be a subset of choices. An empty list means that syscall has nothing to prune."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "calls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Syzlang syscall names from the written chain.",
                },
            },
            "required": ["calls"],
        },
    },
}

SYZLANG_LEVEL_TOOLS = [
    LIST_PRUNABLE_NODES_TOOL,
    READ_SYZLANG_LEVEL_TOOL,
]

SYZLANG_CHOICES_TOOLS = [
    LIST_SYZLANG_CHOICES_TOOL,
]

GET_FUZZ_COVERAGE_TOOL = {
    "type": "function",
    "function": {
        "name": "get_fuzz_coverage",
        "description": (
            "Look up dynamic fuzzing coverage. Supply exactly one of functions, syscall, or query. "
            "A hit shows that syscall appeared in a real run that reached the function. "
            "It does not mean the preceding setup calls can be omitted. "
            "Absence only means the function or syscall was not observed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "functions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Function names to start from, usually just the target. Expands reverse-callgraph neighbors.",
                },
                "syscall": {
                    "type": "string",
                    "description": "Syzlang syscall name whose covered source files should be returned.",
                },
                "query": {
                    "type": "string",
                    "description": "Keyword to search covered function names or example source file paths.",
                },
                "expand_depth": {
                    "type": "integer",
                    "description": "Reverse-callgraph depth when functions is set. Default 1.",
                },
                "file_query": {
                    "type": "string",
                    "description": "Optional keyword used to filter covered source files when syscall is set.",
                },
                "max_functions": {"type": "integer", "description": "Maximum functions after neighborhood expansion."},
                "max_syscalls": {"type": "integer", "description": "Maximum covering syscalls per function."},
                "max_examples": {"type": "integer", "description": "Maximum example programs per function."},
                "max_files": {"type": "integer", "description": "Maximum covered source files when syscall is set."},
                "max_results": {"type": "integer", "description": "Maximum matches when query is set."},
            },
        },
    },
}

FUZZING_COVERAGE_TOOLS = [
    GET_FUZZ_COVERAGE_TOOL,
]

WRITE_CHAIN_RESULT_TOOL = {
    "type": "function",
    "function": {
        "name": "write_chain_result",
        "description": (
            "Validate and write ordered syscall-name chains with their kernel call stacks. "
            "A successful write finishes the task."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target Linux kernel function name.",
                },
                "chains": {
                    "type": "array",
                    "description": "Candidate syscall chains, ordered by recommendation strength. Each chain includes its call stack.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "chain": {
                                "type": "array",
                                "description": "Ordered syzkaller syscall names, for example [\"syz_usb_connect\", \"syz_usb_disconnect\"].",
                                "items": {"type": "string", "minLength": 1},
                            },
                            "stack": {
                                "type": "array",
                                "maxItems": 4,
                                "items": {"type": "string"},
                                "description": "At most 4 kernel function names: the target, its direct caller, and callers above that. Names must come from read_kernel_source. Do not include syscalls.",
                            },
                        },
                        "required": ["chain", "stack"],
                    },
                },
                "path": {
                    "type": "string",
                    "description": "Optional output JSON path. Defaults to data/linux-6.6/results/<target>.chains.json.",
                },
                "fuzz_guidance": {
                    "type": "object",
                    "description": "Source-grounded B and C focus candidates. Target and target file are filled automatically; B is always non-empty in the written result.",
                    "properties": {
                        "near_functions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "B candidates: exact function names, no regex, at most three. Prefer selective functions 1-2 source-linked stack edges from the target. If only generic callers exist, include the nearest one. When omitted or empty, the writer fills the nearest verified stack caller.",
                        },
                        "path_functions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "C candidates: exact function names, no regex, at most three. Choose upstream path functions or a required earlier callback from the target's driver. Leave empty if source evidence is weak.",
                        },
                    },
                },
            },
            "required": ["target", "chains"],
        },
    },
}

CHAIN_RESULT_TOOLS = [
    WRITE_CHAIN_RESULT_TOOL,
]

READ_CHAIN_RESULT_TOOL = {
    "type": "function",
    "function": {
        "name": "read_chain_result",
        "description": (
            "Read the written syscall sequences and their call stacks. "
            "Use each stack as the source-reading path from the target through its callers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target Linux kernel function name."},
                "path": {
                    "type": "string",
                    "description": "Optional chain-result path. Defaults to data/linux-6.6/results/<target>.chains.json.",
                },
            },
            "required": ["target"],
        },
    },
}

WRITE_REFINE_RESULT_TOOL = {
    "type": "function",
    "function": {
        "name": "write_refine_result",
        "description": (
            "Write one keep-list per syscall and finish. "
            "Keep union, flags, named const, and string choices that can reach the target. "
            "Do not recommend integers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target from the written chain result."},
                "calls": {
                    "type": "array",
                    "description": "One entry per syscall that has something to prune. An empty list is valid.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "call": {"type": "string"},
                            "refinements": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "path": {"type": "string"},
                                        "kind": {
                                            "type": "string",
                                            "enum": ["union", "flags", "const", "string"],
                                        },
                                        "type": {"type": "string"},
                                        "keep": {"type": "array", "items": {"type": "string"}},
                                    },
                                    "required": ["path", "kind", "type", "keep"],
                                },
                            },
                        },
                        "required": ["call", "refinements"],
                    },
                },
                "chain_path": {
                    "type": "string",
                    "description": "Optional written chain-result path.",
                },
                "path": {
                    "type": "string",
                    "description": "Optional output path. Defaults to data/linux-6.6/results/<target>.refine.json beside the chain file.",
                },
            },
            "required": ["target", "calls"],
        },
    },
}

REFINE_RESULT_TOOLS = [
    READ_CHAIN_RESULT_TOOL,
    WRITE_REFINE_RESULT_TOOL,
]

TOOL_GROUPS = {
    "bash": [BASH_TOOL],
    "entry": ENTRY_TOOLS,
    "kernel_source": KERNEL_SOURCE_TOOLS,
    "callgraph": FUNC_GRAPH_TOOLS,
    "syzlang": SYZLANG_TOOLS,
    "syzlang_level": SYZLANG_LEVEL_TOOLS,
    "syzlang_choices": SYZLANG_CHOICES_TOOLS,
    "fuzzing_coverage": FUZZING_COVERAGE_TOOLS,
    "chain_result": CHAIN_RESULT_TOOLS,
    "refine_result": REFINE_RESULT_TOOLS,
}


def get_tool_specs(tool_groups: list[str] | None = None) -> list[dict]:
    groups = ["bash"] if tool_groups is None else tool_groups
    unknown_groups = sorted(set(groups) - set(TOOL_GROUPS))
    if unknown_groups:
        raise ValueError(f"Unknown tool groups: {unknown_groups}. Available groups: {sorted(TOOL_GROUPS)}")
    return [tool for group in groups for tool in TOOL_GROUPS[group]]


def parse_toolcall_actions(
    tool_calls: list,
    *,
    tools: list[dict] | None = None,
    format_error_template: str,
    template_kwargs: dict | None = None,
) -> list[dict]:
    """Parse tool calls from the response. Raises FormatError if unknown tool or invalid args.

    ``template_kwargs`` are extra variables exposed to ``format_error_template`` (e.g.
    ``{"finish_reason": ...}`` so a template can distinguish a real format mistake from a
    ``max_tokens`` truncation).
    """
    template_kwargs = template_kwargs or {}
    if not tool_calls:
        raise FormatError(
            {
                "role": "user",
                "content": Template(format_error_template, undefined=StrictUndefined).render(
                    error="No tool calls found in the response. Every response MUST include at least one tool call.",
                    actions=[],
                    has_tool_calls=False,
                    **template_kwargs,
                ),
                "extra": {"interrupt_type": "FormatError"},
            }
        )
    actions = []
    allowed_tool_names = {tool["function"]["name"] for tool in tools or [BASH_TOOL]}
    for tool_call in tool_calls:
        error_msg = ""
        args = {}
        try:
            args = json.loads(tool_call.function.arguments)
        except Exception as e:
            error_msg = f"Error parsing tool call arguments: {e}."
        if tool_call.function.name not in allowed_tool_names:
            error_msg += f"Unknown tool '{tool_call.function.name}'."
        if not isinstance(args, dict):
            error_msg += "Tool call arguments must be a JSON object."
        elif tool_call.function.name == "bash" and "command" not in args:
            error_msg += "Missing 'command' argument in bash tool call."
        if error_msg:
            raise FormatError(
                {
                    "role": "user",
                    "content": Template(format_error_template, undefined=StrictUndefined).render(
                        actions=[], error=error_msg.strip(), has_tool_calls=True, **template_kwargs
                    ),
                    "extra": {"interrupt_type": "FormatError"},
                }
            )
        action = {"tool": tool_call.function.name, "args": args, "tool_call_id": tool_call.id}
        if tool_call.function.name == "bash":
            action["command"] = args["command"]
        actions.append(action)
    return actions


def format_toolcall_observation_messages(
    *,
    actions: list[dict],
    outputs: list[dict],
    observation_template: str,
    template_vars: dict | None = None,
    multimodal_regex: str = "",
) -> list[dict]:
    """Format execution outputs into tool result messages."""
    not_executed = {"output": "", "returncode": -1, "exception_info": "action was not executed"}
    padded_outputs = outputs + [not_executed] * (len(actions) - len(outputs))
    results = []
    for action, output in zip(actions, padded_outputs):
        content = Template(observation_template, undefined=StrictUndefined).render(
            action=action, output=output, **(template_vars or {})
        )
        msg = {
            "content": content,
            "extra": {
                "tool": action.get("tool", "bash" if "command" in action else ""),
                "raw_output": output.get("output", ""),
                "returncode": output.get("returncode"),
                "timestamp": time.time(),
                "exception_info": output.get("exception_info"),
                **output.get("extra", {}),
            },
        }
        if "tool_call_id" in action:
            msg["tool_call_id"] = action["tool_call_id"]
            msg["role"] = "tool"
        else:
            msg["role"] = "user"  # human issued commands
        if multimodal_regex:
            msg = expand_multimodal_content(msg, pattern=multimodal_regex)
        results.append(msg)
    return results
