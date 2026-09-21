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
            "Supply exactly one of func, type_name, or path. Use this when func_bfs source is missing or truncated."
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

FUNC_BFS_TOOL = {
    "type": "function",
    "function": {
        "name": "func_bfs",
        "description": (
            "Bounded BFS over the kernel callgraph. Default direction is reverse: walk callers "
            "toward syscall entry. Each node includes path-to-start; nearest nodes include truncated source. "
            "depth=1 reverse is direct callers; depth=1 forward is direct callees."
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

GET_SYSCALL_DEPS_TOOL = {
    "type": "function",
    "function": {
        "name": "get_syscall_deps",
        "description": "Read explicit depend/depended edges for one or more syzkaller syscalls. The graph only records direct flavor-resource links (e.g. socket$foo → bind$foo). Unflavored generic calls are often absent; missing edges do not mean those steps are invalid after a socket.",
        "parameters": {
            "type": "object",
            "properties": {
                "syscalls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Syzlang syscall names, usually every step in a candidate chain. The graph only contains explicit flavor-resource edges; unflavored generic calls are often missing.",
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

GET_FUZZ_COVERAGE_TOOL = {
    "type": "function",
    "function": {
        "name": "get_fuzz_coverage",
        "description": (
            "Look up dynamic fuzzing coverage. Supply exactly one of functions, syscall, or query. "
            "A hit is ground truth from real runs; absence only means the function or syscall was not observed."
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
            "Validate and write the final target-to-syzkaller syscall-chain result to a JSON file. "
            "A successful write finishes the task. Rejects unknown syscall names and fully duplicate chains."
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
                    "description": "Evidence-supported candidate syscall chains, ordered by recommendation strength.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "chain": {
                                "type": "array",
                                "description": "Ordered syscall steps.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "call": {
                                            "type": "string",
                                            "description": "Existing syzkaller syscall name.",
                                        },
                                        "params": {
                                            "type": "array",
                                            "description": "Optional top-level argument hints: union, const, or flags. Nested fields are not supported.",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "kind": {
                                                        "type": "string",
                                                        "description": "union, const, or flags.",
                                                    },
                                                    "arg": {
                                                        "type": "string",
                                                        "description": "Top-level syzlang argument name.",
                                                    },
                                                    "index": {
                                                        "type": "integer",
                                                        "description": "0-based top-level argument index, used if arg is omitted.",
                                                    },
                                                    "path": {
                                                        "type": "string",
                                                        "description": "For union: type.field of the chosen arm.",
                                                    },
                                                    "values": {
                                                        "type": "array",
                                                        "items": {"type": "string"},
                                                        "description": "For const/flags: names from the syzlang definition.",
                                                    },
                                                },
                                                "required": ["kind"],
                                            },
                                        },
                                    },
                                    "required": ["call"],
                                },
                            },
                            "evidence": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Short evidence strings supporting this chain.",
                            },
                        },
                        "required": ["chain"],
                    },
                },
                "path": {
                    "type": "string",
                    "description": "Optional output JSON path. Defaults to data/linux-6.6/results/<target>.chains.json.",
                },
                "fuzz_guidance": {
                    "type": "object",
                    "description": "Optional fuzzing focus guidance derived from callgraph/source evidence.",
                    "properties": {
                        "focus_target_functions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Regex for the exact target function to focus. At most one item.",
                        },
                        "focus_hop1_functions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Regexes for functions that directly guide or dispatch to the target path. At most three items.",
                        },
                        "focus_hop2_functions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Regexes for callers or protocol-entry functions one level above hop1. At most three items.",
                        },
                        "focus_subsystem_files": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Kernel .c source files that define the target path or subsystem entry. At most three items; do not include header files.",
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

TOOL_GROUPS = {
    "bash": [BASH_TOOL],
    "kernel_source": KERNEL_SOURCE_TOOLS,
    "callgraph": FUNC_GRAPH_TOOLS,
    "syzlang": SYZLANG_TOOLS,
    "fuzzing_coverage": FUZZING_COVERAGE_TOOLS,
    "chain_result": CHAIN_RESULT_TOOLS,
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
