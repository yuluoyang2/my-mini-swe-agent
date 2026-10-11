import json
from pathlib import Path
from typing import Any

from minisweagent.environments.local import LocalEnvironment, LocalEnvironmentConfig
from minisweagent.exceptions import Submitted
from minisweagent.models.utils import (
    callgraph_tools,
    chain_result_tools,
    fuzzing_coverage_tools,
    kernel_source_tools,
    refine_result_tools,
    syzlang_tools,
)


class KernelEnvironmentConfig(LocalEnvironmentConfig):
    data_root: Path = kernel_source_tools.DEFAULT_DATA_ROOT
    linux_root: Path = kernel_source_tools.DEFAULT_LINUX_ROOT


class KernelEnvironment(LocalEnvironment):
    def __init__(self, *, config_class: type = KernelEnvironmentConfig, **kwargs):
        self.config = config_class(**kwargs)

    def execute(self, action: dict, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        tool = action.get("tool")
        if not tool or tool == "bash":
            return {
                "output": "",
                "returncode": -1,
                "exception_info": "bash is not available; call a result-writing tool to finish.",
            }
        try:
            result = self._execute_tool(action)
        except Submitted:
            raise
        except Exception as e:
            return {
                "output": "",
                "returncode": -1,
                "exception_info": f"An error occurred while executing {tool}: {e}",
                "extra": {"exception_type": type(e).__name__, "exception": str(e)},
            }
        return {
            "output": json.dumps(result, indent=2, ensure_ascii=False),
            "returncode": 0,
            "exception_info": "",
        }

    def _execute_tool(self, action: dict) -> dict[str, Any]:
        tool = action["tool"]
        args = action.get("args", {})
        if tool == "read_kernel_source":
            return kernel_source_tools.read_kernel_source(
                **args, data_root=self.config.data_root, linux_root=self.config.linux_root
            )
        if tool == "lookup_ops":
            return kernel_source_tools.lookup_ops(**args, data_root=self.config.data_root)
        if tool in CALLGRAPH_TOOLS:
            return CALLGRAPH_TOOLS[tool](**args, data_root=self.config.data_root)
        if tool in SYZLANG_TOOLS:
            return SYZLANG_TOOLS[tool](**args, data_root=self.config.data_root)
        if tool in FUZZING_COVERAGE_TOOLS:
            return FUZZING_COVERAGE_TOOLS[tool](**args, data_root=self.config.data_root)
        if tool in RESULT_TOOLS:
            result = RESULT_TOOLS[tool](**args, data_root=self.config.data_root)
            if tool not in FINISH_TOOLS:
                return result
            submission = Path(result["path"]).read_text()
            raise Submitted(
                {
                    "role": "exit",
                    "content": submission,
                    "extra": {"exit_status": "Submitted", "submission": submission},
                }
            )
        raise ValueError(f"Unknown tool: {tool}")


CALLGRAPH_TOOLS = {
    "func_bfs": callgraph_tools.func_bfs,
}

SYZLANG_TOOLS = {
    "search_syzlang": syzlang_tools.search_syzlang,
    "read_syzlang_def": syzlang_tools.read_syzlang_def,
    "read_syzlang_level": syzlang_tools.read_syzlang_level,
    "list_prunable_nodes": syzlang_tools.list_prunable_nodes,
    "list_syzlang_choices": syzlang_tools.list_syzlang_choices,
    "get_syscall_deps": syzlang_tools.get_syscall_deps,
}

FUZZING_COVERAGE_TOOLS = {
    "get_fuzz_coverage": fuzzing_coverage_tools.get_fuzz_coverage,
}

RESULT_TOOLS = {
    "write_chain_result": chain_result_tools.write_chain_result,
    "read_chain_result": refine_result_tools.read_chain_result,
    "write_refine_result": refine_result_tools.write_refine_result,
}

FINISH_TOOLS = {"write_chain_result", "write_refine_result"}
