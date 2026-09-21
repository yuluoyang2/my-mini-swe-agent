from pathlib import Path

import pytest

from minisweagent.environments.kernel import KernelEnvironment
from minisweagent.exceptions import Submitted
from minisweagent.models.utils.actions_toolcall import get_tool_specs
from minisweagent.models.utils.callgraph_tools import func_bfs
from minisweagent.models.utils.fuzzing_coverage_tools import get_fuzz_coverage
from minisweagent.models.utils.kernel_source_tools import lookup_ops, read_kernel_source
from minisweagent.models.utils.chain_result_tools import validate_chain_result, validate_chain_semantics
from minisweagent.models.utils.syzlang_tools import get_syscall_deps, read_syzlang_def

DATA_ROOT = Path(__file__).resolve().parents[2] / "data/linux-6.6"
pytestmark = pytest.mark.skipif(
    not (DATA_ROOT / "callgraph/callers.index.json").exists()
    or not (DATA_ROOT / "source/func.index.json").exists()
    or not (DATA_ROOT / "progfunc_index/func_index.json").exists()
    or not (DATA_ROOT / "syzlang/syzlang.index.json").exists(),
    reason="kernel query indexes are not present",
)


def test_kernel_tool_groups_are_collapsed():
    assert [tool["function"]["name"] for tool in get_tool_specs(["callgraph"])] == ["func_bfs"]
    assert [tool["function"]["name"] for tool in get_tool_specs(["kernel_source"])] == ["read_kernel_source", "lookup_ops"]
    assert [tool["function"]["name"] for tool in get_tool_specs(["syzlang"])] == [
        "search_syzlang",
        "read_syzlang_def",
        "get_syscall_deps",
    ]
    assert [tool["function"]["name"] for tool in get_tool_specs(["fuzzing_coverage"])] == ["get_fuzz_coverage"]
    assert "bash" not in [tool["function"]["name"] for tool in get_tool_specs(["chain_result"])]


def test_func_bfs_defaults_to_reverse_and_attaches_caller_source():
    result = func_bfs("nr_add_node", max_depth=1, max_nodes=20, data_root=DATA_ROOT)
    assert result["direction"] == "reverse"
    by_name = {record["function"]: record for record in result["records"]}
    assert by_name["nr_rt_ioctl"]["path"] == ["nr_rt_ioctl", "nr_add_node"]
    assert "SIOCADDRT" in by_name["nr_rt_ioctl"]["source"]
    assert "NETROM_NODE" in by_name["nr_rt_ioctl"]["source"]
    assert "source" not in func_bfs("nr_add_node", include_source=False, max_nodes=5, data_root=DATA_ROOT)["records"][0]


def test_func_bfs_reverse_keeps_path_across_depths():
    result = func_bfs("nr_add_node", max_depth=2, max_nodes=30, data_root=DATA_ROOT)
    by_name = {record["function"]: record for record in result["records"]}
    assert by_name["nr_add_node"]["path"] == ["nr_add_node"]
    assert by_name["nr_rt_ioctl"]["path"] == ["nr_rt_ioctl", "nr_add_node"]
    assert by_name["nr_ioctl"]["path"][-1] == "nr_add_node"


def test_read_kernel_source_and_lookup_ops_cover_old_entry_points():
    function = read_kernel_source(func="nr_rt_ioctl", data_root=DATA_ROOT)
    assert "SIOCADDRT" in function["records"][0]["source"]
    ops = lookup_ops(handler="hdm_disconnect", data_root=DATA_ROOT)
    assert ops["records"][0]["table"] == "hdm_usb"
    table = lookup_ops(table="hdm_usb", data_root=DATA_ROOT)
    assert any(record["handler"] == "hdm_disconnect" for record in table["records"])
    with pytest.raises(ValueError, match="exactly one"):
        lookup_ops(handler="hdm_disconnect", table="hdm_usb", data_root=DATA_ROOT)
    with pytest.raises(ValueError, match="exactly one"):
        read_kernel_source(func="nr_rt_ioctl", type_name="file_operations", data_root=DATA_ROOT)


def test_syzlang_read_defaults_to_full_and_deps_accept_a_chain():
    brief = read_syzlang_def("ioctl$sock_netrom_SIOCADDRT", full=False, data_root=DATA_ROOT)
    full = read_syzlang_def("ioctl$sock_netrom_SIOCADDRT", data_root=DATA_ROOT)
    assert full["full"] is True
    assert len(full["records"][0]["source"]) > len(brief["records"][0]["source"])
    deps = get_syscall_deps(
        ["syz_init_net_socket$netrom", "ioctl$sock_netrom_SIOCADDRT"],
        data_root=DATA_ROOT,
    )
    assert "ioctl$sock_netrom_SIOCADDRT" in deps["syscalls"]
    assert any(
        item.get("syscall") == "syz_init_net_socket$netrom"
        for item in deps["syscalls"]["ioctl$sock_netrom_SIOCADDRT"]["depend"]
    )


def test_get_fuzz_coverage_unifies_function_syscall_and_search():
    expanded = get_fuzz_coverage(functions=["xfrm_alloc_spi"], expand_depth=1, data_root=DATA_ROOT)
    by_name = {record["function"]: record for record in expanded["records"]}
    assert "xfrm_alloc_userspi" in by_name
    assert "sendmsg$nl_xfrm" in by_name["xfrm_alloc_spi"]["syscalls"]
    syscall = get_fuzz_coverage(syscall="sendmsg$nl_xfrm", file_query="xfrm", data_root=DATA_ROOT)
    assert syscall["exists"]
    assert syscall["records"]
    assert all("xfrm" in record["file"] for record in syscall["records"])
    search = get_fuzz_coverage(query="xfrm_alloc_spi", data_root=DATA_ROOT)
    assert search["records"][0]["function"] == "xfrm_alloc_spi"
    with pytest.raises(ValueError, match="exactly one"):
        get_fuzz_coverage(functions=["xfrm_alloc_spi"], syscall="sendmsg$nl_xfrm", data_root=DATA_ROOT)


def test_validate_chain_semantics_unknown_names_and_one_resource_group():
    sco = [{"call": "syz_init_net_socket$bt_sco"}, {"call": "connect$bt_sco"}, {"call": "close"}]
    l2cap = [{"call": "syz_init_net_socket$bt_l2cap"}, {"call": "connect$bt_l2cap"}, {"call": "close"}]
    listen_chain = [
        {"call": "syz_init_net_socket$bt_l2cap"},
        {"call": "bind$bt_l2cap"},
        {"call": "listen"},
        {"call": "syz_emit_vhci"},
    ]
    bind_only = [
        {"call": "syz_init_net_socket$bt_l2cap"},
        {"call": "bind$bt_l2cap"},
        {"call": "syz_emit_vhci"},
    ]
    mixed = sco + [{"call": "syz_init_net_socket$bt_l2cap"}, {"call": "connect$bt_l2cap"}]
    assert validate_chain_semantics([{"chain": sco}, {"chain": l2cap}], data_root=DATA_ROOT) == []
    assert validate_chain_semantics([{"chain": listen_chain}, {"chain": bind_only}], data_root=DATA_ROOT) == []
    assert validate_chain_semantics([{"chain": mixed}], data_root=DATA_ROOT) == []
    assert validate_chain_semantics([{"chain": [{"call": "syz_emit_vhci"}, {"call": "syz_emit_vhci"}]}], data_root=DATA_ROOT) == []
    with pytest.raises(ValueError, match="no satisfied resource-flow group"):
        validate_chain_semantics([{"chain": [{"call": "listen"}, {"call": "syz_emit_vhci"}]}], data_root=DATA_ROOT)
    with pytest.raises(ValueError, match="same syscall sequence"):
        validate_chain_semantics([{"chain": sco, "evidence": ["acl"]}, {"chain": sco, "evidence": ["le"]}], data_root=DATA_ROOT)
    with pytest.raises(ValueError, match="Unknown"):
        validate_chain_semantics([{"chain": [{"call": "socket$does_not_exist"}]}], data_root=DATA_ROOT)
    event_a = [
        {"call": "syz_init_net_socket$bt_l2cap"},
        {"call": "syz_emit_vhci", "params": [{"kind": "union", "arg": "data", "path": "pkt.EVT_A"}]},
    ]
    event_b = [
        {"call": "syz_init_net_socket$bt_l2cap"},
        {"call": "syz_emit_vhci", "params": [{"kind": "union", "arg": "data", "path": "pkt.EVT_B"}]},
    ]
    assert validate_chain_semantics([{"chain": event_a}, {"chain": event_b}], data_root=DATA_ROOT) == []
    validate_chain_result("t", [{"chain": event_a}])
    with pytest.raises(ValueError, match="same syscall sequence"):
        validate_chain_semantics([{"chain": event_a}, {"chain": event_a}], data_root=DATA_ROOT)
    with pytest.raises(ValueError, match="kind must be"):
        validate_chain_result("t", [{"chain": [{"call": "syz_emit_vhci", "params": [{"kind": "buffer"}]}]}])
    with pytest.raises(ValueError, match="union requires path"):
        validate_chain_result("t", [{"chain": [{"call": "syz_emit_vhci", "params": [{"kind": "union", "arg": "data"}]}]}])


def test_kernel_environment_rejects_bash_and_finishes_on_write(tmp_path):
    env = KernelEnvironment()
    denied = env.execute({"tool": "bash", "command": "echo hi"})
    assert denied["returncode"] == -1
    assert "bash is not available" in denied["exception_info"]
    out_file = tmp_path / "t.chains.json"
    with pytest.raises(Submitted) as exc:
        env.execute(
            {
                "tool": "write_chain_result",
                "args": {
                    "target": "nr_add_node",
                    "chains": [
                        {
                            "chain": [
                                {"call": "syz_init_net_socket$netrom"},
                                {"call": "ioctl$sock_netrom_SIOCADDRT"},
                            ]
                        }
                    ],
                    "path": str(out_file),
                },
            }
        )
    assert "syz_init_net_socket$netrom" in exc.value.messages[0]["extra"]["submission"]
    assert out_file.exists()
