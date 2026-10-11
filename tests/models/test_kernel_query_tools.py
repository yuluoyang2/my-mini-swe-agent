import json
from pathlib import Path

import pytest

from minisweagent.environments.kernel import KernelEnvironment
from minisweagent.exceptions import Submitted
from minisweagent.models.utils.actions_toolcall import get_tool_specs
from minisweagent.models.utils.callgraph_tools import func_bfs
from minisweagent.models.utils.fuzzing_coverage_tools import get_fuzz_coverage
from minisweagent.models.utils.kernel_source_tools import lookup_ops, read_kernel_source
from minisweagent.models.utils.chain_result_tools import validate_chain_result, validate_chain_semantics, write_chain_result
from minisweagent.models.utils.refine_result_tools import read_chain_result, write_refine_result
from minisweagent.models.utils.syzlang_tools import get_syscall_deps, list_prunable_nodes, read_syzlang_def

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
    assert [tool["function"]["name"] for tool in get_tool_specs(["syzlang_level"])] == [
        "list_prunable_nodes",
        "read_syzlang_level",
    ]
    assert [tool["function"]["name"] for tool in get_tool_specs(["syzlang_choices"])] == ["list_syzlang_choices"]
    assert [tool["function"]["name"] for tool in get_tool_specs(["fuzzing_coverage"])] == ["get_fuzz_coverage"]
    assert "bash" not in [tool["function"]["name"] for tool in get_tool_specs(["chain_result"])]
    assert [tool["function"]["name"] for tool in get_tool_specs(["refine_result"])] == [
        "read_chain_result",
        "write_refine_result",
    ]


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


def test_list_prunable_nodes_returns_named_choices_with_paths():
    listed = list_prunable_nodes(
        ["syz_emit_vhci", "syz_init_net_socket$bt_l2cap", "listen"],
        data_root=DATA_ROOT,
    )
    vhci = {node["path"]: node for node in listed["calls"]["syz_emit_vhci"]}
    assert vhci["data"]["kind"] == "union" and "HCI_EVENT_PKT" in vhci["data"]["choices"]
    link = vhci["data.HCI_EVENT_PKT.hdr.hci_ev_conn_complete.payload.link_type"]
    assert link["type"] == "link_types" and "ACL_LINK" in link["choices"]
    assert listed["calls"]["listen"] == []
    assert "proto" not in {node["path"] for node in listed["calls"]["syz_init_net_socket$bt_l2cap"]}
    assert all(
        node["kind"] in {"union", "flags", "string"} and len(node["choices"]) >= 2
        for nodes in listed["calls"].values()
        for node in nodes
    )
    with pytest.raises(ValueError, match="must not be empty"):
        list_prunable_nodes([], data_root=DATA_ROOT)
    with pytest.raises(ValueError, match="Unknown syzkaller syscall"):
        list_prunable_nodes("not_a_syscall", data_root=DATA_ROOT)


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
    with pytest.raises(ValueError, match="same calls and refinements"):
        validate_chain_semantics([{"chain": sco, "evidence": ["acl"]}, {"chain": sco, "evidence": ["le"]}], data_root=DATA_ROOT)
    with pytest.raises(ValueError, match="Unknown"):
        validate_chain_semantics([{"chain": [{"call": "socket$does_not_exist"}]}], data_root=DATA_ROOT)
    event = [{"call": "syz_init_net_socket$bt_l2cap"}, {"call": "syz_emit_vhci"}]
    assert validate_chain_semantics([{"chain": event}], data_root=DATA_ROOT) == []
    validate_chain_result("t", [{"chain": event}])
    with pytest.raises(ValueError, match="same calls and refinements"):
        validate_chain_semantics([{"chain": event, "evidence": ["a"]}, {"chain": event, "evidence": ["b"]}], data_root=DATA_ROOT)
    with pytest.raises(ValueError, match="must use refinements instead of params"):
        validate_chain_result("t", [{"chain": [{"call": "syz_emit_vhci", "params": [{"kind": "union", "path": "pkt.EVT_A"}]}]}])


def test_refinements_keep_concrete_values_and_leave_lengths_alone():
    chain = [
        {
            "call": "syz_init_net_socket$bt_l2cap",
            "refinements": [{"path": "proto", "kind": "const", "type": "const", "keep": ["BTPROTO_L2CAP"]}],
        },
        {
            "call": "bind$bt_l2cap",
            "refinements": [
                {"path": "addr.l2_family", "kind": "const", "type": "int16", "keep": ["AF_BLUETOOTH"]},
                {"path": "addr.l2_cid", "kind": "scalar", "type": "int16", "keep": ["4"]},
                {"path": "addr.l2_bdaddr_type", "kind": "flags", "type": "bdaddr_type", "keep": ["BDADDR_LE_PUBLIC"]},
            ],
        },
        {
            "call": "syz_emit_vhci",
            "refinements": [{"path": "data", "kind": "union", "type": "vhci_pkt", "keep": ["HCI_EVENT_PKT"]}],
        },
    ]
    assert validate_chain_semantics([{"chain": chain}], data_root=DATA_ROOT) == []
    with pytest.raises(ValueError, match="unknown choices"):
        validate_chain_semantics(
            [{"chain": [{"call": "syz_init_net_socket$bt_l2cap", "refinements": [
                {"path": "proto", "kind": "const", "type": "const", "keep": ["BTPROTO_HCI"]},
            ]}]}],
            data_root=DATA_ROOT,
        )
    with pytest.raises(ValueError, match="non-integer"):
        validate_chain_semantics(
            [{"chain": [{"call": "bind$bt_l2cap", "refinements": [
                {"path": "addr.l2_cid", "kind": "scalar", "type": "int16", "keep": ["ATT"]},
            ]}]}],
            data_root=DATA_ROOT,
        )
    with pytest.raises(ValueError, match="derived"):
        validate_chain_semantics(
            [{"chain": [{"call": "bind$bt_l2cap", "refinements": [
                {"path": "addrlen", "kind": "scalar", "type": "len", "keep": ["14"]},
            ]}]}],
            data_root=DATA_ROOT,
        )


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
    read = env.execute({
        "tool": "read_chain_result",
        "args": {"target": "nr_add_node", "path": str(out_file)},
    })
    assert read["returncode"] == 0
    refine_file = tmp_path / "t.refine.json"
    with pytest.raises(Submitted) as refine_exc:
        env.execute(
            {
                "tool": "write_refine_result",
                "args": {
                    "target": "nr_add_node",
                    "chain_path": str(out_file),
                    "calls": [{
                        "call": "ioctl$sock_netrom_SIOCADDRT",
                        "refinements": [{
                            "path": "arg.type",
                            "kind": "flags",
                            "type": "nr_route_type",
                            "keep": ["NETROM_NODE"],
                        }],
                    }],
                    "path": str(refine_file),
                },
            }
        )
    assert "NETROM_NODE" in refine_exc.value.messages[0]["extra"]["submission"]
    assert refine_file.exists()


def test_refine_result_keeps_the_written_call_sequence(tmp_path):
    chain_path = tmp_path / "l2cap.chains.json"
    chains = [{"chain": [{"call": "syz_init_net_socket$bt_l2cap"}, {"call": "syz_emit_vhci"}]}]
    write_chain_result(
        "l2cap_connect_cfm",
        [{"evidence": ["acl conn complete"], **record} for record in chains],
        path=str(chain_path),
        fuzz_guidance={"focus_target_functions": ["^l2cap_connect_cfm$"]},
        data_root=DATA_ROOT,
    )
    visible = read_chain_result("l2cap_connect_cfm", path=str(chain_path), data_root=DATA_ROOT)
    assert visible.keys() == {"target", "chains"}
    assert visible["chains"] == chains
    kept = [{
        "call": "syz_emit_vhci",
        "refinements": [{
            "path": "data",
            "kind": "union",
            "type": "vhci_pkt",
            "keep": ["HCI_EVENT_PKT"],
        }],
    }]
    output = write_refine_result(
        "l2cap_connect_cfm",
        [{
            "call": "syz_init_net_socket$bt_l2cap",
            "refinements": [{
                "path": "type",
                "kind": "flags",
                "type": "bt_l2cap_type",
                "keep": ["SOCK_SEQPACKET", "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW"],
            }],
        }, *kept],
        chain_path=str(chain_path),
        data_root=DATA_ROOT,
    )
    written = json.loads(Path(output["path"]).read_text())
    assert written == {"target": "l2cap_connect_cfm", "calls": kept}
    assert "HCI_EVENT_PKT" in Path(output["path"]).read_text()
    with pytest.raises(ValueError, match="must not include refinements"):
        write_chain_result(
            "l2cap_connect_cfm",
            [{"chain": kept}],
            path=str(tmp_path / "rejected.json"),
            data_root=DATA_ROOT,
        )
    with pytest.raises(ValueError, match="more than once"):
        write_refine_result(
            "l2cap_connect_cfm",
            kept + kept,
            chain_path=str(chain_path),
            data_root=DATA_ROOT,
        )
    with pytest.raises(ValueError, match="must not recommend an integer"):
        write_refine_result(
            "l2cap_connect_cfm",
            [{
                "call": "syz_emit_vhci",
                "refinements": [{
                    "path": "data.HCI_EVENT_PKT.hdr.hci_ev_conn_complete.payload.status",
                    "kind": "scalar",
                    "type": "int8",
                    "keep": ["0"],
                }],
            }],
            chain_path=str(chain_path),
            data_root=DATA_ROOT,
        )
    with pytest.raises(ValueError, match="unknown choices"):
        write_refine_result(
            "l2cap_connect_cfm",
            [{
                "call": "syz_emit_vhci",
                "refinements": [{
                    "path": "data",
                    "kind": "union",
                    "type": "vhci_pkt",
                    "keep": ["PKT_FAKE"],
                }],
            }],
            chain_path=str(chain_path),
            data_root=DATA_ROOT,
        )
