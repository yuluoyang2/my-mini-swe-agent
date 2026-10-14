from pathlib import Path

import pytest

from minisweagent.models.utils.syzlang_trim import grouped_type_refinements, trim_syzlang

DATA_ROOT = Path(__file__).resolve().parents[2] / "data/linux-6.6"
pytestmark = pytest.mark.skipif(
    not (DATA_ROOT / "syzlang/syzlang.index.json").exists(),
    reason="syzlang index is not present",
)


def test_trim_keeps_path_shared_types_global_and_leaves_unused_definitions(tmp_path):
    output = tmp_path / "xfrm_alloc_spi.syzlang"
    result = trim_syzlang(
        DATA_ROOT / "results/xfrm_alloc_spi.refine.json",
        data_root=DATA_ROOT,
        output=output,
    )
    xfrm = (output / "linux/socket_netlink_xfrm.txt").read_text()
    key = (output / "linux/socket_key.txt").read_text()
    changed = (output / "CHANGED.txt").read_text()
    assert "\tallocspi\tnetlink_msg[XFRM_MSG_ALLOCSPI" in xfrm
    assert "\tnewsa\t\tnetlink_msg[XFRM_MSG_NEWSA" not in xfrm
    assert (
        "xfrm_proto = IPPROTO_AH, IPPROTO_ESP, IPPROTO_COMP, "
        "IPPROTO_DSTOPTS, IPPROTO_ROUTING, IPSEC_PROTO_ANY"
    ) in xfrm
    assert (
        "sadb_satype = SADB_SATYPE_UNSPEC, SADB_SATYPE_AH, "
        "SADB_SATYPE_ESP, SADB_X_SATYPE_IPCOMP"
    ) in key
    assert "skipped sendmsg$nl_xfrm:msg.vec.addr.allocspi.payload.info.id.proto" in changed
    assert "removed" not in changed
    assert result["edited_files"] == ["socket_key.txt", "socket_netlink_xfrm.txt"]
    assert {path.name for path in (output / "linux").iterdir()} == {
        "socket_key.txt",
        "socket_netlink_xfrm.txt",
    }


def test_trim_rejects_path_specific_keep_conflicts():
    with pytest.raises(ValueError, match="conflicting refinements for shared flags shared_flags"):
        grouped_type_refinements(
            [
                ("call$one", {"path": "arg.left", "kind": "flags", "type": "shared_flags", "keep": ["A"]}),
                ("call$one", {"path": "arg.right", "kind": "flags", "type": "shared_flags", "keep": ["B"]}),
            ]
        )
