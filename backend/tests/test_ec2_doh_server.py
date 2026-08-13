import importlib.util
import json
import struct
from pathlib import Path


SERVER_PATH = Path(__file__).parents[2] / "deploy" / "ec2-doh" / "doh_server.py"
spec = importlib.util.spec_from_file_location("ec2_doh_server", SERVER_PATH)
server = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(server)


def snapshot():
    return {
        "version": 1,
        "revision": "test",
        "records": [{"name": "snejsat.baidu.com", "type": "A", "value": "203.0.113.10", "ttl": 60}],
    }


def dns_query(name: str, query_type: int = 1) -> bytes:
    return struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0) + server.encode_name(name) + struct.pack("!HH", query_type, 1)


def test_json_allowlist_returns_answer_and_refuses_other_names():
    server._snapshot = snapshot()
    allowed = server.json_response("snejsat.baidu.com", "A")
    refused = server.json_response("example.com", "A")

    assert allowed["Status"] == 0
    assert allowed["Answer"][0]["data"] == "203.0.113.10"
    assert refused["Status"] == 5
    assert "Answer" not in refused


def test_wire_allowlist_sets_refused_rcode_for_other_names():
    server._snapshot = snapshot()
    allowed = server.dns_wire_response(dns_query("snejsat.baidu.com"))
    refused = server.dns_wire_response(dns_query("example.com"))

    assert struct.unpack("!H", allowed[2:4])[0] & 0xF == 0
    assert struct.unpack("!H", refused[2:4])[0] & 0xF == 5
    assert struct.unpack("!H", allowed[6:8])[0] == 1
    assert struct.unpack("!H", refused[6:8])[0] == 0


def test_wire_response_is_authoritative_and_copies_rd_without_claiming_recursion():
    server._snapshot = snapshot()
    response = server.dns_wire_response(dns_query("snejsat.baidu.com"))
    flags = struct.unpack("!H", response[2:4])[0]

    assert flags & 0x8000  # QR
    assert flags & 0x0400  # AA
    assert flags & 0x0100  # copied RD
    assert not flags & 0x0080  # no RA


def test_server_accepts_and_returns_multiple_addresses_for_one_name():
    data = snapshot()
    data["records"].append({"name": "snejsat.baidu.com", "type": "A", "value": "203.0.113.20", "ttl": 60})
    server.validate_snapshot(data)
    server._snapshot = data

    result = server.json_response("snejsat.baidu.com", "A")

    assert [answer["data"] for answer in result["Answer"]] == ["203.0.113.10", "203.0.113.20"]
