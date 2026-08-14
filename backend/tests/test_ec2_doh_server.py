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
    server.activate_snapshot(snapshot())
    allowed = server.json_response("snejsat.baidu.com", "A")
    refused = server.json_response("example.com", "A")

    assert allowed["Status"] == 0
    assert allowed["Answer"][0]["data"] == "203.0.113.10"
    assert refused["Status"] == 5
    assert "Answer" not in refused


def test_wire_allowlist_sets_refused_rcode_for_other_names():
    server.activate_snapshot(snapshot())
    allowed = server.dns_wire_response(dns_query("snejsat.baidu.com"))
    refused = server.dns_wire_response(dns_query("example.com"))

    assert struct.unpack("!H", allowed[2:4])[0] & 0xF == 0
    assert struct.unpack("!H", refused[2:4])[0] & 0xF == 5
    assert struct.unpack("!H", allowed[6:8])[0] == 1
    assert struct.unpack("!H", refused[6:8])[0] == 0


def test_wire_response_is_authoritative_and_copies_rd_without_claiming_recursion():
    server.activate_snapshot(snapshot())
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
    server.activate_snapshot(data)

    result = server.json_response("snejsat.baidu.com", "A")

    assert [answer["data"] for answer in result["Answer"]] == ["203.0.113.10", "203.0.113.20"]


def test_resolver_backed_allowlist_forwards_wire_query(monkeypatch):
    data = {
        "version": 2,
        "revision": "route53",
        "records": [
            {
                "name": "snejsat.baidu.com",
                "type": "A",
                "value": "0.0.0.0",
                "ttl": 60,
                "source": "vpc_resolver",
            }
        ],
    }
    server.validate_snapshot(data)
    server.activate_snapshot(data)
    forwarded = b"route53-response"
    monkeypatch.setattr(server, "resolve_vpc_dns", lambda message: forwarded)

    assert server.dns_wire_response(dns_query("snejsat.baidu.com")) == forwarded
    refused = server.dns_wire_response(dns_query("example.com"))
    assert struct.unpack("!H", refused[2:4])[0] & 0xF == 5


def test_v1_rejects_resolver_marker_while_v2_accepts_it():
    data = {
        "version": 1,
        "revision": "route53",
        "records": [
            {
                "name": "snejsat.baidu.com",
                "type": "A",
                "value": "0.0.0.0",
                "ttl": 60,
                "source": "vpc_resolver",
            }
        ],
    }
    try:
        server.validate_snapshot(data)
    except ValueError as exc:
        assert "version 2" in str(exc)
    else:
        raise AssertionError("version 1 must never accept a VPC Resolver marker")

    data["version"] = 2
    server.validate_snapshot(data)


def test_vpc_udp_socket_is_connected_and_response_id_is_checked(monkeypatch):
    query = dns_query("snejsat.baidu.com")
    response = bytearray(query)
    response[2:4] = struct.pack("!H", 0x8180)

    class FakeSocket:
        def __init__(self):
            self.connected = None
            self.sent = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def connect(self, address):
            self.connected = address

        def send(self, message):
            self.sent = message

        def recv(self, _size):
            assert self.connected == (server.VPC_RESOLVER, 53)
            assert self.sent == query
            return bytes(response)

    fake = FakeSocket()
    monkeypatch.setattr(server.socket, "socket", lambda *_args, **_kwargs: fake)
    assert server.resolve_vpc_dns(query) == bytes(response)

    forged = bytes([query[0] ^ 1]) + query[1:]
    forged = forged[:2] + struct.pack("!H", 0x8180) + forged[4:]
    try:
        server.validate_vpc_dns_response(query, forged)
    except ValueError as exc:
        assert "transaction ID" in str(exc)
    else:
        raise AssertionError("mismatched transaction IDs must be rejected")


def test_record_lookup_uses_prebuilt_normalized_index(monkeypatch):
    data = {
        "version": 1,
        "revision": "many",
        "records": [
            {"name": f"host-{index}.example.com", "type": "A", "value": "203.0.113.10", "ttl": 60}
            for index in range(500)
        ],
    }
    server.validate_snapshot(data)
    server.activate_snapshot(data)
    original = server.normalize_name
    calls = []

    def counted(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(server, "normalize_name", counted)
    allowed, records, resolver_backed = server.current_records("host-499.example.com", "A")

    assert allowed is True
    assert records[0]["value"] == "203.0.113.10"
    assert resolver_backed is False
    assert len(calls) == 1
