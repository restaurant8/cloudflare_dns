from types import SimpleNamespace

from app.request_utils import client_ip_from_request


def request(headers, client_host="127.0.0.1"):
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=client_host))


def test_client_ip_prefers_cloudflare_header():
    value = client_ip_from_request(
        request(
            {
                "cf-connecting-ip": "203.0.113.10",
                "x-forwarded-for": "10.0.0.5, 198.51.100.2",
            }
        )
    )

    assert value == "203.0.113.10"


def test_client_ip_uses_real_ip_before_socket_peer():
    assert client_ip_from_request(request({"x-real-ip": "8.8.8.8"}, "127.0.0.1")) == "8.8.8.8"


def test_client_ip_uses_public_forwarded_ip_when_available():
    assert client_ip_from_request(request({"x-forwarded-for": "10.0.0.5, 8.8.4.4"}, "127.0.0.1")) == "8.8.4.4"


def test_client_ip_falls_back_to_forwarded_or_peer():
    assert client_ip_from_request(request({"x-forwarded-for": "10.0.0.5"}, "127.0.0.1")) == "10.0.0.5"
    assert client_ip_from_request(request({}, "127.0.0.1")) == "127.0.0.1"
