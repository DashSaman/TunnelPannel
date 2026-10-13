import socket
import sys
import threading
import time

import pytest

from deploy.engine import mtf_userspace as harness

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="legacy harness requires Linux")


def test_udp_probe_cannot_supply_its_own_fake_echo_service():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    ok, _ = harness.udp_echo_test(port, "no-service-must-fail")
    assert not ok


def test_udp_probe_never_binds_the_tunnel_endpoint_it_is_testing():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    worker = threading.Thread(target=lambda: harness.udp_echo_test(port))
    worker.start()
    endpoint_was_bound = False
    for _ in range(40):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attempt:
            try:
                attempt.bind(("127.0.0.1", port))
            except OSError:
                endpoint_was_bound = True
        time.sleep(0.025)
    worker.join(timeout=12)
    assert not endpoint_was_bound, "a probe must not create the endpoint it claims to verify"


def test_udp_probe_requires_a_round_trip_through_the_forwarder():
    origin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    origin.bind(("127.0.0.1", 0)); front.bind(("127.0.0.1", 0))
    origin.settimeout(10); front.settimeout(10)
    def echo():
        try:
            data, peer = origin.recvfrom(1024)
            origin.sendto(data, peer)
        finally:
            origin.close()
    def forward():
        try:
            data, peer = front.recvfrom(1024)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(5)
                upstream.sendto(data, origin_address)
                response, _ = upstream.recvfrom(1024)
            front.sendto(response, peer)
        finally:
            front.close()
    origin_address = origin.getsockname()
    port = front.getsockname()[1]
    a = threading.Thread(target=echo); b = threading.Thread(target=forward)
    a.start(); b.start()
    ok, _ = harness.udp_echo_test(port, "must-cross-two-sockets")
    a.join(timeout=12); b.join(timeout=12)
    assert ok
