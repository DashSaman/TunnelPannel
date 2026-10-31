"""Deployment guard: a management-only installation never executes on itself."""
import ipaddress
import os
import socket


def _address(value):
    address = ipaddress.ip_address(value)
    return getattr(address, 'ipv4_mapped', None) or address


def configuration():
    mode = os.environ.get('TP_CONTROL_PLANE_ONLY', '0')
    if mode not in {'0', '1'}:
        raise ValueError('invalid management-only installation mode')
    if mode == '0':
        return None
    excluded = os.environ.get('TP_CONTROLLER_EXCLUDED_HOSTS', '')
    if not excluded.strip():
        raise ValueError('management-only mode requires controller address exclusions')
    return {_address(item.strip()) for item in
            (excluded+','+os.environ.get('TP_RETIRED_NODE_HOSTS', '')).split(',') if item.strip()}


def remote_target(host, port):
    excluded = configuration()
    if excluded is None:
        return host
    try:
        addresses = [_address(host)]
    except ValueError:
        addresses = list(dict.fromkeys(_address(row[4][0]) for row in
            socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(address in excluded or address.is_loopback
            or address.is_unspecified or address.is_link_local or address.is_multicast
            for address in addresses):
        raise ValueError('management or retired hosts cannot be execution nodes')
    # Connect to this already validated numeric address. A second DNS lookup
    # must not swap the target to the controller after the policy check.
    return str(addresses[0])
