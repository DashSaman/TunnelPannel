"""Dependency-free address policy shared by the API and source-node relay."""
import ipaddress


def literal_address(value):
    if not isinstance(value, str) or len(value) > 64 or '%' in value:
        raise ValueError('literal unscoped IP address required')
    address = ipaddress.ip_address(value)
    return getattr(address, 'ipv4_mapped', None) or address


def canonical_address(value, *, target=False):
    address = literal_address(value)
    if address.is_multicast or address.is_link_local or str(address) == '255.255.255.255' or (
            target and address.is_unspecified):
        raise ValueError('unicast target or bind address required')
    return str(address)


def normalize_cidrs(values):
    if not isinstance(values, list) or len(values) > 32:
        raise ValueError('bounded CIDR list required')
    result = []
    for value in values:
        if not isinstance(value, str) or len(value) > 64 or '%' in value:
            raise ValueError('unscoped CIDR required')
        network = ipaddress.ip_network(value, strict=False)
        mapped = getattr(network.network_address, 'ipv4_mapped', None)
        if mapped is not None and network.prefixlen >= 96:
            network = ipaddress.ip_network(f'{mapped}/{network.prefixlen - 96}', strict=False)
        value = str(network)
        if value not in result:
            result.append(value)
    return result


def validate_exposure(bind_host, allow_public, cidrs):
    if type(allow_public) is not bool:
        raise ValueError('explicit public acknowledgement must be a boolean')
    if not literal_address(bind_host).is_loopback and (not allow_public or not cidrs):
        raise ValueError('network listener requires explicit public acknowledgement and source CIDRs')


def client_allowed(peer, cidrs):
    try:
        address = literal_address(peer)
        if not cidrs:
            return address.is_loopback
        return any(address in ipaddress.ip_network(network) for network in cidrs)
    except ValueError:
        return False
