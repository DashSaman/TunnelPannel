"""Peer-scoped rules owned by each pair, never global UFW allow entries."""
import hashlib
import ipaddress
import re
import shlex


def active(remote):
    if not hasattr(remote, '_tp_firewall_active'):
        result = remote.run("if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; "
                            "then printf yes; fi", root=True, check=False)
        remote._tp_firewall_active = result['stdout'].strip() == 'yes'
    return remote._tp_firewall_active


def _allow(remote, peer, arguments):
    journal = getattr(remote, 'journal', None)
    if journal is None or not active(remote):
        return
    peer = ipaddress.ip_address(peer)
    tool = 'ip6tables' if peer.version == 6 else 'iptables'
    suffix = hashlib.sha256((str(peer) + repr(arguments)).encode()).hexdigest()[:12]
    marker = 'tp-' + journal.marker + '-' + suffix
    name = 'tp-firewall-' + journal.marker + '-' + suffix
    issued = getattr(remote, '_tp_firewall_issued', set())
    if name in issued:
        return
    if remote.run('test -e /etc/systemd/system/' + name + '.service', root=True, check=False)['code'] == 0:
        raise RuntimeError('owned firewall service name already exists')
    rule = ' '.join(shlex.quote(value) for value in [*arguments, '-m', 'comment', '--comment', marker, '-j', 'ACCEPT'])
    start = f'{tool} -w 5 -C INPUT {rule} 2>/dev/null || {tool} -w 5 -I INPUT 1 {rule}'
    stop = f'{tool} -w 5 -D INPUT {rule} 2>/dev/null || true'
    # Persist before mutation; explicit deletion also covers interrupted ExecStop.
    journal.record('cleanup_command', stop)
    journal.record('firewall_rule', tool + '|' + marker)
    journal.record('service', name)
    from plan_executor.executor import create_unit
    create_unit(remote, name, start, stop)
    issued.add(name)
    remote._tp_firewall_issued = issued


def allow_port(remote, port, protocol, peer=None):
    if protocol not in {'tcp', 'udp'} or not 1 <= int(port) <= 65535:
        raise ValueError('invalid owned transport port')
    peer = str(ipaddress.ip_address(peer or remote.firewall_peer))
    _allow(remote, peer, ['-p', protocol, '-s', peer, '--dport', str(int(port))])


def allow_protocol(remote, peer, protocol):
    if int(protocol) not in {4, 41, 47}:
        raise ValueError('invalid owned kernel transport')
    peer = str(ipaddress.ip_address(peer))
    _allow(remote, peer, ['-p', str(int(protocol)), '-s', peer])


def allow_interface(remote, interface, peer):
    if not re.fullmatch('[A-Za-z0-9_.-]{1,15}', interface):
        raise ValueError('invalid owned tunnel interface')
    peer = str(ipaddress.ip_address(peer))
    _allow(remote, peer, ['-i', interface, '-s', peer])
