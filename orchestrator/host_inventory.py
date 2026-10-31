"""Read-only, secret-free Linux coexistence inspection; runnable on remote Python.

No daemon configuration, arguments, environment, WireGuard keys or XFRM state
are read. A snapshot cannot reserve resources against independent controllers.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

TUNNEL_KINDS = {'wireguard','tun','ipip','sit','gre','gretap','ip6gre','ip6gretap',
                'ip6tnl','vti','vti6','xfrm','vxlan','geneve','erspan','ip6erspan',
                'gtp','bareudp','l2tpeth'}
IPSEC_METHODS = {'IKEV2_IPSEC','L2TP_IPSEC','VTI','VTI6'}
RESERVATIONS = '/etc/tunnelpannel/reserved-ports.json'


def command(args):
    # Fixed argv only. Never return raw stderr (it can contain private details).
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode or len(result.stdout) > 2_000_000:
        raise RuntimeError('inspection command failed or exceeded its output limit')
    return result.stdout


def parse_listeners(raw):
    rows = []
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 5 or parts[0] not in {'tcp','udp'}:
            raise ValueError('unrecognized socket listing')
        address, separator, port = parts[4].rpartition(':')
        if not separator or not port.isdigit() or not 0 < int(port) <= 65535:
            raise ValueError('unrecognized socket address')
        process = re.search(r'\(\("([^"\n]+)"', line)
        rows.append({'proto':parts[0].upper(),'addr':address[:128],'port':int(port),
                     'proc':process.group(1)[:64] if process else '', 'source':'socket'})
    return rows


def container_ports(bindings):
    rows = []
    if not isinstance(bindings, dict):
        raise ValueError('unrecognized container port mapping')
    for target, values in bindings.items():
        proto = target.rpartition('/')[2].upper()
        if proto not in {'TCP','UDP'}:
            continue
        for value in values or []:
            port = int(value['HostPort'])
            if not 0 < port <= 65535:
                raise ValueError('invalid published port')
            rows.append({'proto':proto,'addr':str(value.get('HostIp',''))[:128],
                         'port':port,'proc':'container','source':'container'})
    return rows


def validate_reservations(value):
    if not isinstance(value,dict) or set(value)-{'tcp','udp'}:
        raise ValueError('use tcp/udp lists of ports or inclusive [first,last] ranges')
    result = {}
    for proto, ranges in value.items():
        if not isinstance(ranges,list) or len(ranges) > 1024:
            raise ValueError('invalid reserved port list')
        result[proto.upper()] = []
        for entry in ranges:
            pair = [entry,entry] if type(entry) is int else entry
            if (not isinstance(pair,list) or len(pair) != 2 or
                any(type(port) is not int for port in pair) or not 1 <= pair[0] <= pair[1] <= 65535):
                raise ValueError('invalid reserved port range')
            result[proto.upper()].append(pair)
    return result


def tunnel_links(links):
    return [{'name':str(row.get('ifname',''))[:64], 'kind':row['linkinfo']['info_kind']}
            for row in links if row.get('linkinfo',{}).get('info_kind') in TUNNEL_KINDS]


def policy_count(raw):
    count = sum(line.startswith('src ') for line in raw.splitlines())
    if raw.strip() and not count:
        raise ValueError('unrecognized XFRM policy listing')
    return count


def collect(ports_only=False):
    deadline = time.monotonic() + 60
    report = {'schema':1,'observed_at':time.time(),'complete':False,'errors':[],
              'listeners':[], 'reserved_ranges':{}, 'containers':[],
              'tunnels':[], 'services':[], 'processes':[]}
    def read(label, args, decode=lambda raw:raw):
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError('inspection time budget exhausted')
            return decode(command(args))
        except Exception:
            report['errors'].append(label)
            return None
    listeners = read('sockets', ['ss','-tulnpH'], parse_listeners)
    report['listeners'] = listeners or []
    path = Path(RESERVATIONS)
    try:
        if path.is_symlink():
            raise ValueError('reservation file must be a regular file')
        if path.exists():
            if path.stat().st_size > 100_000:
                raise ValueError('reservation file too large')
            report['reserved_ranges'] = validate_reservations(json.loads(path.read_text()))
    except Exception:
        report['errors'].append('reserved_ports')
    for engine in ('docker','podman'):
        if not shutil.which(engine):
            continue
        ids = read(engine+'_list', [engine,'ps','--format','{{.ID}}'])
        if ids is None:
            continue
        ids = ids.split()
        if len(ids) > 128 or any(not re.fullmatch('[0-9a-f]{6,64}',v) for v in ids):
            report['errors'].append(engine+'_inventory_limit')
            continue
        for identity in ids:
            bindings = read(engine+'_ports', [engine,'inspect','--format',
                             '{{json .NetworkSettings.Ports}}',identity], json.loads)
            try:
                if bindings is not None:
                    ports = container_ports(bindings)
                    report['listeners'].extend(ports)
                    report['containers'].append({'engine':engine,'id':identity[:12],
                                                  'published_ports':len(ports)})
            except Exception:
                report['errors'].append(engine+'_port_format')
    if not ports_only:
        links = read('links', ['ip','-j','-d','link','show'], json.loads)
        report['tunnels'] = tunnel_links(links or [])
        # Read addresses and all routing tables for visibility, not route changes.
        report['networks'] = {}
        for family in ('-4','-6'):
            for kind, args in [('addresses',['address','show']),
                               ('routes',['route','show','table','all']),('rules',['rule','show'])]:
                rows = read(family+'_'+kind, ['ip','-j',family,*args], json.loads)
                report['networks'][family+'_'+kind] = rows or []
        policies = read('xfrm_policies', ['ip','xfrm','policy','list'], policy_count)
        report['xfrm_policy_count'] = policies or 0
        units = read('services',['systemctl','list-units','--type=service','--state=running',
                                  '--no-legend','--no-pager','--plain'])
        report['services'] = [row.split()[0][:160] for row in (units or '').splitlines() if row.split()]
        processes = read('process_names',['ps','-eo','comm='])
        # Names only; no command line, arguments, environment or key material.
        report['processes'] = sorted(set((processes or '').split()))
        try:
            report['ip_forward'] = Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
            memory = dict((line.split(':')[0],int(line.split()[1])*1024)
                          for line in Path('/proc/meminfo').read_text().splitlines()
                          if line.split()[1].isdigit())
            report['memory'] = {key:memory[key] for key in ('MemTotal','MemAvailable','SwapTotal','SwapFree')}
        except Exception:
            report['errors'].append('host_resources')
    report['complete'] = not report['errors']
    return report


def scan(remote, ports_only=False):
    import shlex
    # Self-contained standard library collector; does not require a remote install.
    source = Path(__file__).read_text(encoding='utf-8')
    result = remote.run('python3 -c '+shlex.quote(source)+(' --ports-only' if ports_only else ''),
                        root=True, timeout=180)
    report = json.loads(result['stdout'])
    if not isinstance(report,dict) or report.get('schema') != 1:
        raise RuntimeError('unsupported host inventory')
    return report


def require_safe(report, method):
    if not report.get('complete'):
        raise RuntimeError('coexistence inspection incomplete; verify host tools and access')
    if method == 'L2TP_IPSEC' and any(row['proto']=='UDP' and row['port']==1701
                                     for row in report.get('listeners',[])):
        raise RuntimeError('coexistence conflict: UDP 1701 already in use')
    if method in IPSEC_METHODS:
        busy = report.get('xfrm_policy_count',0) or any(
            token in unit.lower() for unit in report.get('services',[])
            for token in ('strongswan','ipsec','libreswan')) or any(
            name.lower() in {'charon','charon-systemd','pluto','starter'}
            for name in report.get('processes',[])) or any(
            row['proto']=='UDP' and row['port'] in {500,4500} for row in report.get('listeners',[]))
        busy = busy or any(lo <= port <= hi for port in (500,4500)
                           for lo,hi in report.get('reserved_ranges',{}).get('UDP',[]))
        if busy:
            raise RuntimeError('coexistence conflict: existing IPsec daemon, policy or fixed port; preserved')
    # SIT and WG terminate on the host; only FULL adds a forwarded namespace origin.
    # Keep unknown future stacks fail-closed until their forwarding needs are known.
    if (method.startswith('HAJSAMAN_') and method not in {'HAJSAMAN_SIT','HAJSAMAN_WG'}
            and report.get('ip_forward') != '1'):
        raise RuntimeError('coexistence conflict: method would change global IPv4 forwarding')


if __name__ == '__main__':
    print(json.dumps(collect(ports_only='--ports-only' in sys.argv)))
