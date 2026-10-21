#!/usr/bin/env python3
"""Install an isolated loopback web gateway; no API, database or job worker."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.engine.mtf import portmgr
from orchestrator.host_inventory import collect, require_safe

CONF = Path('/etc/tunnelpannel-web-gateway')
DATA = Path('/var/lib/tunnelpannel-web-gateway')
USER = 'tp-web-gateway'
UNITS = ('tunnelpannel-web-transport.service', 'tunnelpannel-web-http.service')


def settings(host, user, ssh_port, api_port, http_port, forward_port):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', host):
            raise ValueError('invalid controller host') from None
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise ValueError('invalid SSH user')
    if any(type(p) is not int or not 1 <= p <= 65535 for p in (ssh_port, api_port)):
        raise ValueError('invalid upstream port')
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in (http_port, forward_port)):
        raise ValueError('invalid loopback port')
    if http_port == forward_port:
        raise ValueError('loopback ports must differ')
    return dict(host=host, user=user, ssh_port=ssh_port, api_port=api_port,
                http_port=http_port, forward_port=forward_port)


def select_ports(report, http_port=None, forward_port=None):
    require_safe(report, '')
    if http_port is not None and http_port == forward_port:
        raise ValueError('loopback ports must differ')
    selected = []
    for requested in (http_port, forward_port):
        if requested is not None:
            if not 1024 <= requested <= 65535:
                raise ValueError('invalid loopback port')
            occupied = any(r['proto'] == 'TCP' and r['port'] == requested for r in report.get('listeners', []))
            reserved = any(lo <= requested <= hi for lo, hi in report.get('reserved_ranges', {}).get('TCP', []))
            if occupied or reserved or requested in selected or requested in portmgr.NEVER:
                raise RuntimeError('gateway port occupied or reserved; existing services preserved')
            port = requested
        else:
            port = portmgr.free_port({'sides': {'gateway': report}}, 'tcp', ['gateway'], reserved=set(selected))
            if not port:
                raise RuntimeError('no free gateway port')
        selected.append(port)
    return tuple(selected)


def units(config):
    common = f'''User={USER}
Group={USER}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CPUQuota=10%
TasksMax=16
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
'''
    ssh = f'''[Unit]
Description=TunnelPannel website encrypted controller transport
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
{common}MemoryMax=64M
ExecStart=/usr/bin/ssh -NT -o BatchMode=yes -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=3 -o IdentitiesOnly=yes -o UserKnownHostsFile={CONF}/known_hosts -i {CONF}/ssh.key -p {config['ssh_port']} -L 127.0.0.1:{config['forward_port']}:127.0.0.1:{config['api_port']} -l {config['user']} {config['host']}
[Install]
WantedBy=multi-user.target
'''
    http = f'''[Unit]
Description=TunnelPannel isolated website gateway (no application workers)
After=tunnelpannel-web-transport.service
Requires=tunnelpannel-web-transport.service
[Service]
Type=simple
{common}MemoryMax=96M
RuntimeDirectory=tunnelpannel-web-http
ReadWritePaths={DATA}
ExecStartPre=/usr/sbin/nginx -t -c {CONF}/nginx.conf
ExecStart=/usr/sbin/nginx -c {CONF}/nginx.conf -g "daemon off;"
[Install]
WantedBy=multi-user.target
'''
    return dict(zip(UNITS, (ssh, http)))


def nginx_config(config):
    return f'''worker_processes 1;
pid /run/tunnelpannel-web-http/nginx.pid;
error_log stderr warn;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_body_temp_path {DATA}/client;
    proxy_temp_path {DATA}/proxy;
    fastcgi_temp_path {DATA}/fastcgi;
    uwsgi_temp_path {DATA}/uwsgi;
    scgi_temp_path {DATA}/scgi;
    server {{
        listen 127.0.0.1:{config['http_port']};
        server_name _;
        client_max_body_size 1m;
        location / {{
            proxy_pass http://127.0.0.1:{config['forward_port']};
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Connection "";
            proxy_request_buffering off;
            proxy_buffering off;
            proxy_read_timeout 180s;
            add_header Referrer-Policy same-origin always;
        }}
    }}
}}
'''


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=45)


def safe_directory(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise RuntimeError('gateway symlink path refused')
    if path.exists() and not path.is_dir():
        raise RuntimeError('gateway non-directory path refused')


def owned_port(port, unit):
    try:
        pid = int(run(['systemctl', 'show', unit, '-p', 'MainPID', '--value']).stdout.strip())
        if pid <= 0:
            return False
        process = Path('/proc')/str(pid)
        if not any(r.endswith('/'+unit) for r in (process/'cgroup').read_text().splitlines()):
            return False
        sockets = {str(p.readlink()) for p in (process/'fd').iterdir()}
        found = set()
        for name in ('tcp', 'tcp6'):
            for line in (Path('/proc/net')/name).read_text().splitlines()[1:]:
                parts = line.split()
                if int(parts[1].rpartition(':')[2], 16) == port and parts[3] == '0A':
                    found.add('socket:['+parts[9]+']')
        return bool(found) and found <= sockets
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return False


def prepare_directories(user):
    for path in (CONF, DATA):
        path.mkdir(mode=0o750, exist_ok=True)
        # The bootstrap uses umask077. mkdir(mode=750) alone becomes700 and
        # prevents the unprivileged SSH/nginx processes reading root-owned config.
        path.chmod(0o750)
    os.chown(CONF, 0, user.pw_gid)
    os.chown(DATA, user.pw_uid, user.pw_gid)
    for directory in ('client', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
        path = DATA/directory
        safe_directory(path)
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
        os.chown(path, user.pw_uid, user.pw_gid)


def install(args):
    import pwd
    if os.geteuid() != 0:
        raise RuntimeError('run as root')
    for binary in ('/usr/bin/ssh', '/usr/sbin/nginx', '/usr/bin/systemctl'):
        if not Path(binary).is_file():
            raise RuntimeError('nginx, openssh-client and systemd must already be installed')
    for path in (CONF, DATA):
        safe_directory(path)
    receipt_path = CONF/'receipt.json'
    old = None
    if receipt_path.exists():
        if receipt_path.is_symlink() or receipt_path.stat().st_uid != 0:
            raise RuntimeError('unsafe gateway receipt')
        old = json.loads(receipt_path.read_text())
        if old.get('product') != 'TunnelPannel-web-gateway':
            raise RuntimeError('foreign gateway receipt')
    elif any(p.exists() and any(p.iterdir()) for p in (CONF, DATA)):
        raise RuntimeError('unowned gateway paths preserved')
    for unit in UNITS:
        unit_path = Path('/etc/systemd/system')/unit
        load = run(['systemctl','show',unit,'-p','LoadState','--value']).stdout.strip()
        if not old and (unit_path.exists() or load != 'not-found'):
            raise RuntimeError('foreign gateway service preserved')
    for key in (args.key_file, args.known_hosts):
        if key.is_symlink() or not key.is_file() or key.stat().st_uid != 0 or key.stat().st_mode & 0o022:
            raise RuntimeError('key and host pins must be root-owned regular files without public write access')
    key_digest = hashlib.sha256(args.key_file.read_bytes()).hexdigest()
    pins_digest = hashlib.sha256(args.known_hosts.read_bytes()).hexdigest()
    report = collect(ports_only=True)
    if old:
        for port, unit in zip((old['config']['forward_port'],old['config']['http_port']), UNITS):
            if owned_port(port, unit):
                report['listeners'] = [r for r in report['listeners'] if not (r['proto']=='TCP' and r['port']==port and r.get('source')!='container')]
        http_port, forward_port = select_ports(report, old['config']['http_port'], old['config']['forward_port'])
    else:
        http_port, forward_port = select_ports(report, args.http_port, args.forward_port)
    config = settings(args.host,args.user,args.ssh_port,args.api_port,http_port,forward_port)
    if old and (old['config'] != config or old['key_sha256'] != key_digest or old['pins_sha256'] != pins_digest):
        raise RuntimeError('existing gateway identity differs; explicit migration required')
    host_lookup = config['host'] if config['ssh_port']==22 else '['+config['host']+']:'+str(config['ssh_port'])
    run(['ssh-keygen','-F',host_lookup,'-f',str(args.known_hosts)])
    run(['ssh-keygen','-y','-f',str(args.key_file)])
    try:
        user = pwd.getpwnam(USER)
        if not old:
            raise RuntimeError('foreign gateway account preserved')
    except KeyError:
        run(['useradd','--system','--user-group','--home-dir',str(DATA),'--shell','/usr/sbin/nologin',USER])
        user = pwd.getpwnam(USER)
    prepare_directories(user)
    files = {str(CONF/'nginx.conf'):nginx_config(config),
             **{str(Path('/etc/systemd/system')/name):body for name,body in units(config).items()}}
    if old:
        for path, digest in old['files'].items():
            if Path(path).is_symlink() or hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                raise RuntimeError('gateway config or unit changed; preserve operator edits')
    # Receipt before publication makes a failed start recoverable without claiming success.
    receipt={'product':'TunnelPannel-web-gateway','status':'PREPARED','config':config,
             'key_sha256':key_digest,'pins_sha256':pins_digest,'files':
             {p:hashlib.sha256(body.encode()).hexdigest() for p,body in files.items()},
             'application_workers':False,'database_on_gateway':False}
    receipt_path.write_text(json.dumps(receipt,indent=2))
    receipt_path.chmod(0o600)
    for source, dest in ((args.key_file,CONF/'ssh.key'),(args.known_hosts,CONF/'known_hosts')):
        if source.resolve() != dest.resolve():
            shutil.copyfile(source,dest)
        dest.chmod(0o640)
        os.chown(dest,0,user.pw_gid)
    for path,body in files.items():
        Path(path).write_text(body)
        Path(path).chmod(0o640 if path.endswith('nginx.conf') else 0o644)
        os.chown(path,0,user.pw_gid if path.endswith('nginx.conf') else 0)
    # The system nginx unit and all website configuration stay unchanged.
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable',*UNITS])
    for unit in UNITS:
        run(['systemctl','restart',unit])
    for _ in range(30):
        if owned_port(forward_port,UNITS[0]) and owned_port(http_port,UNITS[1]):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{http_port}/health',timeout=3) as response:
                    if json.load(response).get('ok'):
                        receipt.update(status='PASS',health=True)
                        receipt_path.write_text(json.dumps(receipt,indent=2))
                        return receipt
            except (OSError, ValueError):
                pass
        time.sleep(1)
    raise RuntimeError('gateway health failed; only gateway units may require inspection')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True)
    parser.add_argument('--user',required=True)
    parser.add_argument('--ssh-port',type=int,default=22)
    parser.add_argument('--api-port',type=int,default=8080)
    parser.add_argument('--http-port',type=int)
    parser.add_argument('--forward-port',type=int)
    parser.add_argument('--key-file',type=Path,required=True)
    parser.add_argument('--known-hosts',type=Path,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(install(args)))
    except Exception as error:
        # Do not echo subprocess output, key material, environments or HTTP bodies.
        print('Gateway installation failed: '+type(error).__name__+': '+str(error) if isinstance(error,(ValueError,RuntimeError)) else 'Gateway installation failed: '+type(error).__name__,file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
