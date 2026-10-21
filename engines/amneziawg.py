"""Pinned official userspace AmneziaWG, with private owned UAPI configuration."""
import ipaddress
import json
from pathlib import Path
import shlex
import uuid

PIN = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
RUNTIME = '/opt/tunnelpannel-engines/amneziawg/' + PIN + '/amneziawg-go'
GO_VERSION = '1.27.2'
GO_DIGESTS = {'x86_64': ('amd64', 'ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5'),
              'aarch64': ('arm64', '94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8')}


def memory_snapshot(remote):
    value = remote.run("python3 - <<'MEMORY'\nimport json,pathlib\nv={r.split(':')[0]:int(r.split()[1])*1024 for r in pathlib.Path('/proc/meminfo').read_text().splitlines() if r.split(':')[0] in {'MemAvailable','SwapFree'}}\nprint(json.dumps(v))\nMEMORY")
    return json.loads(value['stdout'])


def build_budget(memory):
    unit = 1024**2
    available = memory.get('MemAvailable', 0)
    if type(available) is not int or available < 256*unit:
        raise RuntimeError('insufficient available memory for isolated AmneziaWG build')
    return min(512*unit, available - 128*unit), min(512*unit, memory.get('SwapFree', 0)//2)


def artifact(remote):
    script = ("import hashlib,json,pathlib\np=pathlib.Path(" + repr(RUNTIME) + ")\n"
              "m=json.loads(p.with_name('build.json').read_text())\nassert m['source']==" + repr(PIN) +
              "\nassert hashlib.sha256(p.read_bytes()).hexdigest()==m['sha256']\nprint(json.dumps(m))")
    result = remote.run("python3 - <<'VERIFY'\n" + script + '\nVERIFY', root=True, check=False)
    return None if result['code'] else json.loads(result['stdout'])


def copy_artifact(source, target):
    """Pinned SSH transfer of verified public engine bytes; no credentials/config."""
    meta = artifact(source)
    if not meta:
        raise RuntimeError('source AmneziaWG artifact is not verified')
    if source.run('uname -m')['stdout'].strip() != target.run('uname -m')['stdout'].strip():
        raise RuntimeError('cannot copy AmneziaWG across architectures')
    temporary = '/tmp/.tp-awg-' + uuid.uuid4().hex
    try:
        with source.client.open_sftp() as reader, target.client.open_sftp() as writer:
            reader.get_channel().settimeout(60); writer.get_channel().settimeout(60)
            with reader.open(RUNTIME, 'rb') as src, writer.open(temporary, 'wx') as dst:
                writer.chmod(temporary, 0o600)
                while chunk := src.read(1024*1024):
                    dst.write(chunk)
        code = r'''import hashlib,json,os,pathlib,shutil,stat,tempfile
source=pathlib.Path(__TEMP__);target=pathlib.Path(__TARGET__);meta=__META__
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as data:
 info=os.fstat(data.fileno())
 if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077:raise RuntimeError('unsafe engine transfer')
 if hashlib.file_digest(data,'sha256').hexdigest()!=meta['sha256']:raise RuntimeError('engine transfer digest mismatch')
 data.seek(0);target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
 out,name=tempfile.mkstemp(dir=target.parent)
 with os.fdopen(out,'wb') as file:shutil.copyfileobj(data,file);file.flush();os.fsync(file.fileno())
 os.chmod(name,0o755);os.replace(name,target)
target.with_name('build.json').write_text(json.dumps(meta));target.with_name('build.json').chmod(0o600)
'''.replace('__TEMP__', repr(temporary)).replace('__TARGET__', repr(RUNTIME)).replace('__META__', repr(meta))
        target.run("python3 - <<'TRANSFER'\n" + code + '\nTRANSFER', root=True)
        if artifact(target) != meta:
            raise RuntimeError('installed engine transfer verification failed')
    finally:
        target.run('rm -f -- ' + shlex.quote(temporary), check=False)


def prepare_pair(access):
    """Build once per architecture on the best available execution node."""
    from orchestrator.remote_nodes import NodeRemote
    remotes = []
    try:
        for endpoint, credentials in access:
            remotes.append(NodeRemote(endpoint, credentials).connect())
        groups = {}
        for remote in remotes:
            arch = remote.run('uname -m')['stdout'].strip()
            groups.setdefault(arch, []).append(remote)
        for cohort in groups.values():
            source = next((remote for remote in cohort if artifact(remote)), None)
            if source is None:
                resources = [(remote, memory_snapshot(remote)) for remote in cohort]
                source, _ = max(resources, key=lambda item: item[1].get('MemAvailable', 0) + min(item[1].get('SwapFree', 0), 512*1024**2))
                install(source)
            for remote in cohort:
                if remote is not source and not artifact(remote):
                    copy_artifact(source, remote)
    finally:
        for remote in remotes:
            remote.close()


def uapi_config(private, public, port, host, peer_port, peer_ip):
    ip = ipaddress.ip_address(peer_ip)
    host = str(ipaddress.ip_address(host))
    authority = '[' + host + ']' if ':' in host else host
    return (f'private_key={private}\nlisten_port={port}\njc=4\njmin=40\njmax=80\n'
            's1=16\ns2=32\ns3=16\ns4=16\nh1=1001\nh2=1002\nh3=1003\nh4=1004\n'
            f'replace_peers=true\npublic_key={public}\nreplace_allowed_ips=true\n'
            f'allowed_ip={ip}/{32 if ip.version == 4 else 128}\nendpoint={authority}:{peer_port}\npersistent_keepalive_interval=15\n')


def install(remote):
    from plan_executor import executor as bodies
    if artifact(remote):
        return RUNTIME
    memory, swap = build_budget(memory_snapshot(remote))
    root = '/var/cache/tunnelpannel-build/amneziawg/' + PIN
    bootstrap = r'''import hashlib,io,os,pathlib,platform,tarfile,urllib.request
arch,expected=__DIGESTS__[platform.machine()]
root=pathlib.Path('/opt/tunnelpannel-toolchains/go__GO__')
if not (root/'go/bin/go').is_file():
 data=urllib.request.urlopen('https://go.dev/dl/go__GO__.linux-'+arch+'.tar.gz',timeout=120).read()
 if hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('Go toolchain digest mismatch')
 root.mkdir(mode=0o755,parents=True,exist_ok=True)
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
  for member in archive.getmembers():
   if member.name.startswith('/') or '..' in pathlib.PurePosixPath(member.name).parts or member.issym() or member.islnk():raise RuntimeError('unsafe Go archive')
  archive.extractall(root)
'''.replace('__DIGESTS__', repr(GO_DIGESTS)).replace('__GO__', GO_VERSION)
    remote.run("python3 - <<'TOOLCHAIN'\n" + bootstrap + '\nTOOLCHAIN', root=True, timeout=180)
    # Do not rely on a distribution's Go version or replace its binaries.
    remote.run('command -v git >/dev/null && command -v runuser >/dev/null && command -v useradd >/dev/null', root=True)
    script = f'''set -Eeuo pipefail
id tp-awgbuild >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin tp-awgbuild
chmod 0755 /var/cache/tunnelpannel-build /var/cache/tunnelpannel-build/amneziawg {root}
install -d -m 0700 -o tp-awgbuild -g tp-awgbuild {root}/work
runuser -u tp-awgbuild -- bash -s <<'COMPILE'
set -Eeuo pipefail
cd {root}/work
export HOME={root}/work GOPATH={root}/work/gopath GOCACHE={root}/work/cache GOTOOLCHAIN=local GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org GOMAXPROCS=1 GOMEMLIMIT={max(64,memory*3//5//1024**2)}MiB
if [ ! -d source/.git ]; then git init -q source; git -C source remote add origin https://github.com/amnezia-vpn/amneziawg-go.git; fi
git -C source fetch --depth 1 origin {PIN}
git -C source checkout --detach FETCH_HEAD
test "$(git -C source rev-parse HEAD)" = {PIN}
cd source
nice -n 10 /opt/tunnelpannel-toolchains/go{GO_VERSION}/go/bin/go build -p 1 -trimpath -o ../amneziawg-go .
COMPILE
install -d -m 0755 {Path(RUNTIME).parent.as_posix()}
install -m 0755 {root}/work/amneziawg-go {RUNTIME}
python3 - <<'META'
import hashlib,json,pathlib
p=pathlib.Path({RUNTIME!r});p.with_name('build.json').write_text(json.dumps({{'source':{PIN!r},'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}}));p.with_name('build.json').chmod(0o600)
META
'''
    bodies.write_remote_text(remote, root + '/build.sh', script, '0700')
    remote.run(f'systemd-run --quiet --wait --pipe --collect --unit=tp-awg-build-{PIN[:12]} '
               f'--property=MemoryMax={memory} --property=MemorySwapMax={swap} --property=CPUQuota=100% '
               f'--property=TasksMax=128 timeout -s TERM 1700 bash {root}/build.sh > {root}/build.log 2>&1 || '
               f'{{ tail -n 25 {root}/build.log; exit 1; }}', root=True, timeout=1800)
    return RUNTIME


def deploy(run, item, config, a, b):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from orchestrator.owned_firewall import allow_interface, allow_port
    from plan_executor import executor as bodies
    address = bodies.parse_addressing(config)
    interface = bodies.short_name('naw', run['id'], item['id'])
    name = f"tp-awg-{run['id']}-{item['id']}"
    directory = '/etc/netauto/amneziawg/' + name
    ports = [bodies.free_port(remote, 'udp', 22000) for remote in (a, b)]
    keys = [X25519PrivateKey.generate() for _ in range(2)]
    for index, remote in enumerate((a, b)):
        side, peer = ('a', 'b') if index == 0 else ('b', 'a')
        install(remote)
        bodies.install_iproute(remote)
        bodies.ensure_source(remote, address['source_' + side])
        remote.journal.claim_interface(interface)
        document = uapi_config(keys[index].private_bytes_raw().hex(), keys[1-index].public_key().public_bytes_raw().hex(),
                               ports[index], str(address['source_' + peer]), ports[1-index], str(address['address_' + peer].ip))
        bodies.write_remote_text(remote, directory + '/config.uapi', document, '0600')
        apply = """import pathlib,socket,sys,time
base=pathlib.Path(sys.argv[1]); interface=sys.argv[2]
path='/var/run/amneziawg/'+interface+'.sock'
for _ in range(100):
 if pathlib.Path(path).exists():break
 time.sleep(.1)
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
 sock.settimeout(10);sock.connect(path);sock.sendall(b'set=1\\n'+(base/'config.uapi').read_bytes()+b'\\n')
 data=b''
 while not data.endswith(b'\\n\\n'):
  chunk=sock.recv(4096)
  if not chunk:raise RuntimeError('AmneziaWG closed configuration socket')
  data+=chunk
 if data!=b'errno=0\\n\\n':raise RuntimeError('AmneziaWG rejected owned UAPI configuration')
"""
        bodies.write_remote_text(remote, directory + '/apply.py', apply, '0600')
        command = (f'set -Eeuo pipefail; {RUNTIME} -f {interface} & child=$!; trap \'kill "$child" 2>/dev/null || true\' EXIT; '
                   f'python3 {directory}/apply.py {directory} {interface}; '
                   f'ip address replace {address["address_" + side]} dev {interface}; '
                   f'ip link set {interface} mtu 1380 up; wait "$child"')
        allow_port(remote, ports[index], 'udp', peer=str(address['source_' + peer]))
        allow_interface(remote, interface, str(address['address_' + peer].ip))
        bodies.persistent_service(remote, name, command)
    a.run(bodies.ping_command(address['address_b'].ip), root=True, timeout=30)
    b.run(bodies.ping_command(address['address_a'].ip), root=True, timeout=30)
    return {'method': 'AMNEZIAWG', 'interface_name': interface, 'interfaces_a': [interface], 'interfaces_b': [interface],
            'tunnel_ip_a': str(address['address_a']), 'tunnel_ip_b': str(address['address_b']),
            'services_a': [name], 'services_b': [name], 'files_a': [directory], 'files_b': [directory],
            'source_commit': PIN, 'transport': 'official AmneziaWG userspace; encrypted UDP with junk/padding/custom headers'}
