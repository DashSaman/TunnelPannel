"""Bounded measurements from real traffic; never substitute synthetic speed."""
import hashlib
import ipaddress
import json
import shlex


def resource_snapshot(remote):
    script = """import pathlib,json
cpu=list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
mem={line.split(':')[0]:int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines()}
print(json.dumps({'total':sum(cpu),'idle':cpu[3]+cpu[4],'ram_mb':(mem['MemTotal']-mem['MemAvailable'])/1024}))
"""
    return json.loads(remote.run('python3 -c ' + shlex.quote(script))['stdout'])


def resource_usage(before, after):
    elapsed = after['total'] - before['total']
    if elapsed <= 0:
        raise RuntimeError('resource sample interval did not advance')
    return {'cpu_pct': max(0, min(100, 100 * (1 - (after['idle'] - before['idle']) / elapsed))),
            'ram_mb': max(before['ram_mb'], after['ram_mb'])}


def parse_iperf(document):
    if document.get('error'):
        raise RuntimeError('iperf: ' + document['error'])
    received = document.get('end', {}).get('sum_received', {})
    if received.get('bytes', 0) <= 0 or received.get('seconds', 0) <= 0:
        raise RuntimeError('iperf did not report received data')
    return {'verified_bytes': received['bytes'], 'elapsed_s': received['seconds'],
            'throughput_mbps': received['bits_per_second'] / 1_000_000}


def measure_l3(adapter):
    from deploy.engine.mtf.portmgr import _parse_ss, free_port
    from plan_executor import executor as bodies
    a, b = adapter.remotes
    for remote in (a, b):
        bodies.install_packages(remote, ['iperf3'])
    listeners = _parse_ss(b.run('ss -tulnH')['stdout'])
    # iperf uses the same port for TCP control and UDP data.
    combined = [{**row, 'proto': 'TCP'} for row in listeners]
    port = free_port({'sides': {'throughput': {'listeners': combined}}}, 'tcp', ['throughput'])
    if not port:
        raise RuntimeError('no free iperf control/data port')
    target = str(ipaddress.ip_interface(adapter.artifact['tunnel_ip_b']).ip)
    unit = adapter.tag + '-iperf'
    b.run(f'systemd-run --collect --unit={unit} --property=RuntimeMaxSec=180 '
          f'iperf3 --server --bind {target} --port {port}', root=True)
    bodies.wait_listener(b, 'tcp', port)
    adapter.extra_services.append((b, unit))
    seconds = adapter.profile.throughput_seconds
    samples = []
    for reverse in ('', '--reverse'):
        result = a.run(f'iperf3 --client {target} --port {port} --time {seconds} --json {reverse}',
                       root=True, timeout=adapter.profile.throughput_timeout_s, check=False)
        sample = parse_iperf(json.loads(result['stdout']))
        sample['direction'] = 'b_to_a' if reverse else 'a_to_b'
        samples.append(sample)
    return {'throughput_mbps': min(s['throughput_mbps'] for s in samples),
            'throughput_evidence': {'tool': 'iperf3', 'transport': 'TCP', 'samples': samples}}


def measure_http(adapter):
    remote, command, origin_remote, directory, nonce = adapter.http_flow
    data = nonce.encode() + bytes(1_048_576 - len(nonce))
    digest = hashlib.sha256(data).hexdigest()
    make = ("import pathlib; "
            f"pathlib.Path({directory + '/blob.bin'!r}).write_bytes({nonce.encode()!r}+bytes({1_048_576-len(nonce)}))")
    origin_remote.run('python3 -c ' + shlex.quote(make), root=True)
    arguments = shlex.split(command)
    arguments[-1] = arguments[-1].rstrip('/') + '/blob.bin'
    download = (getattr(adapter, 'download_directory', '/var/lib/tunnelpannel/bench')
                + f'/{adapter.tag}-download')
    adapter.journals[adapter.remotes.index(remote)].record('path', download)
    remote.run('mkdir -p /var/lib/tunnelpannel/bench', root=True)
    arguments += ['-o', download]
    script = f'''import hashlib,json,pathlib,subprocess,time
arguments={arguments!r}
deadline=time.monotonic()+{adapter.profile.throughput_seconds}
started=time.monotonic(); count=0; total=0
while time.monotonic()<deadline:
 p=subprocess.run(arguments,capture_output=True,timeout={adapter.profile.throughput_timeout_s})
 if p.returncode: raise RuntimeError('verified HTTP transfer failed: '+p.stderr.decode(errors='replace')[-400:])
 data=pathlib.Path({download!r}).read_bytes()
 if hashlib.sha256(data).hexdigest()!={digest!r}: raise RuntimeError('remote blob hash mismatch')
 total+=len(data); count+=1
elapsed=time.monotonic()-started
print(json.dumps({{'verified_bytes':total,'elapsed_s':elapsed,'transfers':count,'throughput_mbps':total*8/elapsed/1e6}}))
'''
    receipt = json.loads(remote.run('python3 -c ' + shlex.quote(script), root=True,
                        timeout=adapter.profile.throughput_seconds + adapter.profile.throughput_timeout_s + 10)['stdout'])
    return {'throughput_mbps': receipt['throughput_mbps'],
            'throughput_evidence': {'tool': 'curl', 'integrity': 'SHA256', **receipt}}


def measure_udp(adapter):
    remote, port, nonce = adapter.udp_flow
    script = f'''import socket,time,json,select
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setblocking(False)
started=time.monotonic(); deadline=started+{adapter.profile.throughput_seconds}
pending={{}}; sent=0; received_count=0; total=0; prefix={nonce.encode()!r}+b'|'
def payload(seq): return (('%08x:'%seq).encode()+bytes(1191))
while time.monotonic()<deadline or (pending and time.monotonic()<deadline+1):
 now=time.monotonic()
 while now<deadline and len(pending)<64:
  try: s.sendto(payload(sent),('127.0.0.1',{port}))
  except BlockingIOError: break
  pending[sent]=now; sent+=1
 if select.select([s],[],[],.01)[0]:
  while True:
   try: received,_=s.recvfrom(65535)
   except BlockingIOError: break
   if not received.startswith(prefix): raise RuntimeError('remote datagram nonce mismatch')
   seq=int(received[len(prefix):len(prefix)+8],16)
   if received!=prefix+payload(seq): raise RuntimeError('remote datagram integrity mismatch')
   if seq in pending:
    del pending[seq]; received_count+=1; total+=1200
 for seq,when in list(pending.items()):
  if now-when>1: del pending[seq]
elapsed=time.monotonic()-started
if not received_count: raise RuntimeError('no verified UDP data received')
print(json.dumps({{'verified_bytes':total,'elapsed_s':elapsed,'datagrams':received_count,'sent_datagrams':sent,
 'loss_pct':100*(sent-received_count)/sent,'throughput_mbps':total*8/elapsed/1e6}}))
'''
    receipt = json.loads(remote.run('python3 -c ' + shlex.quote(script), root=True,
                                   timeout=adapter.profile.throughput_seconds + 10)['stdout'])
    return {'throughput_mbps': receipt['throughput_mbps'], 'loss_pct': receipt['loss_pct'],
            'throughput_evidence': {'tool': 'verified UDP echo', 'payload_bytes': 1200,
                                    'window_datagrams': 64, 'receipt_timeout_s': 1, **receipt}}


def measure_tun(adapter):
    """Sustained bidirectional streams through the scoped TUN, not connection churn."""
    from deploy.engine.mtf.portmgr import _parse_ss, free_port
    from plan_executor import executor as bodies
    a,b=adapter.remotes
    for remote in (a,b):
        bodies.install_packages(remote,['iperf3'])
    listeners=_parse_ss(b.run('ss -tulnH')['stdout'])
    port=free_port({'sides':{'throughput':{'listeners':[{**row,'proto':'TCP'} for row in listeners]}}},
                   'tcp',['throughput'])
    if not port:
        raise RuntimeError('no free TUN throughput port')
    host=adapter.access[1][0]['host']
    table,_,interface=adapter.tun_route
    selector=(f"-p tcp -d {host}/32 --dport {port} -m owner --uid-owner {adapter.tun_probe_uid} "
              f"-m comment --comment {adapter.tag}-iperf -j MARK --set-mark {table}")
    adapter.journals[0].record('cleanup_command',
                              'iptables -t mangle -D OUTPUT '+selector+' 2>/dev/null || true')
    a.run('iptables -t mangle -A OUTPUT '+selector,root=True)
    unit=adapter.tag+'-iperf'
    adapter.extra_services.append((b,unit))
    b.run(f'systemd-run --collect --unit={unit} --property=RuntimeMaxSec=300 '
          f'iperf3 --server --bind {host} --port {port}',root=True)
    bodies.wait_listener(b,'tcp',port)
    samples=[]
    for reverse in ('','--reverse'):
        response=a.run(f'runuser -u {shlex.quote(adapter.tun_probe_user)} -- '
                       f'iperf3 --client {host} --port {port} --time {adapter.profile.throughput_seconds} '
                       f'--json {reverse}',root=True,timeout=adapter.profile.throughput_timeout_s,check=False)
        sample=parse_iperf(json.loads(response['stdout']))
        sample['direction']='b_to_a' if reverse else 'a_to_b'
        samples.append(sample)
    return {'throughput_mbps':min(s['throughput_mbps'] for s in samples),
            'throughput_evidence':{'tool':'iperf3','transport':'TCP through TUN',
                                  'interface':interface,'samples':samples}}
