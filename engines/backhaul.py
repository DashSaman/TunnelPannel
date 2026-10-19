"""Official Backhaul TCP reverse forwarding in an owned namespace."""
import json
import secrets

VERSION = 'v0.7.2'
RUNTIME = '/opt/tunnelpannel-engines/backhaul/' + VERSION + '/backhaul'
DIGESTS = {'x86_64': ('amd64', '57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc'),
           'aarch64': ('arm64', '9a424c97ff16fc3f682e8314c418790d2b5bf3136e008edbb6cd402ea00999f6')}


def pair_configs(host, transport, listener, target, token):
    authority = '[' + host + ']' if ':' in host else host
    common = '\ntransport = "tcp"\nskip_optz = true\nsniffer = false\nweb_port = 0\nlog_level = "error"\nnodelay = true\n'
    token_line = 'token = ' + json.dumps(token) + '\n'
    # Keep the engine's transport listener peer-reachable, payload listener local.
    server = '[server]\nbind_addr = ' + json.dumps(('[::]' if ':' in host else '0.0.0.0') + ':' + str(transport)) + common + token_line
    server += 'heartbeat = 5\nchannel_size = 128\nports = [' + json.dumps(f'127.0.0.1:{listener}=127.0.0.1:{target}') + ']\n'
    client = '[client]\nremote_addr = ' + json.dumps(f'{authority}:{transport}') + common + token_line
    client += 'connection_pool = 4\naggressive_pool = false\nretry_interval = 1\ndial_timeout = 8\n'
    return server, client


def install(remote):
    script = r'''import hashlib,io,json,os,pathlib,platform,tarfile,urllib.request
assets=__DIGESTS__
arch,expected=assets[platform.machine()]
root=pathlib.Path('__RUNTIME__').parent
path=root/'backhaul';meta=root/'artifact.json'
if path.is_file() and meta.is_file():
 value=json.loads(meta.read_text())
 if value.get('archive_sha256')==expected and hashlib.sha256(path.read_bytes()).hexdigest()==value.get('binary_sha256'):raise SystemExit(0)
data=urllib.request.urlopen('https://github.com/Musixal/Backhaul/releases/download/__VERSION__/backhaul_linux_'+arch+'.tar.gz',timeout=120).read()
if hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('Backhaul archive digest mismatch')
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
 members=[m for m in archive.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name=='backhaul']
 if len(members)!=1:raise RuntimeError('Backhaul release layout mismatch')
 binary=archive.extractfile(members[0]).read()
root.mkdir(mode=0o755,parents=True,exist_ok=True)
temporary=root/'backhaul.next';temporary.write_bytes(binary);temporary.chmod(0o755);os.replace(temporary,path)
meta.write_text(json.dumps({'archive_sha256':expected,'binary_sha256':hashlib.sha256(binary).hexdigest()}));meta.chmod(0o600)
'''.replace('__DIGESTS__', repr(DIGESTS)).replace('__RUNTIME__', RUNTIME).replace('__VERSION__', VERSION)
    remote.run("python3 - <<'TPBACKHAUL'\n" + script + '\nTPBACKHAUL', root=True, timeout=180)
    return RUNTIME


def deploy(run, item, config, a, b, endpoint_a, endpoint_b):
    from plan_executor import executor as bodies
    for remote in (a, b):
        install(remote)
    name = f"tp-backhaul-{run['id']}-{item['id']}"
    transport = bodies.free_port(a, 'tcp', 22000)
    listener = bodies.free_port(a, 'tcp', 22000)
    server, client = pair_configs(endpoint_a['host'], transport, listener, config['target_port'], secrets.token_urlsafe(32))
    directory = '/etc/netauto/backhaul/' + name
    for remote, text, suffix in [(a, server, '-server'), (b, client, '-client')]:
        bodies.write_remote_text(remote, directory + '/config.toml', text, '0600')
        bodies.persistent_service(remote, name + suffix, f'exec {RUNTIME} -c {directory}/config.toml')
    bodies.allow_firewall_port(a, transport, 'tcp')
    bodies.wait_listener(a, 'tcp', listener)
    return {'method': 'BACKHAUL_TCP', 'listen_port': listener, 'listener_side': 'A',
            'services_a': [name + '-server'], 'services_b': [name + '-client'],
            'files_a': [directory], 'files_b': [directory], 'transport': 'Backhaul TCP; token authentication; payload not encrypted'}
