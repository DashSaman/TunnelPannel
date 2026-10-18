"""Independently rendered WaterWall-H recipes; source remains MPL-2.0 upstream.

The optional owned-CA patch adds an explicit CA file to the embedded trust
store. Invalid or empty files fail startup; peer/hostname verification stays on.
"""
from __future__ import annotations
import json
from pathlib import Path
import secrets
import shlex
import uuid

PIN = '613bb32c93db40b09cb915070e5f7ff09ad3c81d'
METHODS = {'WATERWALL_H_WS_TLS', 'WATERWALL_H_HTTP2_TLS', 'WATERWALL_H_REALITY',
           'WATERWALL_H_VLESS_REALITY'}
PATCHSET = 'ca1-h2drain6'
RUNTIME = '/opt/tunnelpannel-engines/waterwall-h/' + PIN + '-' + PATCHSET


def patch_http2_receive(source):
    """Deliver parsed DATA before a control write can close the transport.

    nghttp2 queues received application events. Sending its WINDOW_UPDATE/ACK
    first can re-enter downstream Finish through the transport and destroy it.
    Drain received events first; an aborted consumer must also prevent writes
    through the receive state it just destroyed. WebSocket handling is unchanged.
    """
    before = '''    if (! sendNghttp2Outbound(t, l, ls))
    {
        return false;
    }

    httpclient_tstate_t *ts = tunnelGetState(t);
    if (! ts->websocket_enabled)
    {
        if (! drainDownEvents(t, l, ls))
        {
            return false;
        }
    }
'''
    after = '''    /* TunnelPannel: deliver received DATA before a re-entrant control write. */
    httpclient_tstate_t *ts = tunnelGetState(t);
    if (! ts->websocket_enabled)
    {
        if (! drainDownEvents(t, l, ls))
        {
            return false;
        }
    }

    if (! sendNghttp2Outbound(t, l, ls))
    {
        return false;
    }
'''
    if source.count(after) == 1:
        return source
    if source.count(before) != 1:
        raise ValueError('unexpected WaterWall-H HTTP2 client receive source')
    return source.replace(before, after)


def patch_tcp_close_source(source):
    """Opt-in Linux close: send FIN, then consume late control until peer EOF.

    close(fd) with unread WINDOW_UPDATE sends RST even when all application
    output reached send(). That reset can discard the peer's unread tail.
    The detached listener owns no more application callbacks during this drain.
    """
    def replace(before, after):
        nonlocal source
        if source.count(after) == 1:
            return
        if source.count(before) != 1:
            raise ValueError('unexpected WaterWall-H TCP close source')
        source = source.replace(before, after)

    replace('    if (! write_queue_empty(&io->write_queue) && io->error == 0 && io->close == 0 && io->destroy == 0)',
            '''#if defined(OS_LINUX)
    /* TunnelPannel: repeated close/EOF cannot abort an owned write drain. */
    if (io->drain_close && io->close && io->error == 0 && ! io->destroy &&
        (! write_queue_empty(&io->write_queue) || (io->drain_close == 2 && ! io->read_eof)))
    {
        return 0;
    }
#endif
    if (! write_queue_empty(&io->write_queue) && io->error == 0 && io->close == 0 && io->destroy == 0)''')
    replace('    const bool freeing    = io->destroy;',
            '''#if defined(OS_LINUX)
    /* TunnelPannel: a software-empty queue is not a completed TCP close. */
    if (io->drain_close && ! io->read_eof && io->error == 0 && ! io->destroy &&
        io->io_type == WIO_TYPE_TCP && shutdown(wioGetFD(io), SHUT_WR) == 0)
    {
        io->drain_close = 2;
        io->close = 1;
        wioDel(io, WW_WRITE);
        int timeout_ms = io->close_timeout ? io->close_timeout : 2000;
        wioDelCloseTimer(io);
        io->close_timer = wtimerAdd(io->loop, __close_timeout_cb, (uint32_t) timeout_ms, 1);
        if (io->close_timer != NULL)
        {
            io->close_timer->privdata = io;
            return wioRead(io);
        }
        io->error = ECANCELED;
    }
#endif
    const bool freeing    = io->destroy;''')
    before = '\n\n    return 0;\n}'
    # Anchor to the final close body rather than every return in the full file.
    before = '        wioFinalizeNow(io);\n    }' + before
    replace(before, before + '''

#if defined(OS_LINUX)
int wioCloseDrain(wio_t *io)
{
    if (! io->drain_close) io->drain_close = 1;
    /* Caller has detached the application owner before requesting this close. */
    wioSetCallBackRead(io, NULL);
    wioSetCallBackWrite(io, NULL);
    io->read_flags = 0;
    return wioClose(io);
}
#endif''')
    return source


def patch_tcp_close(directory):
    root = Path(directory)

    def replace(path, before, after):
        target = root / path
        text = target.read_text()
        if text.count(after) == 1:
            return
        if text.count(before) != 1:
            raise ValueError('unexpected WaterWall-H TCP close source: ' + path)
        target.write_text(text.replace(before, after))

    replace('ww/event/wevent.h', '    unsigned close : 1;', '''    unsigned close : 1;
#if defined(OS_LINUX)
    unsigned drain_close : 2; /* TunnelPannel: requested / FIN sent */
    unsigned read_eof : 1;
#endif''')
    replace('ww/event/wevent.c', '    io->close                 = 0;', '''    io->close                 = 0;
#if defined(OS_LINUX)
    io->drain_close = 0;
    io->read_eof = 0;
#endif''')
    replace('ww/event/wloop.h', 'WW_EXPORT int wioClose(wio_t *io);', '''WW_EXPORT int wioClose(wio_t *io);
#if defined(OS_LINUX)
/* Detached TCP owner only: flush output, FIN, discard input until EOF/timeout. */
WW_EXPORT int wioCloseDrain(wio_t *io);
#endif''')
    replace('ww/event/nio.c', '''        goto disconnect;
    }
    // printf("%d \\n",nread);''', '''#if defined(OS_LINUX)
        io->read_eof = 1;
        if (io->drain_close) wioDel(io, WW_READ);
#endif
        goto disconnect;
    }
    // printf("%d \\n",nread);''')
    target = root / 'ww/event/nio.c'
    target.write_text(patch_tcp_close_source(target.read_text()))
    replace('tunnels/TcpListener/downstream/fin.c', '    wioClose(ls->io);', '''#if defined(OS_LINUX)
    wioCloseDrain(ls->io);
#else
    wioClose(ls->io);
#endif''')


def patch_http2_drain(directory):
    """Keep the H2 server alive for WINDOW_UPDATE until queued DATA drains.

    The pinned upstream destroyed its nghttp2 queue on target EOF even when
    stream/connection flow control still held unsent response bytes.
    """
    root = Path(directory) / 'tunnels' / 'HttpServer'

    def replace(path, before, after):
        target = root / path
        text = target.read_text()
        if after in text:
            return
        if text.count(before) != 1:
            raise ValueError('unexpected WaterWall-H HTTP2 source: ' + path)
        target.write_text(text.replace(before, after))

    replace('include/HttpServer/structure.h', '    bool h2_request_rejected;',
            '    bool h2_request_rejected;\n    bool h2_finish_deferred; /* TunnelPannel: drain before EOF */')
    replace('downstream/fin.c',
            '    // A final-byte send above can re-enter through an upstream Finish from prev',
            '''    /* TunnelPannel: EOF must not discard flow-control-blocked DATA.
     * Keep the transport open to process WINDOW_UPDATE; upstream payload
     * completes this finish after the END_STREAM item has been emitted. */
    if (! ts->websocket_enabled && ls->runtime_proto == kHttpServerRuntimeHttp2 &&
        ! ls->prev_finished && (ls->h2_data_head != NULL || ls->h2_data_active != NULL))
    {
        ls->h2_finish_deferred = true;
        lineUnref(l);
        return;
    }

    // A final-byte send above can re-enter through an upstream Finish from prev''')
    replace('upstream/payload.c',
            '        if (ts->websocket_enabled && ls->websocket_active &&\n',
            '''        /* TunnelPannel: response END_STREAM is now fully serialized. */
        if (ls->h2_finish_deferred && ls->h2_data_head == NULL && ls->h2_data_active == NULL)
        {
            ls->h2_finish_deferred = false;
            httpserverTunnelDownStreamFinish(t, l);
            lineUnref(l);
            return;
        }

        if (ts->websocket_enabled && ls->websocket_active &&
''')
    replace('upstream/fin.c', '        ls->prev_finished = true;\n        lineUnref(l);',
            '''        ls->prev_finished = true;
        if (ls->h2_finish_deferred)
        {
            /* Peer abandoned the drain; no downstream Finish is on stack. */
            httpserverLinestateDestroy(ls);
        }
        lineUnref(l);''')
    replace('include/HttpServer/structure.h',
            '    bool h2_finish_deferred; /* TunnelPannel: drain before EOF */',
            '''    bool h2_finish_deferred; /* TunnelPannel: drain before EOF */
    bool h2_source_paused;
    size_t h2_queued_bytes;''')
    replace('common/transport.c',
            '    httpserverH2DataQueuePush(ls, httpserverH2DataItemCreate(payload, end_stream));',
            '''    /* TunnelPannel: bound the queue even if a producer ignores Pause. */
    if (ls->h2_queued_bytes + payload_len > 4U * 1024U * 1024U)
    {
        if (payload != NULL) lineReuseBuffer(l, payload);
        return false;
    }
    ls->h2_queued_bytes += payload_len;
    httpserverH2DataQueuePush(ls, httpserverH2DataItemCreate(payload, end_stream));''')
    replace('common/transport.c',
            '    httpserverH2DataItemDestroy(ls->line, ls->h2_data_active);\n    ls->h2_data_active = NULL;',
            '''    /* TunnelPannel: account only after nghttp2 emits the final DATA frame. */
    if (ls->h2_data_active->payload != NULL)
        ls->h2_queued_bytes -= sbufGetLength(ls->h2_data_active->payload);
    httpserverH2DataItemDestroy(ls->line, ls->h2_data_active);
    ls->h2_data_active = NULL;''')
    replace('common/transport.c',
            '    return true;\n}\n\nstatic httpserver_h2_data_item_t *httpserverH2DataItemCreate',
            '''    /* TunnelPannel: flow control must propagate to the response producer.
     * Resume outside nghttp2 callbacks to avoid re-entering its frame parser. */
    if (! ls->next_finished)
    {
        if (! ls->h2_source_paused && ls->h2_queued_bytes >= 256U * 1024U)
        {
            ls->h2_source_paused = true;
            tunnelNextUpStreamPause(t, l);
        }
        else if (ls->h2_source_paused && ls->h2_queued_bytes <= 64U * 1024U)
        {
            ls->h2_source_paused = false;
            tunnelNextUpStreamResume(t, l);
        }
    }
    return true;
}

static httpserver_h2_data_item_t *httpserverH2DataItemCreate''')
    root = Path(directory) / 'tunnels' / 'HttpClient'
    replace('include/HttpClient/structure.h',
            '    httpclient_h2_data_item_t *h2_data_active;',
            '''    httpclient_h2_data_item_t *h2_data_active;
    bool h2_source_paused;
    size_t h2_queued_bytes;''')
    replace('common/transport.c',
            '    httpclientH2DataQueuePush(ls, httpclientH2DataItemCreate(payload, end_stream));',
            '''    /* TunnelPannel: bound upload buffering and propagate flow control. */
    if (ls->h2_queued_bytes + payload_len > 4U * 1024U * 1024U)
    {
        if (payload != NULL) lineReuseBuffer(l, payload);
        return false;
    }
    ls->h2_queued_bytes += payload_len;
    httpclientH2DataQueuePush(ls, httpclientH2DataItemCreate(payload, end_stream));''')
    replace('common/transport.c',
            '    httpclientH2DataItemDestroy(ls->line, ls->h2_data_active);\n    ls->h2_data_active = NULL;',
            '''    if (ls->h2_data_active->payload != NULL)
        ls->h2_queued_bytes -= sbufGetLength(ls->h2_data_active->payload);
    httpclientH2DataItemDestroy(ls->line, ls->h2_data_active);
    ls->h2_data_active = NULL;''')
    replace('common/transport.c',
            '    return true;\n}\n\nstatic httpclient_h2_data_item_t *httpclientH2DataItemCreate',
            '''    /* TunnelPannel: resume the request producer outside nghttp2 callbacks. */
    if (! ls->prev_finished)
    {
        if (! ls->h2_source_paused && ls->h2_queued_bytes >= 256U * 1024U)
        {
            ls->h2_source_paused = true;
            tunnelPrevDownStreamPause(t, l);
        }
        else if (ls->h2_source_paused && ls->h2_queued_bytes <= 64U * 1024U)
        {
            ls->h2_source_paused = false;
            tunnelPrevDownStreamResume(t, l);
        }
    }
    return true;
}

static httpclient_h2_data_item_t *httpclientH2DataItemCreate''')
    target = root / 'common/transport.c'
    target.write_text(patch_http2_receive(target.read_text()))
    patch_tcp_close(directory)


def patch_owned_ca(source):
    if 'TP_WATERWALL_CA_FILE' in source:
        return source
    start = source.find('static bool loadCaCertificates(SSL_CTX *ssl_ctx)')
    if start < 0:
        raise ValueError('unexpected WaterWall-H TLS source')
    end = source.find('\nstatic SSL_CTX *setupSslContext', start)
    if end < 0:
        end = len(source)
    block = source[start:end]
    old = '    BIO_free(bio);\n    return true;'
    if block.count(old) != 1:
        raise ValueError('WaterWall-H CA loader does not match the reviewed source')
    extra = '''    BIO_free(bio);
    /* TunnelPannel addition: an explicit owned CA augments embedded roots. */
    const char *owned_ca = getenv("TP_WATERWALL_CA_FILE");
    if (owned_ca != NULL && owned_ca[0] != '\\0')
    {
        BIO *owned = BIO_new_file(owned_ca, "r");
        if (owned == NULL) return false;
        size_t loaded = 0;
        while ((x = PEM_read_bio_X509_AUX(owned, NULL, NULL, NULL)) != NULL)
        {
            int added = X509_STORE_add_cert(SSL_CTX_get_cert_store(ssl_ctx), x);
            X509_free(x);
            if (added != 1) { BIO_free(owned); return false; }
            ++loaded;
        }
        BIO_free(owned);
        return loaded > 0;
    }
    return true;'''
    return '#include <stdlib.h>\n' + source[:start] + block.replace(old, extra) + source[end:]


def paired_configs(method, peer, transport_port, local_port, target_port, cert_file, key_file,
                   password, salt, cover_port, user_uuid=None):
    if method not in METHODS:
        raise ValueError('unknown reviewed WaterWall-H recipe')

    def node(name, kind, settings, next_node=None):
        result = {'name': name, 'type': kind, 'settings': settings}
        if next_node:
            result['next'] = next_node
        return result

    def connector(name, host, port):
        return node(name, 'TcpConnector', {'address': host, 'port': port, 'nodelay': True, 'fastopen': False})

    tls_client = {'sni': 'owned-cover.test', 'alpns': ['h2', 'http/1.1'], 'verify': True}
    tls_server = {'cert-file': cert_file, 'key-file': key_file, 'select-alpns': ['h2', 'http/1.1']}
    client, server = [], []
    user_uuid = user_uuid or str(uuid.uuid4())
    if 'REALITY' in method:
        auth = {'password': password, 'salt': salt, 'algorithm': 'chacha20-poly1305', 'kdf-iterations': 12000}
        if method == 'WATERWALL_H_VLESS_REALITY':
            # Fixed-target stream recipes avoid inventing dest_context on a
            # plain TcpListener. VLESS explicitly carries this owned target.
            client.append(node('protocol-client', 'VlessClient',
                {'uuid': user_uuid, 'address': '127.0.0.1',
                 'port': target_port, 'protocol': 'tcp'}, 'reality-client'))
            first = 'protocol-client'
            next_server = 'protocol-server'
        else:
            first, next_server = 'reality-client', 'target-out'
        client.append(node('reality-client', 'RealityClient', {**tls_client, **auth}, 'transport-out'))
        server.append(node('reality-server', 'RealityServer', {**auth, 'destination': 'cover-out',
                                                              'sniffing-attempts': 8}, next_server))
        if method == 'WATERWALL_H_VLESS_REALITY':
            server.append(node('protocol-server', 'VlessServer', {'uuid': user_uuid,
                                                                 'connect': True, 'udp': False}, 'target-out'))
        server.append(connector('cover-out', '127.0.0.1', cover_port))
    else:
        version = '2' if method == 'WATERWALL_H_HTTP2_TLS' else '1.1'
        tls_client['alpns'] = ['h2'] if version == '2' else ['http/1.1']
        tls_server['select-alpns'] = list(tls_client['alpns'])
        http_client = {'host': 'owned-cover.test', 'path': '/owned-stream', 'scheme': 'https',
                       'port': transport_port, 'http-version': version}
        http_server = {'host': 'owned-cover.test', 'path': '/owned-stream', 'http-version': version, 'status': 200}
        if version == '2':
            http_client['method'] = http_server['method'] = 'POST'
        else:
            http_client.update(websocket=True, **{'websocket-subprotocol': 'tunnel-stream'})
            http_server.update(websocket=True, **{'websocket-subprotocol': 'tunnel-stream'})
        # TLS authenticates the server. A separate AEAD layer authenticates the
        # client as well, so an unauthenticated listener is never a raw relay.
        auth = {'algorithm': 'chacha20-poly1305', 'password': password, 'salt': salt, 'kdf-iterations': 12000}
        client += [node('encryption-client', 'EncryptionClient', auth, 'http-client'),
                   node('http-client', 'HttpClient', http_client, 'tls-client'),
                   node('tls-client', 'TlsClient', tls_client, 'transport-out')]
        server += [node('tls-server', 'TlsServer', tls_server, 'http-server'),
                   node('http-server', 'HttpServer', http_server, 'encryption-server'),
                   node('encryption-server', 'EncryptionServer', auth, 'target-out')]
        first = 'encryption-client'
    client = [node('local-in', 'TcpListener', {'address': '127.0.0.1', 'port': local_port, 'nodelay': True}, first)] + client
    client.append(connector('transport-out', peer, transport_port))
    server = [node('transport-in', 'TcpListener', {'address': peer, 'port': transport_port, 'nodelay': True},
                   'reality-server' if 'REALITY' in method else 'tls-server')] + server
    server.append(connector('target-out', '127.0.0.1', target_port))
    return {'name': method + '-client', 'nodes': client}, {'name': method + '-server', 'nodes': server}


def installed(remote):
    script = f'''import hashlib,json,pathlib
base=pathlib.Path({RUNTIME!r})
try:
 meta=json.loads((base/'build.json').read_text())
 assert meta['source_commit']=={PIN!r} and meta['patchset']=={PATCHSET!r}
 assert hashlib.sha256((base/'waterwall').read_bytes()).hexdigest()==meta['sha256']
except Exception: raise SystemExit(1)
'''
    return remote.run('python3 -c ' + shlex.quote(script), root=True, check=False)['code'] == 0


def install(remote):
    """Bounded, unprivileged pinned build. Invoke during job preparation."""
    if installed(remote):
        return
    from plan_executor import executor as bodies
    # Build code lives outside the panel's private customer-data directory.
    # Keep source/build trees separate from older patches and archive-only caches.
    root = '/var/cache/tunnelpannel-build/waterwall-h/' + PIN + '-' + PATCHSET
    remote.run('install -d -m 0755 /var/cache/tunnelpannel-build/waterwall-h', root=True)
    bodies.write_remote_text(remote, root + '/owned_ca_module.py', Path(__file__).read_text(encoding='utf-8'), '0644')
    remote.run('chmod 0755 ' + shlex.quote(root), root=True)
    build = r'''set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null; then
 apt-get update -qq; apt-get install -y -qq build-essential cmake ninja-build git pkg-config perl ca-certificates
elif command -v dnf >/dev/null; then
 dnf install -y gcc gcc-c++ make cmake ninja-build git pkgconf-pkg-config perl ca-certificates
elif command -v yum >/dev/null; then
 yum install -y gcc gcc-c++ make cmake ninja-build git pkgconfig perl ca-certificates
elif command -v zypper >/dev/null; then
 zypper --non-interactive install gcc gcc-c++ make cmake ninja git pkg-config perl ca-certificates
elif command -v pacman >/dev/null; then
 pacman -Sy --noconfirm --needed base-devel cmake ninja git pkgconf perl ca-certificates
elif command -v apk >/dev/null; then
 apk add build-base cmake ninja git pkgconf perl linux-headers ca-certificates shadow
else exit 3; fi
id tp-wwbuild >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin tp-wwbuild
install -d -m 0700 -o tp-wwbuild -g tp-wwbuild '__ROOT__/work'
runuser -u tp-wwbuild -- bash -s <<'COMPILE'
set -Eeuo pipefail
cd '__ROOT__/work'
if ! test -d source/.git; then git clone --filter=blob:none --no-checkout https://github.com/DashSaman/WaterWall-H.git source; fi
test "$(git -C source remote get-url origin)" = 'https://github.com/DashSaman/WaterWall-H.git'
git -C source fetch --depth=1 origin '__PIN__'
git -C source checkout --detach '__PIN__'
test "$(git -C source rev-parse HEAD)" = '__PIN__'
git -C source restore --source='__PIN__' tunnels/TlsClient/instance/create.c tunnels/HttpServer tunnels/HttpClient tunnels/TcpListener/downstream/fin.c ww/event/nio.c ww/event/wevent.c ww/event/wevent.h ww/event/wloop.h
python3 - <<'PATCH'
import pathlib,runpy
module=runpy.run_path('__ROOT__/owned_ca_module.py')
target=pathlib.Path('source/tunnels/TlsClient/instance/create.c')
target.write_text(module['patch_owned_ca'](target.read_text()))
module['patch_http2_drain']('source')
PATCH
cmake -S source -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DWW_ENABLE_IPO=OFF -DWW_BUILD_UNIT_TESTS=OFF -DBUILD_TESTING=OFF
cmake --build build --target Waterwall --parallel 1
COMPILE
install -d -m 0755 '__RUNTIME__'
install -m 0755 '__ROOT__/work/build/Waterwall' '__RUNTIME__/waterwall'
python3 - <<'STAMP'
import pathlib,hashlib,json
base=pathlib.Path('__RUNTIME__')
meta={'source_commit':'__PIN__','owned_ca_patch':'ca1','patchset':'__PATCHSET__','sha256':hashlib.sha256((base/'waterwall').read_bytes()).hexdigest()}
(base/'build.json').write_text(json.dumps(meta))
STAMP
'''.replace('__ROOT__', root).replace('__PIN__', PIN).replace('__RUNTIME__', RUNTIME).replace('__PATCHSET__', PATCHSET)
    bodies.write_remote_text(remote, root + '/build.sh', build, '0700')
    # write_remote_text reapplies mode 0700 to its parent directory.
    # The unprivileged compiler must be able to traverse this code-only parent.
    remote.run('chmod 0755 ' + shlex.quote(root), root=True)
    log = shlex.quote(root + '/build.log')
    command = ('build_rc=0; timeout -s TERM 1700 bash ' + shlex.quote(root + '/build.sh') +
               ' > ' + log + ' 2>&1 || build_rc=$?; if [ "$build_rc" -ne 0 ]; then tail -n 60 ' +
               log + '; exit "$build_rc"; fi')
    remote.run(command, root=True, timeout=1800)
    if not installed(remote):
        raise RuntimeError('pinned WaterWall-H build integrity failed')


def deploy(method, run, item, config, a, b, endpoint_a, endpoint_b):
    from plan_executor import executor as bodies
    if not all(installed(remote) for remote in (a, b)):
        raise RuntimeError('WaterWall-H must be prepared before timed candidate execution')
    port = bodies.free_port(b, 'tcp', 23000)
    bodies.allow_firewall_port(b, port, 'tcp')
    local = bodies.free_port(a, 'tcp', 22000)
    target = int(config['target_port'])
    name = f'netauto-wwh-{run["id"]}-{item["id"]}'
    directory = '/etc/netauto/waterwall-h/' + name
    tls = bodies.prepare_tls_pair(b, a, name=name, server_host='owned-cover.test', pfx_password='unused')
    cover_port = bodies.free_port(b, 'tcp', 25000)
    secret, salt = secrets.token_hex(16), secrets.token_hex(12)
    client, server = paired_configs(method, endpoint_b['host'], port, local, target,
        tls['server_cert'], tls['server_key'], secret, salt, cover_port)
    services_a, services_b = [name + '-client'], [name + '-server']
    if 'REALITY' in method:
        cover = name + '-cover'
        services_b.append(cover)
        bodies.persistent_service(b, cover,
            f"exec openssl s_server -accept 127.0.0.1:{cover_port} -tls1_3 -cert {shlex.quote(tls['server_cert'])} "
            f"-key {shlex.quote(tls['server_key'])} -alpn h2,http/1.1 -www -quiet")
        bodies.wait_listener(b, 'tcp', cover_port)
    for remote, doc, service in ((b, server, services_b[0]), (a, client, services_a[0])):
        core = bodies.waterwall_core(1)
        core['misc']['ram-profile'] = 'client'
        core['misc']['libs-path'] = directory + '/libs/'
        remote.run('install -d -m 700 ' + shlex.quote(directory + '/libs'), root=True)
        bodies.write_remote_text(remote, directory + '/core.json', json.dumps(core), '0600')
        bodies.write_remote_text(remote, directory + '/config.json', json.dumps(doc), '0600')
        command = f'cd {shlex.quote(directory)}; exec {RUNTIME}/waterwall --config:core.json'
        environment = {'TP_WATERWALL_CA_FILE': tls['client_ca']} if remote is a else None
        bodies.persistent_service(remote, service, command, environment)
        bodies.wait_listener(remote, 'tcp', port if remote is b else local)
    return {'method': method, 'listen_side': 'A', 'listen_port': local, 'transport_port': port,
            'services_a': services_a, 'services_b': services_b,
            'files_a': [directory, tls['client_dir']], 'files_b': [directory, tls['server_dir']],
            'source_commit': PIN, 'owned_ca_extension': 'ca1', 'certificate_validation': True,
            'authenticated_transport': True}
