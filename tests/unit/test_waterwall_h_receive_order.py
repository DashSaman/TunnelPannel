"""Compile the pinned receive function against adversarial transport callbacks.

These callbacks model TLS closing synchronously during an HTTP2 control write.
The assertion is on delivered application bytes and lifetime, not source text.
"""
from pathlib import Path
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.unit_portable


def test_receive_patch_is_idempotent_and_refuses_unreviewed_source():
    from engines.waterwall_h import patch_http2_receive
    source = (Path(__file__).parents[1] / 'fixtures/waterwall_h_httpclient_receive.c').read_text()
    changed = patch_http2_receive(source)
    assert patch_http2_receive(changed) == changed
    with pytest.raises(ValueError, match='unexpected WaterWall-H HTTP2 client receive source'):
        patch_http2_receive('unreviewed source')


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef long nghttp2_ssize;
typedef struct { bool websocket_enabled, verbose; } httpclient_tstate_t;
typedef struct { httpclient_tstate_t *state; } tunnel_t;
typedef struct { bool alive; } line_t;
typedef struct { uint32_t len; unsigned char data[256]; } sbuf_t;
typedef struct {
 void *session;
 bool websocket_h2_request_submitted, h2_headers_received, websocket_active;
 bool websocket_h2_status_seen, websocket_h2_protocol_seen, websocket_h2_extensions_seen;
 bool websocket_waiting_handshake;
 int websocket_h2_status_code, h2_stream_id;
 char *websocket_h2_protocol, *websocket_h2_extensions;
} httpclient_lstate_t;
static int mode, queued, delivered, control_writes, reused, ws_drains;
#define min(a,b) ((a)<(b)?(a):(b))
#define kHttpClientNghttp2RecvChunkBytes 64
#define LOGE(...) ((void)0)
#define LOGD(...) ((void)0)
#define boolToTrueFalse(x) ((x)?"true":"false")
static uint32_t sbufGetLength(sbuf_t *b) { return b->len; }
static void *sbufGetRawPtr(sbuf_t *b) { return b->data; }
static void lineReuseBuffer(line_t *l,sbuf_t *b) { (void)l;(void)b;reused++; }
static httpclient_tstate_t *tunnelGetState(tunnel_t *t) { return t->state; }
static nghttp2_ssize nghttp2_session_mem_recv2(void *s,const uint8_t *p,size_t n) {
 (void)s;(void)p;queued+=(int)n;return (nghttp2_ssize)n;
}
static bool httpclientTransportMaybeSubmitWebSocketHttp2Request(tunnel_t *t,line_t *l,httpclient_lstate_t *s) {
 (void)t;(void)l;(void)s;return true;
}
static bool sendNghttp2Outbound(tunnel_t *t,line_t *l,httpclient_lstate_t *s) {
 (void)t;(void)s;control_writes++;
 if(mode==1) { /* TLS failure -> synchronous downstream Finish destroys queued DATA. */
  l->alive=false;queued=0;return false;
 }
 if(mode==2) return false;
 return true;
}
static bool drainDownEvents(tunnel_t *t,line_t *l,httpclient_lstate_t *s) {
 (void)t;(void)s;
 if(!l->alive) return false;
 delivered+=queued;queued=0;
 if(mode==3) { l->alive=false;return false; }
 return true;
}
static bool httpclientTransportDrainWebSocketDown(tunnel_t *t,line_t *l,httpclient_lstate_t *s) {
 (void)t;(void)l;(void)s;ws_drains++;return true;
}
static bool httpclientTransportFlushPendingUp(tunnel_t *t,line_t *l,httpclient_lstate_t *s) {
 (void)t;(void)l;(void)s;return true;
}
'''

MAIN = r'''
int main(int argc,char **argv) {
 mode=argc>1?atoi(argv[1]):0;
 httpclient_tstate_t ts={.websocket_enabled=mode==4};
 tunnel_t t={.state=&ts};line_t l={.alive=true};sbuf_t b={.len=256};
 httpclient_lstate_t state={.websocket_active=mode==4};
 bool ok=httpclientTransportFeedHttp2Input(&t,&l,&state,&b);
 printf("%d %d %d %d %d %d\n",ok,delivered,control_writes,reused,ws_drains,l.alive);
 return 0;
}
'''


@pytest.fixture(scope='module')
def receive_harness(tmp_path_factory):
    compiler = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
    if not compiler:
        pytest.skip('C compiler required; exercised on physical Linux and Linux CI')
    import engines.waterwall_h as engine
    source = (Path(__file__).parents[1] / 'fixtures/waterwall_h_httpclient_receive.c').read_text()
    # On the original module, compile the unmodified production function: this
    # makes missing/deleted patch behavior fail on bytes, not an ImportError.
    source = getattr(engine, 'patch_http2_receive', lambda text: text)(source)
    directory = tmp_path_factory.mktemp('waterwall-receive')
    cfile, binary = directory / 'receive.c', directory / 'receive'
    cfile.write_text(PRELUDE + source + MAIN)
    subprocess.run([compiler, '-std=c11', '-Wall', '-Werror', str(cfile), '-o', str(binary)],
                   check=True, capture_output=True, text=True)
    return binary


@pytest.mark.parametrize('mode', [1, 2])
def test_received_data_delivered_before_control_write_can_fail(receive_harness, mode):
    result = subprocess.run([str(receive_harness), str(mode)], check=True, capture_output=True, text=True)
    ok, delivered, writes, reused, _, _ = map(int, result.stdout.split())
    assert delivered == 256, 'parsed response DATA was discarded by a synchronous control-write failure'
    assert (ok, writes, reused) == (0, 1, 1)  # Preserve failure reporting and single ownership release.


def test_consumer_close_does_not_write_after_destroying_receive_state(receive_harness):
    result = subprocess.run([str(receive_harness), '3'], check=True, capture_output=True, text=True)
    ok, delivered, writes, reused, _, alive = map(int, result.stdout.split())
    assert (ok, delivered, writes, reused, alive) == (0, 256, 0, 1, 0)


@pytest.mark.parametrize('mode', [0, 4])
def test_healthy_transport_and_websocket_paths_preserved(receive_harness, mode):
    result = subprocess.run([str(receive_harness), str(mode)], check=True, capture_output=True, text=True)
    ok, delivered, writes, reused, ws_drains, alive = map(int, result.stdout.split())
    assert (ok, writes, reused, alive) == (1, 1, 1, 1)
    assert (delivered, ws_drains) == ((0, 1) if mode == 4 else (256, 0))
