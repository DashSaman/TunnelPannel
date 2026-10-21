"""Real Linux TCP regression for unread-control RST and deferred close ownership."""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.unit_portable


def test_tcp_close_patch_is_idempotent_and_rejects_drift():
    from engines.waterwall_h import patch_tcp_close_source
    source = (Path(__file__).parents[1] / 'fixtures/waterwall_h_nio_close.c').read_text()
    changed = patch_tcp_close_source(source)
    assert patch_tcp_close_source(changed) == changed
    with pytest.raises(ValueError, match='unexpected WaterWall-H TCP close source'):
        patch_tcp_close_source('unreviewed source')


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#define OS_LINUX 1
#define UNLIKELY(x) (x)
#define WIO_TYPE_TCP 1
#define WIO_DEFAULT_CLOSE_TIMEOUT 60000
#define WW_READ 1
#define WW_WRITE 2
#define wlogd(...) ((void)0)
typedef struct { void *privdata; } wtimer_t;
typedef struct { int bytes; } queue_t;
typedef struct wio_s {
 int fd,error,close_timeout,closed,close,destroy,close_in_progress,io_type;
 int drain_close,read_eof,events,read_flags;
 queue_t write_queue;
 wtimer_t *close_timer;
 void *loop;
 void (*read_cb)(void);
 void (*write_cb)(void);
} wio_t;
static wtimer_t timer;
static int done_calls, close_calls, timer_ms;
int wioClose(wio_t *io);
static int write_queue_empty(queue_t *q) { return q->bytes==0; }
static int wioGetFD(wio_t *io) { return io->fd; }
static wtimer_t *wtimerAdd(void *l,void (*cb)(wtimer_t*),uint32_t ms,int count) {
 (void)l;(void)cb;(void)count;timer_ms=(int)ms;return &timer;
}
static void __close_timeout_cb(wtimer_t *t) {
 wio_t *io=t->privdata;io->error=ETIMEDOUT;wioClose(io);
}
static void wioDone(wio_t *io) { done_calls++;io->write_queue.bytes=0; }
static void __close_cb(wio_t *io) { close_calls++;io->close_timer=NULL; }
static void wioReleaseFD(wio_t *io,bool keep) { if(!keep)close(io->fd);io->fd=-1; }
static void wioFinalizeNow(wio_t *io) { (void)io; }
static int wioRead(wio_t *io) { io->events|=WW_READ;return 0; }
static int wioDel(wio_t *io,int ev) { io->events&=~ev;return 0; }
static void wioSetCallBackRead(wio_t *io,void (*cb)(void)) {io->read_cb=cb;}
static void wioSetCallBackWrite(wio_t *io,void (*cb)(void)) {io->write_cb=cb;}
static void wioDelCloseTimer(wio_t *io) {io->close_timer=NULL;io->close_timeout=0;}
'''

MAIN = r'''
static void pair(int *server,int *client) {
 int l=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
 if(bind(l,(void*)&a,sizeof(a))||listen(l,1))exit(90);
 socklen_t n=sizeof(a);getsockname(l,(void*)&a,&n);
 *client=socket(AF_INET,SOCK_STREAM,0);if(connect(*client,(void*)&a,n))exit(91);
 *server=accept(l,NULL,NULL);close(l);
 struct timeval tv={.tv_sec=1};setsockopt(*client,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
}
int main(int argc,char **argv) {
 int mode=argc>1?atoi(argv[1]):0,s,c;pair(&s,&c);
 wio_t io={.fd=s,.io_type=WIO_TYPE_TCP};
 if(mode==0) {
  int one=1;setsockopt(s,IPPROTO_TCP,TCP_CORK,&one,sizeof(one));
  char control[13]={0},tail[275]={0};send(c,control,sizeof(control),0);
  usleep(10000);send(s,tail,sizeof(tail),0);
  wioCloseDrain(&io);
  char data[1024];int n,total=0,error=0;
  while((n=recv(c,data,sizeof(data),0))>0)total+=n;
  if(n<0)error=errno;
  int prematurely_closed=io.closed;
  if(!io.closed) {
   shutdown(c,SHUT_WR);
   while(recv(s,data,sizeof(data),0)>0){}
   io.read_eof=1;wioClose(&io);
  }
  printf("%d %d %d %d %d\n",total,error,prematurely_closed,io.closed,close_calls);
 } else if(mode==1) {
  io.write_queue.bytes=275;wioCloseDrain(&io);int write_deadline=timer_ms;wioClose(&io);
  int retained=io.write_queue.bytes,early=io.closed;
  io.read_eof=1;wioClose(&io);int eof_retained=io.write_queue.bytes;
  io.write_queue.bytes=0;io.close=0;wioClose(&io);
  printf("%d %d %d %d %d %d\n",retained,early,eof_retained,io.closed,close_calls,write_deadline);
 } else if(mode==2) {
  wioCloseDrain(&io);wioClose(&io);int early=io.closed;
  if(!io.closed)__close_timeout_cb(io.close_timer);
  printf("%d %d %d %d\n",early,io.closed,io.error,close_calls);
 } else if(mode==4) {
  io.write_queue.bytes=275;wioCloseDrain(&io);int write_deadline=timer_ms;
  io.write_queue.bytes=0;io.close=0;wioClose(&io);int read_deadline=timer_ms;
  __close_timeout_cb(io.close_timer);
  printf("%d %d %d %d\n",write_deadline,read_deadline,io.closed,close_calls);
 } else {
  io.error=ECONNRESET;wioCloseDrain(&io);
  printf("%d %d\n",io.closed,close_calls);
 }
 close(c);return 0;
}
'''


@pytest.fixture(scope='module')
def close_harness(tmp_path_factory):
    compiler = shutil.which('cc')
    if sys.platform != 'linux' or not compiler:
        pytest.skip('Linux TCP_CORK and C compiler required')
    from engines import waterwall_h
    source = (Path(__file__).parents[1] / 'fixtures/waterwall_h_nio_close.c').read_text()
    patch = getattr(waterwall_h, 'patch_tcp_close_source', None)
    if patch:
        source = patch(source)
    else:
        source += '\nint wioCloseDrain(wio_t *io) { return wioClose(io); }\n'
    directory = tmp_path_factory.mktemp('waterwall-close')
    code, binary = directory / 'close.c', directory / 'close'
    code.write_text(PRELUDE + source + MAIN)
    subprocess.run([compiler, '-std=gnu11', '-O0', str(code), '-o', str(binary)],
                   check=True, capture_output=True, text=True)
    return binary


@pytest.mark.parametrize(('mode', 'expected'), [
    (0, [275, 0, 0, 1, 1]),
    (1, [275, 0, 275, 1, 1, 60000]),
    (2, [0, 1, 110, 1]),
    (3, [1, 1]),
    (4, [60000, 2000, 1, 1]),
])
def test_real_tcp_tail_and_close_lifetime(close_harness, mode, expected):
    result = subprocess.run([str(close_harness), str(mode)], check=True,
                            capture_output=True, text=True, timeout=5)
    assert list(map(int, result.stdout.split())) == expected, result.stdout
