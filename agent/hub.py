"""A separate bounded mTLS listener. Client headers cannot supply identity."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import socket
import tempfile
import threading

from fastapi import HTTPException


def create_hub(address, store, server_name):
    bundle = store.server_bundle(server_name)
    directory = tempfile.TemporaryDirectory(prefix='tp-telemetry-tls-')
    paths = {}
    for name in ('certificate','private_key','ca'):
        path = Path(directory.name)/name
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            stream.write(bundle[name])
        paths[name] = str(path)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(paths['certificate'],paths['private_key'])
    context.load_verify_locations(paths['ca'])
    context.verify_mode=ssl.CERT_REQUIRED

    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass

        def do_POST(self):
            self.close_connection=True
            if self.path != '/v1/telemetry':
                self.send_error(404)
                return
            length=self.headers.get('Content-Length','')
            if self.headers.get('Transfer-Encoding') or not length.isascii() or not length.isdigit() or len(length)>5:
                self.send_error(400)
                return
            count=int(length)
            if count>16384:
                self.send_error(413)
                return
            try:
                raw=self.rfile.read(count)
                if len(raw)!=count:
                    raise HTTPException(400,'incomplete telemetry report')
                result=store.accept_report(self.connection.getpeercert(binary_form=True),raw)
                code=200
            except HTTPException as error:
                code, result=error.status_code, {'detail':error.detail}
            except Exception:
                code, result=503, {'detail':'telemetry temporarily unavailable'}
            body=json.dumps(result).encode()
            self.send_response(code)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.end_headers()
            self.wfile.write(body)

    class Hub(ThreadingHTTPServer):
        daemon_threads=True
        address_family=socket.AF_INET6 if ':' in address[0] else socket.AF_INET
        def __init__(self):
            self.slots=threading.BoundedSemaphore(8)
            super().__init__(address, Handler)

        def server_bind(self):
            if self.address_family==socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
            super().server_bind()

        def process_request(self, request, client_address):
            if not self.slots.acquire(False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request,client_address)
            except BaseException:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            channel=request
            try:
                request.settimeout(5)
                channel=context.wrap_socket(request,server_side=True)
                self.finish_request(channel, client_address)
            except (OSError, ValueError):
                pass
            finally:
                self.shutdown_request(channel)
                self.slots.release()

        def server_close(self):
            super().server_close()
            directory.cleanup()
    try:
        return Hub()
    except BaseException:
        directory.cleanup()
        raise


def main():
    import argparse
    from core.agent_identity import AgentIdentityStore
    from core.workspaces import WorkspaceRegistry
    parser=argparse.ArgumentParser(description='Restricted telemetry mTLS hub')
    parser.add_argument('--listen',default='127.0.0.1')
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--server-name',required=True)
    parser.add_argument('--registry',required=True)
    args=parser.parse_args()
    server=create_hub((args.listen,args.port),AgentIdentityStore(WorkspaceRegistry(args.registry)),args.server_name)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__=='__main__': main()
