"""Unprivileged push-only client; reads fixed proc files and accepts no commands."""
import argparse
import json
import os
from pathlib import Path
import platform
import ssl
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


def collect(sequence):
    memory={}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key,_,value=line.partition(':')
        if key in {'MemTotal','MemAvailable'}:
            memory[key]=int(value.split()[0])*1024
    return {'version':1,'sequence':sequence,'sent_at':time.time(),'os':'linux',
        'arch':{'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),platform.machine()),
        'uptime_s':float(Path('/proc/uptime').read_text().split()[0]),'load1':float(os.getloadavg()[0]),
        'memory_total_bytes':memory['MemTotal'],'memory_available_bytes':memory['MemAvailable']}


def send(bundle, report, url=None):
    target=url or bundle.get('hub_url') or ''
    parsed=urlsplit(target)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('a verified HTTPS hub origin is required')
    with tempfile.TemporaryDirectory(prefix='tp-agent-') as directory:
        paths={}
        for name in ('certificate','private_key','ca'):
            path=Path(directory)/name
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                stream.write(bundle[name])
            paths[name]=str(path)
        context=ssl.create_default_context(cafile=paths['ca'])
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(paths['certificate'],paths['private_key'])
        request=Request(target.rstrip('/')+'/v1/telemetry',data=json.dumps(report,allow_nan=False).encode(),
                        headers={'Content-Type':'application/json'}, method='POST')
        # No environment proxy can receive the client key or steer telemetry.
        opener=build_opener(ProxyHandler({}),HTTPSHandler(context=context))
        with opener.open(request,timeout=10) as response:
            return json.loads(response.read(1024))


def main():
    parser=argparse.ArgumentParser(description='Restricted telemetry client')
    parser.add_argument('--bundle',required=True)
    parser.add_argument('--hub')
    parser.add_argument('--once',action='store_true')
    parser.add_argument('--interval',type=int,default=60)
    args=parser.parse_args()
    if not 30 <= args.interval <= 3600:
        parser.error('interval must be30..3600 seconds')
    bundle=json.loads(Path(args.bundle).read_text())
    sequence=time.time_ns()
    while True:
        sequence=max(sequence+1,time.time_ns())
        try:
            send(bundle,collect(sequence),args.hub)
            if args.once:
                return
        except Exception:
            if args.once:
                raise SystemExit('telemetry rejected or unavailable; no credentials logged') from None
            print('telemetry unavailable; retrying',flush=True)
        time.sleep(args.interval)


if __name__=='__main__': main()
