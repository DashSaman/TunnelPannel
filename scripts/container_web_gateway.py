#!/usr/bin/env python3
"""Package a static web-only container; controller and keys remain off-container."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


def package(source, output, prefix, origin, port, upstream_port, image):
    if not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)+',prefix):
        raise ValueError('invalid application prefix')
    parsed=urlsplit(origin)
    if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment
            or not re.fullmatch(r'[a-z0-9.-]+(?::[0-9]+)?',parsed.netloc)):
        raise ValueError('a canonical HTTPS origin without a path is required')
    if any(type(p) is not int or not 1024<=p<=65535 for p in (port,upstream_port)) or port==upstream_port:
        raise ValueError('two distinct unprivileged loopback ports required')
    if not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}',image):
        raise ValueError('container image must be digest-pinned')
    source,output=Path(source),Path(output)
    output.mkdir(parents=True,exist_ok=False)
    public=output/'public';assets=public/'assets';assets.mkdir(parents=True)
    frontend=source/'apps/web'
    for name in ['auth.js','portal.js','portal.css']:
        (assets/name).write_bytes((frontend/name).read_bytes())
    for page in ['portal','mesh','ranking','topology']:
        body=(frontend/(page+'.html')).read_text(encoding='utf8')
        for tag,extension in [('script','js'),('style','css')]:
            index=0
            def external(match):
                nonlocal index
                name=f'{page}-inline-{index}.{extension}';index+=1
                (assets/name).write_text(match.group(1),encoding='utf8')
                return (f'<script src="{prefix}/assets/{name}"></script>' if tag=='script'
                        else f'<link rel="stylesheet" href="{prefix}/assets/{name}">')
            body=re.sub(r'<'+tag+r'\s*>(.*?)</'+tag+r'>',external,body,flags=re.S)
        body=re.sub(r'\b(href|src)="/(?!/|'+re.escape(prefix.lstrip('/'))+r'/)',lambda m:m[1]+'="'+prefix+'/',body)
        (public/(page+'.html')).write_text(body,encoding='utf8')
    locations='\n'.join(f'        location = {prefix}/{p} {{ try_files /{p}.html =404; }}' for p in ['portal','mesh','ranking','topology'])
    nginx=f'''worker_processes 1;
pid /tmp/nginx.pid;
error_log stderr warn;
events {{ worker_connections 256; }}
http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    client_body_temp_path /tmp/client;
    proxy_temp_path /tmp/proxy;
    server {{
        listen 127.0.0.1:{port};
        server_name {parsed.hostname};
        if ($host != "{parsed.hostname}") {{ return 421; }}
        if ($http_x_forwarded_proto != "https") {{ return 403; }}
        root /usr/share/nginx/html;
        client_max_body_size 64k;
        add_header Cache-Control "no-store" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Robots-Tag "noindex, nofollow" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
        location = {prefix} {{ return 308 {prefix}/; }}
        location = {prefix}/ {{ try_files /portal.html =404; }}
{locations}
        location ^~ {prefix}/assets/ {{ alias /usr/share/nginx/html/assets/; }}
        location / {{ return 404; }}
        location {prefix}/ {{
            rewrite ^{prefix}/(.*)$ /$1 break;
            proxy_pass http://127.0.0.1:{upstream_port};
            proxy_http_version 1.1;
            proxy_set_header Host {parsed.netloc};
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $http_x_forwarded_for;
            proxy_set_header Connection "";
            proxy_cookie_path / {prefix}/;
            proxy_cookie_flags tp_session secure httponly samesite=strict;
            proxy_redirect ~^https?://{re.escape(parsed.netloc)}/(.*)$ {prefix}/$1;
            proxy_hide_header Cache-Control;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_read_timeout 180s;
        }}
    }}
}}
'''
    (output/'nginx.conf').write_text(nginx,encoding='utf8')
    health=f"wget -qO- --header='Host: {parsed.hostname}' --header='X-Forwarded-Proto: https' http://127.0.0.1:{port}{prefix}/health | grep -q 'true'"
    compose=f'''services:
  web:
    image: {image}
    container_name: tunnelpannel-tehnet-web
    network_mode: host
    user: "101:101"
    entrypoint: [nginx]
    command: ["-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 32
    mem_limit: 96m
    cpus: 0.20
    restart: unless-stopped
    tmpfs: ["/tmp:rw,noexec,nosuid,size=16m,uid=101,gid=101"]
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./public:/usr/share/nginx/html:ro
    labels:
      io.tunnelpannel.component: website-gateway
    healthcheck:
      test: [CMD-SHELL, {json.dumps(health)}]
      interval: 30s
      timeout: 10s
      retries: 3
'''
    (output/'compose.yaml').write_text(compose,encoding='utf8')
    host=f'''location = {prefix} {{ return 308 {prefix}/; }}
location ^~ {prefix}/ {{
    if ($host != "{parsed.hostname}") {{ return 308 {origin}$request_uri; }}
    access_log off;
    error_log /dev/null crit;
    proxy_pass http://127.0.0.1:{port};
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Connection "";
    proxy_cache off;
    proxy_no_cache 1;
    proxy_buffering off;
    proxy_request_buffering off;
    client_max_body_size 64k;
    proxy_read_timeout 180s;
}}
'''
    (output/'host-location.conf').write_text(host,encoding='utf8')
    manifest={'prefix':prefix,'origin':origin,'port':port,'upstream_port':upstream_port,'image':image,
              'controller_on_gateway':False,'files':{str(p.relative_to(output)):hashlib.sha256(p.read_bytes()).hexdigest() for p in output.rglob('*') if p.is_file()}}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--prefix',default='/tunnels')
    parser.add_argument('--origin',required=True)
    parser.add_argument('--port',required=True,type=int)
    parser.add_argument('--upstream-port',required=True,type=int)
    parser.add_argument('--image',required=True)
    args=parser.parse_args()
    print(json.dumps(package(Path(__file__).resolve().parents[1],args.output,args.prefix,args.origin,args.port,args.upstream_port,args.image),indent=2))
