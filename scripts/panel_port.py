#!/usr/bin/env python3
"""Installer entry-port preflight; standard library only, no config writes."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deploy.engine.mtf import portmgr
from orchestrator.host_inventory import collect, require_safe

PROC = Path('/proc')


def main_pid():
    result = subprocess.run(['systemctl','show','tunnelpannel-api','-p','MainPID','--value'],
                            capture_output=True,text=True,timeout=10)
    return int(result.stdout.strip()) if result.returncode == 0 else 0


def owned_listener(port):
    """Every TCP LISTEN inode at this numerical port must belong to our unit PID."""
    try:
        pid = main_pid()
        if pid <= 0:
            return False
        process = PROC/str(pid)
        if not any(row.rpartition(':')[2].rstrip().endswith('/tunnelpannel-api.service')
                   for row in (process/'cgroup').read_text().splitlines()):
            return False
        sockets = {str(fd.readlink()) for fd in (process/'fd').iterdir()}
        inodes = set()
        for family in ('tcp','tcp6'):
            for line in (PROC/'net'/family).read_text().splitlines()[1:]:
                parts = line.split()
                if int(parts[1].rpartition(':')[2],16)==port and parts[3]=='0A':
                    inodes.add('socket:['+parts[9]+']')
        return bool(inodes) and inodes <= sockets
    except (OSError,ValueError,IndexError,subprocess.SubprocessError):
        return False


def select(report, port, strict):
    require_safe(report,'')
    if not 1024 <= port <= 65535:
        raise ValueError('panel port must be in 1024..65535')
    rows = [r for r in report.get('listeners',[]) if r['proto']=='TCP' and r['port']==port]
    reserved = any(lo <= port <= hi for lo,hi in report.get('reserved_ranges',{}).get('TCP',[]))
    if not reserved and (not rows or (not any(r.get('source')=='container' for r in rows)
                                     and owned_listener(port))):
        return port
    if strict:
        raise RuntimeError('selected panel port occupied or reserved; existing service preserved; choose TUNNELPANNEL_PORT')
    selected = portmgr.free_port({'sides':{'panel-local':report}},'tcp',['panel-local'])
    if not selected:
        raise RuntimeError('no free panel port in canonical allocation range')
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--strict',choices=['0','1'],required=True)
    parser.add_argument('--verify-owned',action='store_true')
    args = parser.parse_args()
    try:
        if args.verify_owned:
            if not owned_listener(args.port):
                raise RuntimeError('panel listener is not owned by the active API unit')
            print(args.port)
        else:
            print(select(collect(ports_only=True),args.port,args.strict=='1'))
    except Exception as error:
        # All error messages here are fixed text; no external stderr is returned.
        print('Panel port preflight failed: '+str(error),file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
