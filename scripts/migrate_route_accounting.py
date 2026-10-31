"""Run as the controller installation owner/root with its private environment.

Requires fresh operator backups and exact live route/PID/config digest. This is
intentionally a privileged CLI; a customer cannot grant legacy entitlement.
"""
import argparse
import json
import os
from pathlib import Path
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',required=True)
    parser.add_argument('--route',required=True)
    parser.add_argument('--expected-pid',required=True,type=int)
    parser.add_argument('--expected-config-sha256',required=True)
    parser.add_argument('--rescue-base',required=True)
    args=parser.parse_args()
    if hasattr(os,'geteuid') and os.geteuid()!=0:parser.error('run on controller as root with its installation environment')
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from apps.api.main import app
    from orchestrator.accounting_migration import migrate
    try:
        report=migrate(app.state.mesh_routes.monthly,args.workspace,args.route,
            expected_config_sha256=args.expected_config_sha256,expected_pid=args.expected_pid,rescue_base=args.rescue_base)
    except Exception as error:
        print(json.dumps({'status':'INCOMPLETE','error_type':type(error).__name__,
                          'action':'Inspect private migration intent and resident source receipt; resume before ordinary edits.'}))
        raise SystemExit(1) from None
    print(json.dumps(report))


if __name__=='__main__':main()
