"""Canonical shared L3 carrier adapter; each logical member owns only its ref."""
import base64
import json
from pathlib import Path
import shlex

from orchestrator.shared_kernel_runtime import carrier_identity


METHODS={'GRE':'gre','IP6GRE':'ip6gre','IPIP':'ipip','SIT_6IN4':'sit'}


def remote_script(action,value):
    if action not in {'attach','detach'}:raise ValueError('invalid shared carrier operation')
    source=Path(__file__).resolve().parents[1].joinpath('orchestrator/shared_kernel_runtime.py').read_text()
    payload=base64.b64encode(source.encode()).decode()
    invocation='import base64;exec(base64.b64decode('+repr(payload)+'));SharedKernel().'+action+'('+repr(value)+')'
    return 'python3 -c '+shlex.quote(invocation)


def deploy(method,run,item,config,a,b,addressing):
    from plan_executor import executor as bodies
    from orchestrator.owned_firewall import allow_interface,allow_protocol
    name=bodies.unit_name(run['id'],item['id'])
    owner=f"{run['id']}-{item['id']}-{method}"
    ceiling=1480 if method=='SIT_6IN4' else 1400
    mtu=min(int(config.get('mtu') or ceiling),ceiling)
    names=[]
    for remote,side,peer in ((a,'a','b'),(b,'b','a')):
        values={'owner':owner,'kind':METHODS[method],'local':str(addressing['source_'+side]),
                'remote':str(addressing['source_'+peer]),'address':str(addressing['address_'+side]),
                'peer':str(addressing['address_'+peer].ip),'mtu':mtu}
        interface='tps'+carrier_identity(values);names.append(interface)
        remote.journal.record('shared_kernel_ref',owner)
        allow_protocol(remote,addressing['source_'+peer],47 if method in {'GRE','IP6GRE'} else 41 if method=='SIT_6IN4' else 4)
        allow_interface(remote,interface,str(addressing['address_'+peer].ip))
        bodies.oneshot_service(remote,name,remote_script('attach',values),remote_script('detach',owner))
    a.run(bodies.ping_command(addressing['address_b'].ip),root=True,timeout=30)
    b.run(bodies.ping_command(addressing['address_a'].ip),root=True,timeout=30)
    return {'method':method,'interface_name':names[0], 'interface_names':names,
            'shared_kernel':True,'shared_kernel_owner':owner,'systemd_unit':name,
            'services_a':[name],'services_b':[name],'interfaces_a':[],'interfaces_b':[],
            'source_ip_a':str(addressing['source_a']),
            'source_ip_b':str(addressing['source_b']),'tunnel_cidr':str(addressing['network']),
            'tunnel_ip_a':str(addressing['address_a']),'tunnel_ip_b':str(addressing['address_b']),
            'mtu':mtu,'vxlan_vni':None,'vxlan_port':None}


def inspect_refs(remote,owner):
    """Diagnostic only: never returns credentials or claims the shared device."""
    path='/var/lib/tunnelpannel-shared-carriers/refs/'+owner+'.json'
    return json.loads(remote.run('cat '+shlex.quote(path),root=True)['stdout'])
