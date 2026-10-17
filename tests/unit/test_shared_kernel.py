"""Two logical owners of the same keyless carrier cannot delete each other."""
import json
import os

import pytest

from orchestrator.shared_kernel_runtime import SharedKernel

pytestmark = [pytest.mark.unit_portable, pytest.mark.skipif(os.name=='nt',reason='POSIX flock and ownership')]


class Kernel:
    def __init__(self): self.links, self.addresses, self.routes, self.commands = {}, set(), set(), []
    def __call__(self,args,check=True):
        self.commands.append(args)
        if args==['ip','-j','-d','link','show']: return json.dumps(list(self.links.values()))
        if args[:2]==['ip','-j'] and 'address' in args:
            name=args[-1]
            return json.dumps([{'addr_info':[{'local':address.split('/')[0]} for iface,address in self.addresses if iface==name]}])
        if args[:2]==['ip','-j'] and 'route' in args:
            return json.dumps([{'dev':iface} for iface,peer in self.routes if peer==args[-1]])
        if args[:3]==['ip','link','add']:
            name=args[4];kind=args[args.index('type')+1]
            self.links[name]={'ifname':name,'ifindex':len(self.links)+10,'ifalias':args[args.index('alias')+1],
                'linkinfo':{'info_kind':kind,'info_data':{'local':args[args.index('local')+1],'remote':args[args.index('remote')+1]}}}
        elif args[:3]==['ip','link','del']: self.links.pop(args[3]);self.addresses.clear();self.routes.clear()
        elif args[:3]==['ip','link','set'] and 'alias' in args:
            self.links[args[3]]['ifalias']=args[args.index('alias')+1]
        elif 'address' in args:
            token=(args[args.index('dev')+1],args[args.index('address')+2])
            self.addresses.add(token) if 'replace' in args else self.addresses.discard(token)
        elif 'route' in args:
            token=(args[args.index('dev')+1],args[args.index('route')+2])
            self.routes.add(token) if 'replace' in args else self.routes.discard(token)
        return ''


def params(owner='123-1-IPIP', **changes):
    return {'owner':owner,'kind':'ipip','local':'192.0.2.1','remote':'192.0.2.2',
            'address':'10.246.0.1/30','peer':'10.246.0.2','mtu':1400,**changes}


@pytest.mark.parametrize('kind',['ipip','sit','gre','ip6gre'])
def test_last_owner_alone_deletes_shared_carrier_and_other_owners_keep_addresses(tmp_path,kind):
    kernel=Kernel();manager=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-one')
    outer={'local':'2001:db8::1','remote':'2001:db8::2'} if kind=='ip6gre' else {}
    inner={'address':'fd45:246::1/64','peer':'fd45:246::2'} if kind=='sit' else {}
    first=params(kind=kind,**outer,**inner)
    second=params('124-1-IPIP',kind=kind,**outer,**({'address':'fd45:247::1/64','peer':'fd45:247::2'} if kind=='sit' else {'address':'10.246.0.5/30','peer':'10.246.0.6'}))
    a=manager.attach(first);b=manager.attach(second)
    assert a==b and len(kernel.links)==1
    manager.detach(first['owner'])
    assert len(kernel.links)==1 and (b,second['address']) in kernel.addresses
    manager.attach(first)  # Restarting a stopped member safely rejoins the carrier.
    manager.detach(second['owner'])
    assert len(kernel.links)==1 and (a,first['address']) in kernel.addresses
    manager.detach(first['owner']);manager.detach(first['owner'])
    assert not kernel.links and not list((tmp_path/'shared').glob('*.json'))
    assert not list((tmp_path/'shared'/'refs').glob('*.json'))


def test_foreign_same_endpoint_carrier_is_rejected_before_any_mutation(tmp_path):
    kernel=Kernel()
    kernel.links['foreign']={'ifname':'foreign','ifindex':9,'linkinfo':{'info_kind':'ipip',
        'info_data':{'local':'192.0.2.1','remote':'192.0.2.2'}}}
    manager=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-one')
    with pytest.raises(RuntimeError,match='foreign'):manager.attach(params())
    assert kernel.commands==[['ip','-j','-d','link','show']]
    assert list(kernel.links)==['foreign']


@pytest.mark.parametrize('active',[False,True])
def test_iproute_any_endpoint_is_a_wildcard_and_active_foreign_carriers_block(tmp_path,active):
    kernel=Kernel()
    kernel.links['ip6gre0']={'ifname':'ip6gre0','ifindex':9,'flags':['UP'] if active else [],
        'linkinfo':{'info_kind':'ip6gre','info_data':{'local':'any','remote':'any'}}}
    manager=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-one')
    value=params(kind='ip6gre',local='2001:db8::1',remote='2001:db8::2')
    if active:
        with pytest.raises(RuntimeError,match='foreign'):manager.attach(value)
        assert kernel.commands==[['ip','-j','-d','link','show']]
    else:
        name=manager.attach(value)
        assert name in kernel.links


def test_each_peer_route_selects_its_own_member_source_address(tmp_path):
    kernel=Kernel();manager=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-one')
    first=params();second=params('124-1-IPIP',address='10.246.0.5/30',peer='10.246.0.6')
    manager.attach(first);manager.attach(second)
    routes=[command for command in kernel.commands if command[:4]==['ip','-4','route','replace']]
    assert all('src' in command for command in routes)
    assert [command[command.index('src')+1] for command in routes]==['10.246.0.1','10.246.0.5']


def test_tunnel_driver_that_ignores_alias_during_creation_is_marked_before_verification(tmp_path):
    kernel=Kernel()
    def run(args,check=True):
        result=kernel(args,check=check)
        if args[:3]==['ip','link','add']:kernel.links[args[4]].pop('ifalias',None)
        return result
    manager=SharedKernel(tmp_path/'shared',run=run,boot='boot-one')
    name=manager.attach(params())
    assert kernel.links[name]['ifalias'].startswith('TunnelPannel:')
    manager.detach(params()['owner']);assert name not in kernel.links


def test_a_replaced_interface_is_never_deleted_by_old_owner_cleanup(tmp_path):
    kernel=Kernel();manager=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-one')
    name=manager.attach(params())
    kernel.links[name]['ifalias']='operator-replacement'
    with pytest.raises(RuntimeError,match='ownership'):manager.detach(params()['owner'])
    assert name in kernel.links and list((tmp_path/'shared'/'refs').glob('*.json'))


def test_reboot_rebuilds_once_and_does_not_count_unstarted_stale_owners(tmp_path):
    kernel=Kernel();manager=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-one')
    first=params();second=params('124-1-IPIP',address='10.246.0.5/30',peer='10.246.0.6')
    manager.attach(first);manager.attach(second)
    kernel.links.clear();kernel.addresses.clear();kernel.routes.clear()
    restarted=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-two')
    name=restarted.attach(second)
    restarted.detach(first['owner'])
    assert name in kernel.links and (name,second['address']) in kernel.addresses
    restarted.detach(second['owner']);assert not kernel.links


def test_corrupt_shared_book_blocks_allocation_without_deleting_foreign_state(tmp_path):
    kernel=Kernel();manager=SharedKernel(tmp_path/'shared',run=kernel,boot='boot-one')
    name=manager.attach(params())
    book=next((tmp_path/'shared').glob('*.json'));book.write_text('{')
    with pytest.raises(ValueError):manager.detach(params()['owner'])
    assert name in kernel.links
