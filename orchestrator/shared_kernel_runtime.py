"""Standalone, host-locked ownership of a keyless L3 carrier and its members.

Linux selects incoming unkeyed packets by outer endpoints. Logical members
therefore share one proven-owned carrier, each with its own inner address,
peer route and systemd unit. The last member alone removes the carrier.
"""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

DIRECTORY = '/var/lib/tunnelpannel-shared-carriers'


def normalized(value):
    if set(value) != {'owner','kind','local','remote','address','peer','mtu'}:
        raise ValueError('invalid shared carrier fields')
    result=dict(value)
    if not re.fullmatch(r'[0-9]+-[0-9]+-[A-Z0-9_]+',result['owner']):
        raise ValueError('invalid shared carrier owner')
    if result['kind'] not in {'gre','ip6gre','sit','ipip'}:
        raise ValueError('unsupported shared carrier')
    for key in ('local','remote','peer'):result[key]=str(ipaddress.ip_address(result[key]))
    result['address']=str(ipaddress.ip_interface(result['address']))
    outer=6 if result['kind']=='ip6gre' else 4
    if any(ipaddress.ip_address(result[key]).version!=outer for key in ('local','remote')):
        raise ValueError('invalid outer address family')
    address=ipaddress.ip_interface(result['address'])
    peer=ipaddress.ip_address(result['peer'])
    if peer.version!=address.version or peer not in address.network or peer==address.ip:
        raise ValueError('invalid shared peer prefix')
    if result['kind']=='sit' and address.version!=6:raise ValueError('SIT needs IPv6 inside')
    if type(result['mtu']) is not int or not 1280<=result['mtu']<=1480:
        raise ValueError('invalid shared MTU')
    return result


def carrier_identity(value):
    source=json.dumps([value['kind'],*sorted([value['local'],value['remote']])],separators=(',',':'))
    return hashlib.sha256(source.encode()).hexdigest()[:12]


class SharedKernel:
    def __init__(self,directory=DIRECTORY,*,run=None,boot=None):
        self.directory=Path(directory)
        self.run=run or self.command
        self.boot=boot or Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    @staticmethod
    def command(args,check=True):
        result=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if check and result.returncode:raise RuntimeError((result.stderr or result.stdout)[-1500:])
        return result.stdout

    @staticmethod
    def safe(path):
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022:
            raise RuntimeError('unsafe shared carrier path')

    def read(self,path):
        self.safe(path)
        return json.loads(path.read_text())

    def write(self,path,value):
        if path.exists() or path.is_symlink():self.safe(path)
        fd,temporary=tempfile.mkstemp(dir=path.parent,prefix=path.name+'.',suffix='.tmp')
        try:
            with os.fdopen(fd,'w') as out:
                os.chmod(temporary,0o600);json.dump(value,out);out.flush();os.fsync(out.fileno())
            os.replace(temporary,path)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)

    @staticmethod
    def validate_book(book,identity,value):
        if (book.get('identity')!=identity or not isinstance(book.get('owners'),dict) or
                not isinstance(book.get('boot'),str) or
                any(book.get(key)!=value[key] for key in ('kind','local','remote')) or
                (book.get('ifindex') is not None and (type(book['ifindex']) is not int or book['ifindex']<=0))):
            raise RuntimeError('invalid shared carrier ownership book')
        for owner,member in book['owners'].items():
            member=normalized(member)
            if owner!=member['owner'] or carrier_identity(member)!=identity:
                raise RuntimeError('invalid shared carrier member')

    @contextmanager
    def locked(self):
        import fcntl
        for path in (self.directory,self.directory/'refs'):
            if path.exists() or path.is_symlink():self.safe(path)
            else:path.mkdir(mode=0o700,parents=True)
            if not path.is_dir():raise RuntimeError('invalid shared carrier directory')
        path=self.directory/'controller.lock'
        if path.exists() or path.is_symlink():self.safe(path)
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield
        finally:os.close(fd)

    @staticmethod
    def verify_link(link,book):
        if (link.get('ifalias')!='TunnelPannel:'+book['identity'] or
                link.get('linkinfo',{}).get('info_kind')!=book['kind'] or
                (book.get('ifindex') is not None and link['ifindex']!=book['ifindex'])):
            raise RuntimeError('shared carrier ownership mismatch')
        data=link['linkinfo'].get('info_data',{})
        if any(str(ipaddress.ip_address(data.get(key,'0.0.0.0')))!=book[key] for key in ('local','remote')):
            raise RuntimeError('shared carrier endpoint ownership mismatch')

    def attach(self,value):
        value=normalized(value)
        identity=carrier_identity(value);name='tps'+identity
        book_path=self.directory/(identity+'.json')
        ref_path=self.directory/'refs'/(value['owner']+'.json')
        with self.locked():
            links=json.loads(self.run(['ip','-j','-d','link','show']))
            current=next((link for link in links if link['ifname']==name),None)
            old=self.read(book_path) if book_path.exists() or book_path.is_symlink() else None
            if old:self.validate_book(old,identity,value)
            if old and old['boot']==self.boot:
                book=old
                if current:self.verify_link(current,book)
                elif book['owners']:raise RuntimeError('owned shared carrier unexpectedly disappeared')
            else:
                if current:raise RuntimeError('foreign shared carrier interface exists')
                book={'identity':identity,'kind':value['kind'],'local':value['local'],'remote':value['remote'],
                      'boot':self.boot,'ifindex':None,'owners':{}}
            for link in links:
                if link['ifname']==name:continue
                info=link.get('linkinfo',{})
                if info.get('info_kind')!=value['kind']:continue
                data=info.get('info_data',{})
                wildcard='::' if value['kind']=='ip6gre' else '0.0.0.0'
                local=str(ipaddress.ip_address(wildcard if data.get('local','any')=='any' else data['local']))
                remote=str(ipaddress.ip_address(wildcard if data.get('remote','any')=='any' else data['remote']))
                if local==value['local'] and remote==value['remote'] or (
                    'UP' in link.get('flags',[]) and local in {wildcard,value['local']} and remote in {wildcard,value['remote']}):
                    raise RuntimeError('foreign carrier matches the same outer endpoints')
            if ref_path.exists() or ref_path.is_symlink():
                previous=self.read(ref_path)
                if previous['value']!=value:raise RuntimeError('shared member identity already owns different addresses')
            if value['owner'] in book['owners'] and book['owners'][value['owner']]!=value:
                raise RuntimeError('shared member identity collision')
            self.write(ref_path,{'identity':identity,'boot':self.boot,'value':value})
            book['owners'][value['owner']]=value
            self.write(book_path,book)  # Persist intent before any kernel mutation.
            if not current:
                self.run(['ip','link','add','name',name,'alias','TunnelPannel:'+identity,
                          'type',value['kind'],'local',value['local'],'remote',value['remote']])
                # Tunnel-specific iproute drivers can ignore alias on creation.
                # This command succeeded under our lock; mark that new link explicitly.
                self.run(['ip','link','set',name,'alias','TunnelPannel:'+identity])
                current=next(link for link in json.loads(self.run(['ip','-j','-d','link','show'])) if link['ifname']==name)
                self.verify_link(current,book)
                book['ifindex']=current['ifindex'];self.write(book_path,book)
            self.run(['ip','link','set',name,'mtu',str(min(member['mtu'] for member in book['owners'].values())),'up'])
            family='-6' if ipaddress.ip_interface(value['address']).version==6 else '-4'
            self.run(['ip',family,'address','replace',value['address'],'dev',name])
            peer=value['peer']+('/128' if family=='-6' else '/32')
            self.run(['ip',family,'route','replace',peer,'dev',name,'scope','link',
                      'src',str(ipaddress.ip_interface(value['address']).ip)])
        return name

    def detach(self,owner):
        if not re.fullmatch(r'[0-9]+-[0-9]+-[A-Z0-9_]+',owner):raise ValueError('invalid shared owner')
        with self.locked():
            ref_path=self.directory/'refs'/(owner+'.json')
            if not ref_path.exists() and not ref_path.is_symlink():return
            reference=self.read(ref_path);value=normalized(reference['value'])
            identity=carrier_identity(value)
            if value['owner']!=owner or reference['identity']!=identity:raise RuntimeError('invalid shared reference')
            name='tps'+identity;book_path=self.directory/(identity+'.json')
            links=json.loads(self.run(['ip','-j','-d','link','show']))
            current=next((link for link in links if link['ifname']==name),None)
            book=self.read(book_path) if book_path.exists() or book_path.is_symlink() else None
            if book:self.validate_book(book,identity,value)
            if not book:
                if current:raise RuntimeError('shared carrier ownership book missing')
                ref_path.unlink();return
            if book['boot']==self.boot and owner in book['owners']:
                if current:
                    self.verify_link(current,book)
                    family='-6' if ipaddress.ip_interface(value['address']).version==6 else '-4'
                    peer=value['peer']+('/128' if family=='-6' else '/32')
                    self.run(['ip',family,'route','del',peer,'dev',name],check=False)
                    self.run(['ip',family,'address','del',value['address'],'dev',name],check=False)
                    addresses=json.loads(self.run(['ip','-j',family,'address','show','dev',name]))
                    if any(str(ipaddress.ip_address(item['local']))==str(ipaddress.ip_interface(value['address']).ip)
                           for link in addresses for item in link.get('addr_info',[])):
                        raise RuntimeError('shared member address survived cleanup')
                    routes=json.loads(self.run(['ip','-j',family,'route','show','exact',peer]))
                    if any(route.get('dev')==name for route in routes):
                        raise RuntimeError('shared member peer route survived cleanup')
                del book['owners'][owner]
            elif book['boot']!=self.boot:
                if current:raise RuntimeError('foreign carrier after host reboot')
                book['owners'].pop(owner,None)
            if not book['owners']:
                if current:
                    self.run(['ip','link','del',name])
                    if any(link['ifname']==name for link in json.loads(self.run(['ip','-j','-d','link','show']))):
                        raise RuntimeError('shared carrier survived last-member cleanup')
                book_path.unlink()
            else:self.write(book_path,book)
            ref_path.unlink()
