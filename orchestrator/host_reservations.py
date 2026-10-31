"""Durable warm-resource reservations; callers hold the physical host lease.

Books are root-owned on the managed host, outside the panel data directory.
The existing deployment journal removes only its own book after stopping units.
This coordinates workspaces in one installation, not independent controllers.
"""
import json


DIRECTORY = '/var/lib/tunnelpannel-engine-reservations'
FIELDS = ('ports', 'prefixes', 'identifiers', 'interfaces')


def _script(remote, body, **values):
    prelude = '''import ipaddress,json,os,re,stat,tempfile
from pathlib import Path
def validate(value):
 if not isinstance(value,dict) or set(value)!=set(('ports','prefixes','identifiers','interfaces')):
  raise RuntimeError('invalid reservation book')
 for key,items in value.items():
  if not isinstance(items,list): raise RuntimeError('invalid reservation list')
  for item in items:
   if key in ('ports','identifiers'):
    if type(item) is not int or not 0<item<(65536 if key=='ports' else 2**31): raise RuntimeError('invalid reserved number')
   elif key=='prefixes': ipaddress.ip_network(item)
   elif not isinstance(item,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',item): raise RuntimeError('invalid interface')
 return value
def safe(path):
 info=path.lstat()
 if stat.S_ISLNK(info.st_mode) or info.st_uid!=getattr(os,'geteuid',lambda:0)() or info.st_mode & 0o022:
  raise RuntimeError('unsafe reservation path')
def write(path,value,exclusive=False):
 validate(value)
 if exclusive:
  with path.open('x') as out:
   os.chmod(path,0o600);json.dump(value,out);out.flush();os.fsync(out.fileno())
 else:
  safe(path)
  fd,temp=tempfile.mkstemp(prefix=path.name+'.',suffix='.tmp',dir=path.parent)
  try:
   with os.fdopen(fd,'w') as out:
    os.chmod(temp,0o600);json.dump(value,out);out.flush();os.fsync(out.fileno())
   os.replace(temp,path)
  finally:
   if os.path.exists(temp): os.unlink(temp)
'''
    source = prelude + '\nargs=json.loads(' + repr(json.dumps(values)) + ')\n' + body
    return json.loads(remote.run("python3 - <<'TP_RESERVATIONS'\n" + source + '\nTP_RESERVATIONS',
                                 root=True)['stdout'])


def initialize(remote, journal, run_id, item_id, *, directory=DIRECTORY):
    if not all(type(value) is int and value >= 0 for value in (run_id, item_id)):
        raise ValueError('invalid reservation owner')
    directory = str(directory)
    path = directory + f'/tp-{run_id}-{item_id}.json'
    occupied = _script(remote, '''directory=Path(args['directory'])
if directory.exists() or directory.is_symlink(): safe(directory)
else: directory.mkdir(mode=0o700,parents=True)
if not directory.is_dir(): raise RuntimeError('reservation directory unavailable')
own=Path(args['path'])
if own.exists() or own.is_symlink(): raise RuntimeError('reservation book already exists')
result={key:[] for key in ('ports','prefixes','identifiers','interfaces')}
for path in directory.glob('tp-*.json'):
 safe(path)
 value=validate(json.loads(path.read_text()))
 for key in result: result[key].extend(value[key])
print(json.dumps(result))
''', directory=directory, path=path)
    # Persist ownership before creating the file, so a disconnect is recoverable.
    journal.record('path', path)
    empty = {field: [] for field in FIELDS}
    _script(remote, "write(Path(args['path']),args['value'],exclusive=True)\nprint('{}')\n",
            path=path, value=empty)
    remote.reservation_book = path
    remote.reservation_owned = empty
    for field in FIELDS:
        setattr(remote, 'reserved_' + field, set(occupied[field]))


def reserve(remote, field, value):
    """Keep compatibility for standalone legacy engine callers without journals."""
    bucket = getattr(remote, 'reserved_' + field, set())
    bucket.add(value)
    setattr(remote, 'reserved_' + field, bucket)
    if not getattr(remote, 'reservation_book', None):
        return
    owned = {key: list(items) for key, items in remote.reservation_owned.items()}
    if value not in owned[field]:
        owned[field].append(value)
        _script(remote, "write(Path(args['path']),args['value'])\nprint('{}')\n",
                path=remote.reservation_book, value=owned)
        remote.reservation_owned = owned


def free_tun_id(remotes, preferred):
    occupied = set().union(*(getattr(remote, 'reserved_interfaces', set()) for remote in remotes))
    for remote in remotes:
        occupied.update(row['ifname'] for row in json.loads(remote.run('ip -j link show')['stdout']))
    for offset in range(800000):
        value = 100000 + (preferred - 100000 + offset) % 800000
        if not {'tun' + str(value), 'tap' + str(value)} & occupied:
            return value
    raise RuntimeError('no free SSH tunnel interface pair')
