"""Allocate owned policy tables without changing or flushing existing tables."""
import json


def _rules(remote):
    return json.loads(remote.run('ip -j rule show', root=True)['stdout'])


def free_priority(remote):
    used = {int(row['priority']) for row in _rules(remote) if 'priority' in row}
    return next(value for value in range(10000, 20000) if value not in used)


def free_table(remote, start):
    used = set()
    aliases = remote.run('cat /etc/iproute2/rt_tables /etc/iproute2/rt_tables.d/* 2>/dev/null || true')['stdout']
    mapping = {parts[1]: int(parts[0]) for line in aliases.splitlines()
               if len(parts := line.split()) >= 2 and parts[0].isdigit()}
    for row in _rules(remote):
        for key in ('table', 'fwmark'):
            value = row.get(key)
            if value is not None:
                try:
                    used.add(int(str(value), 0))
                except ValueError:
                    if str(value) in mapping:
                        used.add(mapping[str(value)])
    for table in range(start, min(start + 1000, 65535)):
        if table in used:
            continue
        result = remote.run(f'ip -j route show table {table}', root=True, check=False)
        if result['code']:
            # iproute2 writes an incomplete '[' for a nonexistent FIB table.
            if 'FIB table does not exist' in result['stderr']:
                return table
            raise RuntimeError('cannot inspect policy table: ' + result['stderr'])
        if not json.loads(result['stdout'] or '[]'):
            return table
    raise RuntimeError('no unoccupied policy routing table')
