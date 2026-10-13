def test_empty_pretty_json_is_free_and_existing_routes_are_preserved():
    from orchestrator.route_allocation import free_table
    class Remote:
        def run(self, command, **kwargs):
            if command == 'ip -j rule show':
                output = '[{"table":30000}, {"fwmark":"0x7531","table":42}]'
            elif command.endswith('30002'):
                output = '[{"dst":"10.1.0.0/16"}]'
            elif 'route show' in command:
                output = '[\n]\n'
            else:
                output = ''
            return {'code': 0, 'stdout': output, 'stderr': ''}
    assert free_table(Remote(), 30000) == 30003


def test_nonexistent_table_with_incomplete_json_is_free():
    from orchestrator.route_allocation import free_table, free_priority
    class Remote:
        def run(self, command, **kwargs):
            if command == 'ip -j rule show':
                return {'code': 0, 'stdout': '[{"priority":10000,"table":"main"}]', 'stderr': ''}
            if 'route show' in command:
                return {'code': 2, 'stdout': '[', 'stderr': 'Error: ipv4: FIB table does not exist.\nDump terminated'}
            return {'code': 0, 'stdout': '', 'stderr': ''}
    assert free_table(Remote(), 55000) == 55000
    assert free_priority(Remote()) == 10001
