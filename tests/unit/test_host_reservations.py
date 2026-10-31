"""Stopped warm members retain their host-global allocations until cleanup."""
import contextlib
import io
import json
import os

import pytest

from orchestrator import host_reservations as books

pytestmark = [pytest.mark.unit_portable, pytest.mark.skipif(os.name == 'nt',
    reason='managed-host POSIX ownership and permission checks require Linux')]


class LocalRemote:
    def run(self, command, **kwargs):
        script = command.split("\n", 1)[1].rsplit("\nTP_RESERVATIONS", 1)[0]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(script, '<remote-reservations>', 'exec'), {})
        return {'code': 0, 'stdout': output.getvalue(), 'stderr': ''}


class Journal:
    def __init__(self): self.paths = []
    def record(self, kind, path):
        assert kind == 'path'
        self.paths.append(path)


def test_stopped_allocations_survive_new_remote_connections_and_owned_cleanup(tmp_path):
    directory = tmp_path / 'books'
    first, second = LocalRemote(), LocalRemote()
    one, two = Journal(), Journal()
    books.initialize(first, one, 123, 1, directory=directory)
    books.reserve(first, 'ports', 22000)
    books.reserve(first, 'prefixes', '10.246.0.0/30')
    books.reserve(first, 'identifiers', 123456789)
    books.reserve(first, 'interfaces', 'tun123456')
    books.initialize(second, two, 124, 1, directory=directory)
    assert second.reserved_ports == {22000}
    assert second.reserved_prefixes == {'10.246.0.0/30'}
    assert second.reserved_identifiers == {123456789}
    assert second.reserved_interfaces == {'tun123456'}
    books.reserve(second, 'ports', 22001)
    from pathlib import Path
    Path(one.paths[0]).unlink()  # Existing journal cleanup deletes exactly this deployment's book.
    third = LocalRemote()
    books.initialize(third, Journal(), 125, 1, directory=directory)
    assert third.reserved_ports == {22001}
    assert Path(two.paths[0]).exists()
    assert not list(directory.glob('*.tmp'))


@pytest.mark.parametrize('damage', ['broken-json', 'bad-port', 'foreign-link'])
def test_corrupt_or_symlinked_books_fail_closed_before_claiming_own_path(tmp_path, damage):
    directory = tmp_path / 'books'
    directory.mkdir(mode=0o700)
    path = directory / 'tp-123-1.json'
    if damage == 'broken-json':
        path.write_text('{')
    elif damage == 'bad-port':
        path.write_text(json.dumps({'ports': [70000], 'prefixes': [], 'identifiers': [], 'interfaces': []}))
    else:
        target = tmp_path / 'foreign.json'
        target.write_text('{}')
        try: path.symlink_to(target)
        except OSError: pytest.skip('symlinks unavailable')
    journal = Journal()
    with pytest.raises((RuntimeError, ValueError)):
        books.initialize(LocalRemote(), journal, 124, 1, directory=directory)
    assert not journal.paths


def test_existing_own_book_is_never_adopted_or_deleted(tmp_path):
    remote, journal = LocalRemote(), Journal()
    books.initialize(remote, journal, 123, 1, directory=tmp_path / 'books')
    other = Journal()
    with pytest.raises(RuntimeError, match='already exists'):
        books.initialize(LocalRemote(), other, 123, 1, directory=tmp_path / 'books')
    assert not other.paths
