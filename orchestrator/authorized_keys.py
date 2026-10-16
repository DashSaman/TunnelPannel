"""Small stdlib-only remote helper. Only exact generated public lines are owned."""
import base64
import json
import os
import re
import secrets
import stat
import sys


def managed(line):
    if not re.fullmatch(r'restrict ssh-ed25519 [A-Za-z0-9+/]{68} tp-managed-[0-9a-f]{32}', line or ''):
        raise ValueError('invalid managed public key line')
    if len(base64.b64decode(line.split()[2], validate=True)) != 51:
        raise ValueError('invalid managed public key')


def rewrite(current, add=None, remove=None):
    for line in (add, remove):
        if line:
            managed(line)
    if len(current) > 1024*1024:
        raise ValueError('authorized_keys exceeds managed size bound')
    lines = current.splitlines(keepends=True)
    if remove:
        lines = [line for line in lines if line.rstrip(b'\r\n') != remove.encode()]
    if add and not any(line.rstrip(b'\r\n') == add.encode() for line in lines):
        if any(add.split()[2].encode() in line.split() for line in lines):
            raise ValueError('public key already exists with a different owner or restrictions')
        if lines and not lines[-1].endswith(b'\n'):
            lines.append(b'\n')
        lines.append(add.encode()+b'\n')
    return b''.join(lines)


def update(username, add=None, remove=None):
    import fcntl
    import pwd
    user = pwd.getpwnam(username)
    # Open each component without following links, including the home directory.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open('/', flags)
    try:
        for part in user.pw_dir.strip('/').split('/'):
            next_fd = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        if os.fstat(directory).st_uid != user.pw_uid:
            raise ValueError('SSH home ownership mismatch')
        try:
            os.mkdir('.ssh', 0o700, dir_fd=directory)
            os.chown('.ssh', user.pw_uid, user.pw_gid, dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            pass
        ssh = os.open('.ssh', flags, dir_fd=directory)
        try:
            info = os.fstat(ssh)
            if info.st_uid != user.pw_uid or info.st_mode & 0o022:
                raise ValueError('unsafe SSH directory owner or mode')
            lock = os.open('.tunnelpannel-keys.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=ssh)
            try:
                info = os.fstat(lock)
                if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, user.pw_uid}:
                    raise ValueError('unsafe key lock')
                os.fchown(lock, user.pw_uid, user.pw_gid)
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    target = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ssh)
                except FileNotFoundError:
                    current = b''
                else:
                    with os.fdopen(target, 'rb') as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != user.pw_uid or info.st_mode & 0o022:
                            raise ValueError('unsafe authorized_keys owner or mode')
                        current = stream.read(1024*1024+1)
                result = rewrite(current, add, remove)
                if result != current:
                    name = '.tp-key-'+secrets.token_hex(16)
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=ssh)
                    try:
                        with os.fdopen(fd, 'wb') as stream:
                            os.fchown(stream.fileno(), user.pw_uid, user.pw_gid)
                            stream.write(result)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(name, 'authorized_keys', src_dir_fd=ssh, dst_dir_fd=ssh)
                        os.fsync(ssh)
                    finally:
                        try:
                            os.unlink(name, dir_fd=ssh)
                        except FileNotFoundError:
                            pass
            finally:
                os.close(lock)
        finally:
            os.close(ssh)
    finally:
        os.close(directory)


if __name__ == '__main__':
    update(**json.loads(base64.b64decode(sys.argv[1])))
