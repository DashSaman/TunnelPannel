"""Invite-only accounts and revocable sessions in the backed-up private registry."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import re
import secrets
import sqlite3
import struct
import time
import uuid

from fastapi import HTTPException

from orchestrator.remote_nodes import decrypt_credentials, encrypt_credentials

SESSION_SECONDS = 43200
IDLE_SECONDS = 1800


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise HTTPException(400, 'password must contain12 to256 characters')
    salt = secrets.token_bytes(16)
    value = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=67108864)
    return 'scrypt$' + salt.hex() + '$' + value.hex()


def verify_password(password, encoded):
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        algorithm, salt, expected = encoded.split('$')
        if algorithm != 'scrypt' or len(salt) != 32 or len(expected) != 128:
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768,
                                r=8, p=1, maxmem=67108864)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def email_address(value):
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
        raise HTTPException(400, 'a valid email address is required')
    return value


def totp_code(seed, timestamp):
    key = base64.b32decode(seed, casefold=True)
    counter = int(timestamp // 30)
    value = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = value[-1] & 15
    number = struct.unpack('>I', value[offset:offset+4])[0] & 0x7fffffff
    return f'{number % 1000000:06d}'


def csrf_token(token):
    return hmac.new(token.encode(), b'tunnelpannel:session-csrf:v1', hashlib.sha256).hexdigest()


def public_account(row):
    return {key: row[key] for key in ('id', 'email', 'workspace_id', 'role')} | {
        'mfa_enabled': bool(row['totp_secret'])}


class AccountStore:
    def __init__(self, registry, *, clock=time.time):
        self.registry, self.clock = registry, clock
        with self._db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                    workspace_id TEXT NOT NULL, role TEXT NOT NULL,
                    password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    totp_secret TEXT, totp_pending TEXT, totp_pending_until REAL,
                    totp_last_counter INTEGER NOT NULL DEFAULT -1);
                CREATE TABLE IF NOT EXISTS account_invites (
                    token_hash TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
                    email TEXT NOT NULL, role TEXT NOT NULL, expires_at REAL NOT NULL,
                    used_at REAL);
                CREATE TABLE IF NOT EXISTS account_sessions (
                    token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL,
                    created_at REAL NOT NULL, last_seen REAL NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS account_recovery (
                    account_id TEXT NOT NULL, code_hash TEXT NOT NULL, used_at REAL,
                    PRIMARY KEY(account_id,code_hash));
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    bucket TEXT PRIMARY KEY, started REAL NOT NULL, hits INTEGER NOT NULL);
            ''')

    @contextmanager
    def _db(self):
        db = self.registry._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def invite(self, workspace_id, email, *, role='SUPER_ADMIN', ttl_s=86400):
        if role not in {'SUPER_ADMIN', 'OPERATOR', 'VIEWER'} or not 60 <= ttl_s <= 604800:
            raise HTTPException(400, 'invalid invitation role or duration')
        if workspace_id != 'system' and self.registry.scope_for(workspace_id) is None:
            raise HTTPException(404, 'workspace not found or disabled')
        token = secrets.token_urlsafe(36)
        with self._db() as db:
            db.execute('INSERT INTO account_invites VALUES(?,?,?,?,?,NULL)',
                (digest(token), workspace_id, email_address(email), role, self.clock()+ttl_s))
        return {'token': token, 'workspace_id': workspace_id, 'role': role,
                'expires_at': self.clock()+ttl_s}

    def register(self, invitation, email, password):
        email = email_address(email)
        if not 12 <= len(password) <= 256:
            raise HTTPException(400, 'password must contain12 to256 characters')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM account_invites WHERE token_hash=?',
                             (digest(invitation),)).fetchone()
            if not row or row['used_at'] is not None or row['expires_at'] <= self.clock() or row['email'] != email:
                raise HTTPException(400, 'invitation is invalid or expired')
            if row['workspace_id'] != 'system' and self.registry.scope_for(row['workspace_id']) is None:
                raise HTTPException(400, 'invitation is invalid or expired')
            identity = uuid.uuid4().hex
            try:
                db.execute('INSERT INTO accounts(id,email,workspace_id,role,password_hash) VALUES(?,?,?,?,?)',
                    (identity, email, row['workspace_id'], row['role'], password_hash(password)))
            except sqlite3.IntegrityError:
                raise HTTPException(409, 'account registration is unavailable') from None
            db.execute('UPDATE account_invites SET used_at=? WHERE token_hash=?',
                       (self.clock(), digest(invitation)))
            return public_account(db.execute('SELECT * FROM accounts WHERE id=?', (identity,)).fetchone())

    def _attempt(self, peer, email):
        now = self.clock()
        # A per-peer bucket prevents arbitrary account names from bypassing the limit.
        buckets = [(digest('peer:'+peer), 30), (digest('login:'+peer+':'+email), 10)]
        blocked = False
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM auth_attempts WHERE started<=?', (now-900,))
            for key, maximum in buckets:
                row = db.execute('SELECT hits FROM auth_attempts WHERE bucket=?', (key,)).fetchone()
                if row and row['hits'] >= maximum:
                    blocked = True
                else:
                    db.execute('INSERT INTO auth_attempts VALUES(?,?,1) ON CONFLICT(bucket) '
                               'DO UPDATE SET hits=hits+1', (key, now))
            if db.execute('SELECT COUNT(*) FROM auth_attempts').fetchone()[0] > 20000:
                blocked = True
        if blocked:
            raise HTTPException(429, 'login temporarily limited; try later', headers={'Retry-After': '900'})

    def _consume_otp(self, db, account, otp):
        if not account['totp_secret']:
            return True
        seed = decrypt_credentials(account['totp_secret'])['seed']
        if re.fullmatch(r'\d{6}', otp or ''):
            now = int(self.clock() // 30)
            for counter in (now, now-1, now+1):
                if counter > account['totp_last_counter'] and hmac.compare_digest(totp_code(seed, counter*30), otp):
                    db.execute('UPDATE accounts SET totp_last_counter=? WHERE id=?', (counter, account['id']))
                    return True
        if otp:
            result = db.execute('UPDATE account_recovery SET used_at=? '
                'WHERE account_id=? AND code_hash=? AND used_at IS NULL',
                (self.clock(), account['id'], digest(otp)))
            return result.rowcount == 1
        return False

    def login(self, email, password, *, otp='', peer='unknown'):
        email = email_address(email)
        self._attempt(peer, email)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM accounts WHERE email=?', (email,)).fetchone()
            if row is None:
                # Do the same expensive derivation for unknown accounts.
                password_hash('unknown-account-dummy-password')
            if not row or not row['enabled'] or not verify_password(password, row['password_hash']):
                raise HTTPException(401, 'credentials or verification code are invalid')
            if row['workspace_id'] != 'system' and self.registry.scope_for(row['workspace_id']) is None:
                raise HTTPException(401, 'credentials or verification code are invalid')
            if not self._consume_otp(db, row, otp):
                raise HTTPException(401, 'credentials or verification code are invalid')
            token, now = 'tps_' + secrets.token_urlsafe(36), self.clock()
            db.execute('DELETE FROM account_sessions WHERE expires_at<=? OR last_seen<=?', (now, now-IDLE_SECONDS))
            db.execute('INSERT INTO account_sessions VALUES(?,?,?,?,?)',
                       (digest(token), row['id'], now, now, now+SESSION_SECONDS))
            return {'token': token, 'csrf': csrf_token(token), 'account': public_account(row)}

    def authenticate_session(self, token):
        if not token.startswith('tps_') or len(token) > 200:
            return None
        now = self.clock()
        with self._db() as db:
            row = db.execute('SELECT a.*,s.created_at,s.last_seen,s.expires_at FROM accounts a '
                'JOIN account_sessions s ON s.account_id=a.id WHERE s.token_hash=? AND a.enabled=1',
                (digest(token),)).fetchone()
            if row is None or row['expires_at'] <= now or row['last_seen'] <= now-IDLE_SECONDS:
                return None
            if row['workspace_id'] != 'system' and self.registry.scope_for(row['workspace_id']) is None:
                return None
            db.execute('UPDATE account_sessions SET last_seen=? WHERE token_hash=?', (now, digest(token)))
            return {**public_account(row), 'created_at': row['created_at'], 'expires_at': row['expires_at']}

    def logout(self, token):
        with self._db() as db:
            db.execute('DELETE FROM account_sessions WHERE token_hash=?', (digest(token),))

    def begin_totp(self, account_id, password):
        self._attempt('totp-setup:' + account_id, '')
        with self._db() as db:
            row = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
            if not row or not verify_password(password, row['password_hash']):
                raise HTTPException(401, 'credentials are invalid')
            if row['totp_secret']:
                raise HTTPException(409, 'two-factor authentication is already enabled')
            seed = base64.b32encode(secrets.token_bytes(20)).decode()
            db.execute('UPDATE accounts SET totp_pending=?,totp_pending_until=? WHERE id=?',
                (encrypt_credentials({'seed': seed}), self.clock()+600, account_id))
            return {'secret': seed, 'expires_at': self.clock()+600, 'period': 30, 'digits': 6}

    def enable_totp(self, account_id, otp):
        self._attempt('totp-verify:' + account_id, '')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
            if not row or not row['totp_pending'] or row['totp_pending_until'] <= self.clock():
                raise HTTPException(400, 'two-factor setup expired')
            seed = decrypt_credentials(row['totp_pending'])['seed']
            counter = int(self.clock() // 30)
            matched = next((c for c in (counter, counter-1, counter+1)
                            if hmac.compare_digest(totp_code(seed, c*30), otp)), None)
            if matched is None:
                raise HTTPException(400, 'verification code is invalid')
            codes = [secrets.token_hex(8) for _ in range(8)]
            db.execute('UPDATE accounts SET totp_secret=totp_pending,totp_pending=NULL,'
                       'totp_pending_until=NULL,totp_last_counter=? WHERE id=?', (matched, account_id))
            db.executemany('INSERT INTO account_recovery VALUES(?,?,NULL)',
                           [(account_id, digest(code)) for code in codes])
            db.execute('DELETE FROM account_sessions WHERE account_id=?', (account_id,))
            return {'mfa_enabled': True, 'recovery_codes': codes}

    def change_password(self, account_id, old_password, new_password, otp=''):
        self._attempt('password-change:' + account_id, '')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
            if not row or not verify_password(old_password, row['password_hash']) or not self._consume_otp(db, row, otp):
                raise HTTPException(401, 'credentials or verification code are invalid')
            db.execute('UPDATE accounts SET password_hash=? WHERE id=?', (password_hash(new_password), account_id))
            db.execute('DELETE FROM account_sessions WHERE account_id=?', (account_id,))

    def list_accounts(self):
        with self._db() as db:
            return [public_account(row) for row in db.execute('SELECT * FROM accounts ORDER BY email')]
