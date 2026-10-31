"""Installation CA and certificate-bound, replay-safe telemetry identities."""
import datetime as dt
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.models import Node
from orchestrator.remote_nodes import decrypt_credentials, encrypt_credentials


class TelemetryReport(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    version: int = Field(strict=True, ge=1, le=1)
    sequence: int = Field(strict=True, ge=1, le=9_000_000_000_000_000_000)
    sent_at: float = Field(strict=True)
    os: str = Field(pattern=r'^linux$')
    arch: str = Field(pattern=r'^[A-Za-z0-9_.-]{1,32}$')
    uptime_s: float = Field(strict=True, ge=0, le=1e12)
    load1: float = Field(strict=True, ge=0, le=1e6)
    memory_total_bytes: int = Field(strict=True, ge=1, le=2**60)
    memory_available_bytes: int = Field(strict=True, ge=0, le=2**60)


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


class AgentIdentityStore:
    def __init__(self, registry, clock=time.time):
        self.registry, self.clock = registry, clock

    @contextmanager
    def _db(self):
        db = self.registry._connect()
        db.executescript('''CREATE TABLE IF NOT EXISTS agent_authority
            (id INTEGER PRIMARY KEY, certificate TEXT NOT NULL, encrypted_key TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS agent_identities
            (fingerprint TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, node_id TEXT NOT NULL,
             serial TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL,
             sequence INTEGER NOT NULL DEFAULT 0, last_seen REAL, report TEXT);
            CREATE INDEX IF NOT EXISTS ix_agent_node ON agent_identities(workspace_id,node_id);''')
        try:
            with db:
                yield db
        finally:
            db.close()

    def authority(self):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM agent_authority WHERE id=1').fetchone()
            if row:
                return (x509.load_pem_x509_certificate(row['certificate'].encode()),
                    serialization.load_pem_private_key(decrypt_credentials(row['encrypted_key'])['key'].encode(),None))
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'TunnelPannel telemetry authority')])
            now = dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5))
                .not_valid_after(now+dt.timedelta(days=1825)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
                .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
                .sign(key, hashes.SHA256()))
            db.execute('INSERT INTO agent_authority VALUES(1,?,?)',(
                cert.public_bytes(serialization.Encoding.PEM).decode(), encrypt_credentials({'key':_pem_key(key)})))
            return cert,key

    def _certificate(self, name, *, server_name=None, identity_uri=None):
        authority, signer = self.authority()
        key, now = ec.generate_private_key(ec.SECP256R1()), dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc)
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)]))
            .issuer_name(authority.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server_name else ExtendedKeyUsageOID.CLIENT_AUTH]),False))
        if server_name:
            try:
                san = x509.IPAddress(ipaddress.ip_address(server_name))
            except ValueError:
                if not server_name or len(server_name)>253 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for c in server_name):
                    raise HTTPException(400,'invalid telemetry server name') from None
                san = x509.DNSName(server_name)
            builder = builder.add_extension(x509.SubjectAlternativeName([san]),False)
        elif identity_uri:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity_uri)]),False)
        cert = builder.sign(signer,hashes.SHA256())
        return cert, {'certificate':cert.public_bytes(serialization.Encoding.PEM).decode(),
                      'private_key':_pem_key(key), 'ca':authority.public_bytes(serialization.Encoding.PEM).decode()}

    def server_bundle(self, name):
        return self._certificate('TunnelPannel telemetry hub',server_name=name)[1]

    def issue(self, workspace_id, node_id):
        scope = self.registry.scope_for(workspace_id)
        if scope is None:
            raise HTTPException(404,'enabled workspace not found')
        with scope['factory']() as session:
            if session.get(Node,node_id) is None:
                raise HTTPException(404,'node not found in workspace')
        cert, bundle = self._certificate('node:'+node_id,
            identity_uri='spiffe://tunnelpannel/'+workspace_id+'/'+node_id)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE agent_identities SET revoked=1 WHERE workspace_id=? AND node_id=?',(workspace_id,node_id))
            db.execute('INSERT INTO agent_identities(fingerprint,workspace_id,node_id,serial,expires,revoked) VALUES(?,?,?,?,?,0)',
                       (fingerprint,workspace_id,node_id,str(cert.serial_number),cert.not_valid_after_utc.timestamp()))
        return {**bundle, 'node_id':node_id, 'workspace_id':workspace_id, 'hub_url':os.environ.get('TP_AGENT_HUB_URL'),
                'expires':cert.not_valid_after_utc.timestamp(), 'capability':'unprivileged typed Linux telemetry only; no commands'}

    def revoke(self, workspace_id, node_id):
        with self._db() as db:
            db.execute('UPDATE agent_identities SET revoked=1 WHERE workspace_id=? AND node_id=?',(workspace_id,node_id))
        return {'node_id':node_id,'revoked':True}

    def status(self, workspace_id, node_id):
        with self._db() as db:
            row = db.execute('SELECT * FROM agent_identities WHERE workspace_id=? AND node_id=? ORDER BY expires DESC,rowid DESC LIMIT 1',
                             (workspace_id,node_id)).fetchone()
        if row is None:
            return {'node_id':node_id, 'enrolled':False}
        return {'node_id':node_id,'enrolled':True,'revoked':bool(row['revoked']),'expires':row['expires'],
                'last_seen':row['last_seen'], 'report':json.loads(row['report']) if row['report'] else None,
                'fresh':row['last_seen'] is not None and 0 <= self.clock()-row['last_seen'] < 180}

    def accept_report(self, certificate, raw):
        if len(raw)>16384:
            raise HTTPException(413,'telemetry report too large')
        try:
            report = TelemetryReport.model_validate(json.loads(raw))
            if report.memory_available_bytes > report.memory_total_bytes or abs(self.clock()-report.sent_at)>120:
                raise ValueError()
            cert = x509.load_der_x509_certificate(certificate)
            authority, _ = self.authority()
            authority.public_key().verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(cert.signature_hash_algorithm))
            if not cert.not_valid_before_utc.timestamp() <= self.clock() < cert.not_valid_after_utc.timestamp():
                raise ValueError()
        except (ValueError, TypeError, ValidationError, RecursionError):
            raise HTTPException(400,'invalid typed telemetry report or certificate') from None
        except Exception:
            raise HTTPException(401,'untrusted telemetry certificate') from None
        fingerprint=hashlib.sha256(certificate).hexdigest()
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT a.* FROM agent_identities a JOIN workspaces w ON w.id=a.workspace_id '
                           'WHERE a.fingerprint=? AND w.enabled=1',(fingerprint,)).fetchone()
            if row is None or row['revoked'] or row['expires']<=self.clock():
                raise HTTPException(401,'telemetry identity revoked, expired or unavailable')
            if report.sequence <= row['sequence']:
                raise HTTPException(409,'telemetry sequence must increase')
            db.execute('UPDATE agent_identities SET sequence=?,last_seen=?,report=? WHERE fingerprint=?',
                       (report.sequence,self.clock(),report.model_dump_json(),fingerprint))
        return {'accepted':True}
