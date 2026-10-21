"""Standalone source-node client: durable credit, monotonic leases, fenced returns."""
import json
import threading
import time
import uuid
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_CREDIT = 8 * 1024 * 1024


def validate_url(url):
    parsed = urlsplit(url)
    port = parsed.port
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or port is not None and not 1 <= port <= 65535 or any(c.isspace() for c in url)
            or parsed.query or parsed.fragment or not parsed.path.endswith('/quota/credits')):
        raise ValueError('monthly accounting requires a verified HTTPS callback URL')
    return url


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ConnectionError('monthly callback redirects are forbidden')


class MonthlyClient:
    def __init__(self, ledger, config, *, rpc=None, monotonic=time.monotonic):
        validate_url(config['url'])
        self.ledger, self.config, self.monotonic = ledger, config, monotonic
        self.rpc = rpc or self._http
        self.lock = threading.RLock()
        self.boot, self.current_id = uuid.uuid4().hex, None
        self.remaining = 0
        self.deadline, self.last_payload = 0, monotonic()
        self.error = None
        self.callback_ok = None
        with ledger.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS monthly_local (
                    id TEXT PRIMARY KEY, amount INTEGER NOT NULL, upload INTEGER NOT NULL DEFAULT 0,
                    download INTEGER NOT NULL DEFAULT 0, closed INTEGER NOT NULL DEFAULT 0,
                    settled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS monthly_pending (
                    id INTEGER PRIMARY KEY CHECK(id=1), request TEXT NOT NULL,
                    period TEXT NOT NULL, boot TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS monthly_worker (id INTEGER PRIMARY KEY CHECK(id=1), boot TEXT NOT NULL);
            ''')
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE monthly_local SET closed=1 WHERE closed=0')
            db.execute('INSERT INTO monthly_worker VALUES(1,?) ON CONFLICT(id) DO UPDATE SET boot=excluded.boot', (self.boot,))
            db.commit()

    def _owner(self, db):
        if db.execute('SELECT boot FROM monthly_worker WHERE id=1').fetchone()[0] != self.boot:
            raise ConnectionError('monthly worker was superseded')

    def _http(self, body):
        request = Request(self.config['url'], json.dumps(body).encode(), headers={
            'Authorization':'Bearer ' + self.config['token'], 'Content-Type':'application/json',
            'User-Agent':'TehNet-TunnelPannel-Gateway/1.0', 'Accept':'application/json'}, method='POST')
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=5) as response:
                data = response.read(16385)
            if len(data) > 16384:
                raise ValueError('response too large')
            return json.loads(data)
        except Exception:
            raise ConnectionError('monthly accounting callback unavailable') from None

    def _call(self, body):
        started = self.monotonic()
        try:
            answer = self.rpc(body)
            ttl = answer.get('ttl_s', 0)
            if not isinstance(ttl, (int, float)) or not 0 <= ttl <= 10:
                raise ConnectionError('invalid monthly accounting lease')
        except Exception:
            self.callback_ok = False
            self.error = 'monthly accounting callback unavailable'
            raise
        self.callback_ok, self.error = True, None
        return answer, max(0, started + ttl - 1)

    def _pending(self):
        with self.ledger.connection() as db:
            self._owner(db)
            pending = db.execute('SELECT request,period,boot FROM monthly_pending WHERE id=1').fetchone()
        if not pending:
            return
        answer, deadline = self._call({'request_id':pending[0], 'period_id':pending[1], 'amount':MAX_CREDIT})
        with self.ledger.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self._owner(db)
            if answer['grant_id']:
                if type(answer['amount']) is not int or not 1 <= answer['amount'] <= MAX_CREDIT:
                    raise ConnectionError('invalid monthly credit size')
                closed = answer.get('closed', True) or pending[2] != self.boot or deadline <= self.monotonic()
                db.execute('INSERT OR IGNORE INTO monthly_local(id,amount,closed) VALUES(?,?,?)',
                           (answer['grant_id'], answer['amount'], int(closed)))
                if not closed:
                    self.current_id, self.deadline = answer['grant_id'], deadline
                    self.remaining = answer['amount']
                    self.last_payload = self.monotonic()
            db.execute('DELETE FROM monthly_pending WHERE id=1')
            db.commit()

    def tick(self):
        with self.lock:
            self._pending()
            with self.ledger.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                self._owner(db)
                if self.monotonic() - self.last_payload >= 3:
                    db.execute('UPDATE monthly_local SET closed=1 WHERE closed=0')
                    self.remaining, self.deadline = 0, 0
                rows = db.execute('SELECT id,upload,download,closed FROM monthly_local WHERE settled=0').fetchall()
                db.commit()
            for identity, up, down, closed in rows:
                answer, deadline = self._call({'grant_id':identity, 'upload':up, 'download':down, 'close':bool(closed)})
                if not closed and (answer.get('closed') or deadline <= self.monotonic()):
                    # Persist the fence before telling the controller to refund.
                    with self.ledger.connection() as db:
                        db.execute('BEGIN IMMEDIATE')
                        self._owner(db)
                        db.execute('UPDATE monthly_local SET closed=1 WHERE id=?', (identity,))
                        up, down = db.execute('SELECT upload,download FROM monthly_local WHERE id=?', (identity,)).fetchone()
                        db.commit()
                    answer, deadline = self._call({'grant_id':identity,'upload':up,'download':down,'close':True})
                    closed = True
                if closed:
                    if not answer.get('closed'):
                        raise ConnectionError('monthly credit fence not acknowledged')
                    with self.ledger.connection() as db:
                        db.execute('UPDATE monthly_local SET settled=1 WHERE id=? AND closed=1', (identity,))
                        db.commit()
                    if self.current_id == identity:
                        self.current_id, self.deadline = None, 0
                        self.remaining = 0
                else:
                    self.current_id, self.deadline = identity, deadline

    def ready(self):
        return bool(self.current_id and self.remaining > 0 and self.monotonic() < self.deadline)

    def ensure(self):
        with self.lock:
            with self.ledger.connection() as db:
                self._owner(db)
                current = db.execute('SELECT amount-upload-download FROM monthly_local WHERE id=? AND closed=0',
                                     (self.current_id,)).fetchone()
            if current and current[0] > 0 and self.monotonic() < self.deadline:
                self.remaining = current[0]
                return True
            with self.ledger.connection() as db:
                db.execute('UPDATE monthly_local SET closed=1 WHERE closed=0')
                db.commit()
            self.tick()
            if self.current_id and self.monotonic() < self.deadline:
                return True
            answer, _ = self._call({})
            if not answer.get('period_id'):
                return False
            with self.ledger.connection() as db:
                db.execute('BEGIN IMMEDIATE')
                self._owner(db)
                db.execute('INSERT INTO monthly_pending VALUES(1,?,?,?)',
                           (uuid.uuid4().hex, answer['period_id'], self.boot))
                db.commit()
            self._pending()
            return bool(self.current_id and self.monotonic() < self.deadline)

    def charge_in(self, db, direction, size):
        self._owner(db)
        if self.monotonic() >= self.deadline:
            return 0
        row = db.execute('SELECT amount-upload-download FROM monthly_local WHERE id=? AND closed=0',
                         (self.current_id,)).fetchone()
        allowed = min(size, max(0, row[0])) if row else 0
        if allowed:
            db.execute('UPDATE monthly_local SET ' + direction + '=' + direction + '+? WHERE id=?',
                       (allowed, self.current_id))
            self.last_payload = self.monotonic()
            self.remaining = max(0, row[0] - allowed)
        return allowed

    def snapshot(self):
        return {'accounting_version':1, 'lease_valid': bool(self.current_id and self.monotonic() < self.deadline),
                'callback_available': self.callback_ok, 'last_error': self.error,
                'scope':'shared customer allowance; unused credit returned after idle fence'}
