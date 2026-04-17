"""
J.A.R.V.I.S. Proxy Server
--------------------------
Central relay between JARVIS clients and Anthropic API.
Each user has a unique access code.  The admin uses ADMIN_KEY to manage users.

Environment variables (set in Railway dashboard):
  ANTHROPIC_KEY   — your Anthropic API key
  ADMIN_KEY       — secret key for admin endpoints (choose anything strong)
  PORT            — set automatically by Railway (default 8000)
"""

import os
import json
import uuid
import hashlib
import datetime
import http.server
import urllib.request
import urllib.error
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_KEY', '')
ADMIN_KEY     = os.environ.get('ADMIN_KEY', 'change-me')
PORT          = int(os.environ.get('PORT', 8000))

USERS_FILE    = Path('users.json')   # persisted on Railway volume (or in-memory on free tier)

ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages'
ANTHROPIC_VER = '2023-06-01'

# ── User store ────────────────────────────────────────────────────────────────
def load_users() -> dict:
    if USERS_FILE.exists():
        try:
            return json.loads(USERS_FILE.read_text('utf-8'))
        except Exception:
            pass
    return {}

def save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False), 'utf-8')

def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()

# ── Handler ───────────────────────────────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f'[{ts}] {fmt % args}')

    # ── Helpers ───────────────────────────────────────────────────────────────
    def send_json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_stream_chunk(self, data: bytes):
        self.wfile.write(data)
        self.wfile.flush()

    def read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length) if length else b''

    def check_admin(self) -> bool:
        key = self.headers.get('X-Admin-Key', '')
        return key == ADMIN_KEY

    def check_user(self) -> tuple[bool, str]:
        """Returns (valid, username)"""
        code = self.headers.get('X-Access-Code', '')
        if not code:
            return False, ''
        users = load_users()
        h = hash_code(code)
        for name, info in users.items():
            if info.get('code_hash') == h and info.get('active', True):
                return True, name
        return False, ''

    # ── CORS preflight ─────────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Access-Code, X-Admin-Key')
        self.end_headers()

    # ── GET ────────────────────────────────────────────────────────────────────
    def do_GET(self):

        # Health check
        if self.path == '/health':
            self.send_json(200, {'status': 'ok', 'version': '1.0.0'})

        # Validate access code
        elif self.path == '/validate':
            valid, name = self.check_user()
            if valid:
                self.send_json(200, {'ok': True, 'name': name})
            else:
                self.send_json(401, {'ok': False, 'error': 'Invalid or inactive access code'})

        # Admin: list users
        elif self.path == '/admin/users':
            if not self.check_admin():
                self.send_json(403, {'error': 'Forbidden'})
                return
            users = load_users()
            # Don't expose hashes
            safe = {name: {'active': info.get('active', True),
                           'created': info.get('created', ''),
                           'note': info.get('note', '')}
                    for name, info in users.items()}
            self.send_json(200, {'users': safe})

        else:
            self.send_json(404, {'error': 'Not found'})

    # ── POST ───────────────────────────────────────────────────────────────────
    def do_POST(self):

        # ── Proxy: forward to Anthropic ────────────────────────────────────────
        if self.path == '/v1/messages':
            valid, username = self.check_user()
            if not valid:
                self.send_json(401, {'error': 'Invalid or inactive access code'})
                return

            if not ANTHROPIC_KEY:
                self.send_json(500, {'error': 'Server not configured — ANTHROPIC_KEY missing'})
                return

            body = self.read_body()
            try:
                req = urllib.request.Request(
                    ANTHROPIC_URL,
                    data=body,
                    method='POST',
                    headers={
                        'Content-Type':      'application/json',
                        'x-api-key':         ANTHROPIC_KEY,
                        'anthropic-version': ANTHROPIC_VER,
                    }
                )
                with urllib.request.urlopen(req, timeout=120) as resp:
                    resp_body = resp.read()
                    self.send_response(resp.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(resp_body)))
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(resp_body)
                    print(f'[PROXY] {username} → {len(body)}B sent, {len(resp_body)}B received')

            except urllib.error.HTTPError as e:
                err_body = e.read()
                self.send_response(e.code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(err_body)))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(err_body)

            except Exception as ex:
                self.send_json(502, {'error': str(ex)})

        # ── Admin: add user ────────────────────────────────────────────────────
        elif self.path == '/admin/users':
            if not self.check_admin():
                self.send_json(403, {'error': 'Forbidden'})
                return
            try:
                data = json.loads(self.read_body())
                name = data.get('name', '').strip()
                note = data.get('note', '').strip()
                if not name:
                    self.send_json(400, {'error': 'name required'})
                    return
                users = load_users()
                if name in users:
                    self.send_json(409, {'error': f'User "{name}" already exists'})
                    return
                # Generate unique access code
                code = str(uuid.uuid4()).replace('-', '')[:20].upper()
                users[name] = {
                    'code_hash': hash_code(code),
                    'active': True,
                    'created': datetime.datetime.now().isoformat()[:16],
                    'note': note,
                }
                save_users(users)
                print(f'[ADMIN] Created user: {name}')
                self.send_json(201, {'ok': True, 'name': name, 'code': code,
                                     'message': f'Share this code with {name} — it cannot be retrieved later!'})
            except Exception as e:
                self.send_json(400, {'error': str(e)})

        else:
            self.send_json(404, {'error': 'Not found'})

    # ── DELETE ─────────────────────────────────────────────────────────────────
    def do_DELETE(self):

        # Admin: deactivate user  DELETE /admin/users/<name>
        if self.path.startswith('/admin/users/'):
            if not self.check_admin():
                self.send_json(403, {'error': 'Forbidden'})
                return
            name = self.path.split('/')[-1]
            users = load_users()
            if name not in users:
                self.send_json(404, {'error': f'User "{name}" not found'})
                return
            users[name]['active'] = False
            save_users(users)
            print(f'[ADMIN] Deactivated user: {name}')
            self.send_json(200, {'ok': True, 'message': f'User "{name}" deactivated'})

        else:
            self.send_json(404, {'error': 'Not found'})


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('=' * 50)
    print(f'  J.A.R.V.I.S. Proxy Server v1.0.0')
    print(f'  Listening on port {PORT}')
    print(f'  ANTHROPIC_KEY: {"SET ✓" if ANTHROPIC_KEY else "NOT SET ✗"}')
    print(f'  ADMIN_KEY:     {"SET ✓" if ADMIN_KEY != "change-me" else "DEFAULT — CHANGE IT!"}')
    print('=' * 50)

    server = http.server.HTTPServer(('0.0.0.0', PORT), Handler)
    server.serve_forever()
