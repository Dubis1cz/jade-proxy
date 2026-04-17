"""
J.A.R.V.I.S. Proxy Server
--------------------------
Central relay between JARVIS clients and Anthropic API.
Users register automatically with their email — no manual code entry needed.

Environment variables (set in Railway dashboard):
  ANTHROPIC_KEY   — your Anthropic API key
  ADMIN_KEY       — secret key for admin endpoints (choose anything strong)
  APP_SECRET      — secret baked into the JARVIS app (prevents random registrations)
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
APP_SECRET    = os.environ.get('APP_SECRET', '')   # must match the value baked into JARVIS
PORT          = int(os.environ.get('PORT', 8000))

USERS_FILE    = Path('users.json')

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

def find_user_by_code(code: str):
    """Returns (name, info) or (None, None)"""
    users = load_users()
    h = hash_code(code)
    for name, info in users.items():
        if info.get('code_hash') == h and info.get('active', True):
            return name, info
    return None, None

def find_user_by_email(email: str):
    """Returns (name, info) or (None, None)"""
    users = load_users()
    email = email.lower().strip()
    for name, info in users.items():
        if info.get('email', '').lower() == email:
            return name, info
    return None, None

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

    def read_body(self) -> bytes:
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length) if length else b''

    def check_admin(self) -> bool:
        return self.headers.get('X-Admin-Key', '') == ADMIN_KEY

    def check_user(self):
        """Returns (valid, name, info)"""
        code = self.headers.get('X-Access-Code', '')
        if not code:
            return False, '', {}
        name, info = find_user_by_code(code)
        if name:
            return True, name, info
        return False, '', {}

    def check_app_secret(self) -> bool:
        if not APP_SECRET:
            return True  # not configured → open registration
        return self.headers.get('X-App-Secret', '') == APP_SECRET

    # ── CORS preflight ─────────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, X-Access-Code, X-Admin-Key, X-App-Secret')
        self.end_headers()

    # ── GET ────────────────────────────────────────────────────────────────────
    def do_GET(self):

        # Health check
        if self.path == '/health':
            self.send_json(200, {'status': 'ok', 'version': '1.1.0'})

        # Validate access code
        elif self.path == '/validate':
            valid, name, _ = self.check_user()
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
            safe = {name: {
                        'active':  info.get('active', True),
                        'email':   info.get('email', ''),
                        'created': info.get('created', ''),
                        'note':    info.get('note', ''),
                    }
                    for name, info in users.items()}
            self.send_json(200, {'users': safe, 'count': len(safe)})

        else:
            self.send_json(404, {'error': 'Not found'})

    # ── POST ───────────────────────────────────────────────────────────────────
    def do_POST(self):

        # ── Auto-registration by email ─────────────────────────────────────────
        if self.path == '/api/register':
            if not self.check_app_secret():
                self.send_json(403, {'error': 'Invalid app secret'})
                return
            try:
                data  = json.loads(self.read_body())
                email = data.get('email', '').lower().strip()
                if not email or '@' not in email:
                    self.send_json(400, {'error': 'Valid email required'})
                    return

                # Already registered? Return existing code (new one)
                existing_name, existing_info = find_user_by_email(email)
                if existing_name:
                    if not existing_info.get('active', True):
                        self.send_json(403, {'error': 'Account deactivated. Contact admin.'})
                        return
                    # Re-issue a new code (old one is invalidated)
                    users = load_users()
                    new_code = uuid.uuid4().hex[:20].upper()
                    users[existing_name]['code_hash'] = hash_code(new_code)
                    save_users(users)
                    print(f'[REGISTER] Re-issued code for: {existing_name} ({email})')
                    self.send_json(200, {'ok': True, 'code': new_code, 'name': existing_name, 'new': False})
                    return

                # New registration
                name = email.split('@')[0][:32]  # use email prefix as display name
                # Ensure unique name
                users = load_users()
                base_name = name
                i = 2
                while name in users:
                    name = f'{base_name}{i}'; i += 1

                code = uuid.uuid4().hex[:20].upper()
                users[name] = {
                    'email':     email,
                    'code_hash': hash_code(code),
                    'active':    True,
                    'created':   datetime.datetime.now().isoformat()[:16],
                    'note':      'auto-registered',
                }
                save_users(users)
                print(f'[REGISTER] New user: {name} ({email})')
                self.send_json(201, {'ok': True, 'code': code, 'name': name, 'new': True})

            except Exception as e:
                self.send_json(400, {'error': str(e)})

        # ── Proxy: forward to Anthropic ────────────────────────────────────────
        elif self.path == '/v1/messages':
            valid, username, _ = self.check_user()
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
                    print(f'[PROXY] {username} → {len(body)}B → {len(resp_body)}B')

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

        # ── Admin: add user manually ───────────────────────────────────────────
        elif self.path == '/admin/users':
            if not self.check_admin():
                self.send_json(403, {'error': 'Forbidden'})
                return
            try:
                data  = json.loads(self.read_body())
                name  = data.get('name', '').strip()
                email = data.get('email', '').strip().lower()
                note  = data.get('note', '').strip()
                if not name:
                    self.send_json(400, {'error': 'name required'})
                    return
                users = load_users()
                if name in users:
                    self.send_json(409, {'error': f'User "{name}" already exists'})
                    return
                code = uuid.uuid4().hex[:20].upper()
                users[name] = {
                    'email':     email,
                    'code_hash': hash_code(code),
                    'active':    True,
                    'created':   datetime.datetime.now().isoformat()[:16],
                    'note':      note,
                }
                save_users(users)
                print(f'[ADMIN] Created user: {name}')
                self.send_json(201, {'ok': True, 'name': name, 'code': code})
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
            print(f'[ADMIN] Deactivated: {name}')
            self.send_json(200, {'ok': True, 'message': f'User "{name}" deactivated'})

        else:
            self.send_json(404, {'error': 'Not found'})


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('=' * 52)
    print(f'  J.A.R.V.I.S. Proxy Server v1.1.0')
    print(f'  Port:          {PORT}')
    print(f'  ANTHROPIC_KEY: {"SET ✓" if ANTHROPIC_KEY else "NOT SET ✗"}')
    print(f'  ADMIN_KEY:     {"SET ✓" if ADMIN_KEY != "change-me" else "DEFAULT — CHANGE IT!"}')
    print(f'  APP_SECRET:    {"SET ✓" if APP_SECRET else "open registration (no secret)"}')
    print('=' * 52)
    server = http.server.HTTPServer(('0.0.0.0', PORT), Handler)
    server.serve_forever()
