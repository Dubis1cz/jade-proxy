"""
J.A.D.E. Proxy Server
---------------------
Central relay between JADE clients and Anthropic API.
Users register automatically with their email — no manual code entry needed.
Users are stored in Supabase for persistence across Railway redeployments.

Environment variables (set in Railway dashboard):
  ANTHROPIC_KEY   — your Anthropic API key
  ADMIN_KEY       — secret key for admin endpoints
  APP_SECRET      — secret baked into the JADE app (prevents random registrations)
  SUPABASE_URL    — Supabase project URL
  SUPABASE_KEY    — Supabase service_role key
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
import urllib.parse

# ── Config ────────────────────────────────────────────────────────────────────
ANTHROPIC_KEY = os.environ.get('ANTHROPIC_KEY', '')
ADMIN_KEY     = os.environ.get('ADMIN_KEY', 'change-me')
APP_SECRET    = os.environ.get('APP_SECRET', '')
PORT          = int(os.environ.get('PORT', 8000))
SUPABASE_URL  = os.environ.get('SUPABASE_URL', '').rstrip('/')
SUPABASE_KEY  = os.environ.get('SUPABASE_KEY', '')

ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages'
ANTHROPIC_VER = '2023-06-01'

# ── Supabase user store ───────────────────────────────────────────────────────
def _sb_headers():
    return {
        'apikey':        SUPABASE_KEY,
        'Authorization': f'Bearer {SUPABASE_KEY}',
        'Content-Type':  'application/json',
        'Prefer':        'return=representation',
    }

def load_users() -> dict:
    """Load all users from Supabase proxy_users table."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return _fallback_load()
    try:
        req = urllib.request.Request(
            f'{SUPABASE_URL}/rest/v1/proxy_users?select=*',
            headers={**_sb_headers(), 'Prefer': ''},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            rows = json.loads(r.read())
        # Convert list → dict keyed by name
        return {row['name']: row for row in rows}
    except Exception as e:
        print(f'[DB] load_users failed: {e} — falling back to local')
        return _fallback_load()

def save_user(name: str, data: dict):
    """Upsert a single user into Supabase."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        _fallback_save_user(name, data)
        return
    row = {**data, 'name': name}
    try:
        req = urllib.request.Request(
            f'{SUPABASE_URL}/rest/v1/proxy_users',
            data=json.dumps(row).encode(),
            headers={**_sb_headers(), 'Prefer': 'resolution=merge-duplicates,return=minimal'},
            method='POST',
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f'[DB] save_user failed: {e}')
        _fallback_save_user(name, data)

def delete_user(name: str):
    """Deactivate user in Supabase."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return
    try:
        req = urllib.request.Request(
            f'{SUPABASE_URL}/rest/v1/proxy_users?name=eq.{urllib.parse.quote(name)}',
            data=json.dumps({'active': False}).encode(),
            headers={**_sb_headers(), 'Prefer': 'return=minimal'},
            method='PATCH',
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f'[DB] delete_user failed: {e}')

# ── Local fallback (in-memory) ────────────────────────────────────────────────
_mem_users: dict = {}

def _fallback_load():
    return dict(_mem_users)

def _fallback_save_user(name, data):
    _mem_users[name] = data

# ── Helpers ───────────────────────────────────────────────────────────────────
def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()

def find_user_by_code(code: str):
    users = load_users()
    h = hash_code(code)
    for name, info in users.items():
        if info.get('code_hash') == h and info.get('active', True):
            return name, info
    return None, None

def find_user_by_email(email: str):
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
        code = self.headers.get('X-Access-Code', '')
        if not code:
            return False, '', {}
        name, info = find_user_by_code(code)
        if name:
            return True, name, info
        return False, '', {}

    def check_app_secret(self) -> bool:
        if not APP_SECRET:
            return True
        return self.headers.get('X-App-Secret', '') == APP_SECRET

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, X-Access-Code, X-Admin-Key, X-App-Secret')
        self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            db = 'supabase' if (SUPABASE_URL and SUPABASE_KEY) else 'memory'
            self.send_json(200, {'status': 'ok', 'version': '1.2.0', 'storage': db})

        elif self.path == '/validate':
            valid, name, _ = self.check_user()
            if valid:
                self.send_json(200, {'ok': True, 'name': name})
            else:
                self.send_json(401, {'ok': False, 'error': 'Invalid or inactive access code'})

        elif self.path == '/admin/users':
            if not self.check_admin():
                self.send_json(403, {'error': 'Forbidden'}); return
            users = load_users()
            safe = {name: {
                        'active':  info.get('active', True),
                        'email':   info.get('email', ''),
                        'created': info.get('created', ''),
                        'note':    info.get('note', ''),
                    } for name, info in users.items()}
            self.send_json(200, {'users': safe, 'count': len(safe)})

        else:
            self.send_json(404, {'error': 'Not found'})

    def do_POST(self):

        # ── Auto-registration ──────────────────────────────────────────────────
        if self.path == '/api/register':
            if not self.check_app_secret():
                self.send_json(403, {'error': 'Invalid app secret'}); return
            try:
                data  = json.loads(self.read_body())
                email = data.get('email', '').lower().strip()
                if not email or '@' not in email:
                    self.send_json(400, {'error': 'Valid email required'}); return

                existing_name, existing_info = find_user_by_email(email)
                if existing_name:
                    if not existing_info.get('active', True):
                        self.send_json(403, {'error': 'Account deactivated.'}); return
                    # Re-issue new code
                    new_code = uuid.uuid4().hex[:20].upper()
                    existing_info['code_hash'] = hash_code(new_code)
                    save_user(existing_name, existing_info)
                    print(f'[REGISTER] Re-issued: {existing_name} ({email})')
                    self.send_json(200, {'ok': True, 'code': new_code, 'name': existing_name, 'new': False})
                    return

                # New user
                name = email.split('@')[0][:32]
                users = load_users()
                base_name = name; i = 2
                while name in users:
                    name = f'{base_name}{i}'; i += 1

                code = uuid.uuid4().hex[:20].upper()
                user_data = {
                    'email':     email,
                    'code_hash': hash_code(code),
                    'active':    True,
                    'created':   datetime.datetime.now().isoformat()[:16],
                    'note':      'auto-registered',
                }
                save_user(name, user_data)
                print(f'[REGISTER] New: {name} ({email})')
                self.send_json(201, {'ok': True, 'code': code, 'name': name, 'new': True})

            except Exception as e:
                self.send_json(400, {'error': str(e)})

        # ── Proxy to Anthropic ─────────────────────────────────────────────────
        elif self.path == '/v1/messages':
            valid, username, _ = self.check_user()
            if not valid:
                self.send_json(401, {'error': 'Invalid or inactive access code'}); return
            if not ANTHROPIC_KEY:
                self.send_json(500, {'error': 'Server not configured — ANTHROPIC_KEY missing'}); return

            body = self.read_body()
            try:
                req = urllib.request.Request(
                    ANTHROPIC_URL, data=body, method='POST',
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

        # ── Admin: add user ────────────────────────────────────────────────────
        elif self.path == '/admin/users':
            if not self.check_admin():
                self.send_json(403, {'error': 'Forbidden'}); return
            try:
                data  = json.loads(self.read_body())
                name  = data.get('name', '').strip()
                email = data.get('email', '').strip().lower()
                if not name:
                    self.send_json(400, {'error': 'name required'}); return
                users = load_users()
                if name in users:
                    self.send_json(409, {'error': f'User "{name}" already exists'}); return
                code = uuid.uuid4().hex[:20].upper()
                user_data = {
                    'email': email, 'code_hash': hash_code(code),
                    'active': True, 'created': datetime.datetime.now().isoformat()[:16],
                    'note': data.get('note', ''),
                }
                save_user(name, user_data)
                print(f'[ADMIN] Created: {name}')
                self.send_json(201, {'ok': True, 'name': name, 'code': code})
            except Exception as e:
                self.send_json(400, {'error': str(e)})

        else:
            self.send_json(404, {'error': 'Not found'})

    def do_DELETE(self):
        if self.path.startswith('/admin/users/'):
            if not self.check_admin():
                self.send_json(403, {'error': 'Forbidden'}); return
            name = self.path.split('/')[-1]
            users = load_users()
            if name not in users:
                self.send_json(404, {'error': f'User "{name}" not found'}); return
            delete_user(name)
            print(f'[ADMIN] Deactivated: {name}')
            self.send_json(200, {'ok': True})
        else:
            self.send_json(404, {'error': 'Not found'})


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('=' * 52)
    print(f'  J.A.D.E. Proxy Server v1.2.0')
    print(f'  Port:          {PORT}')
    print(f'  ANTHROPIC_KEY: {"SET ✓" if ANTHROPIC_KEY else "NOT SET ✗"}')
    print(f'  ADMIN_KEY:     {"SET ✓" if ADMIN_KEY != "change-me" else "DEFAULT — CHANGE IT!"}')
    print(f'  APP_SECRET:    {"SET ✓" if APP_SECRET else "open registration"}')
    storage = "Supabase ✓" if (SUPABASE_URL and SUPABASE_KEY) else "in-memory (set SUPABASE vars!)"
    print(f'  STORAGE:       {storage}')
    print('=' * 52)
    server = http.server.HTTPServer(('0.0.0.0', PORT), Handler)
    server.serve_forever()
