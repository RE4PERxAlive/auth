import http.server
import socketserver
import json
import os
import time
import urllib.parse
from datetime import datetime, timedelta

PORT = 8080
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uuids.json')
HTML_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')

DEFAULT_OWNER_ID = "e4b3c2a1-8765-4321-90ab-cdef12345678"
DEFAULT_SECRET_KEY = "bloody_sec_9f8e7d6c5b4a39281706f5e4d3c2b1a"

def get_server_machine_uuid():
    try:
        import subprocess
        out = subprocess.check_output('wmic csproduct get uuid', shell=True).decode()
        lines = [line.strip() for line in out.splitlines() if line.strip() and 'UUID' not in line]
        if lines:
            return lines[0]
    except:
        pass
    return "UNKNOWN"

def load_db():
    if not os.path.exists(DB_FILE):
        return []
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return []

def save_db(data):
    # 1. Save to uuids.json
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    # 2. Auto-save directly into index.html itself!
    try:
        if os.path.exists(HTML_FILE):
            with open(HTML_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            start_tag = '/* [BLOODY_DB_START] */'
            end_tag = '/* [BLOODY_DB_END] */'
            if start_tag in content and end_tag in content:
                before = content.split(start_tag)[0]
                after = content.split(end_tag)[1]
                db_code = f"\n        let EMBEDDED_UUIDS = {json.dumps(data, indent=8)};\n        "
                new_content = before + start_tag + db_code + end_tag + after
                with open(HTML_FILE, 'w', encoding='utf-8') as f:
                    f.write(new_content)
    except Exception as e:
        print(f"[-] Error auto-saving to index.html: {e}")

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. Verification endpoint: /verify?owner_id=...&secret_key=...&system_uuid=...
        if parsed.path == '/verify':
            owner_id = (params.get('owner_id', [''])[0]).strip()
            secret_key = (params.get('secret_key', [''])[0]).strip()
            # client sends system_uuid (or hwid/uuid)
            system_uuid = (params.get('system_uuid', [''])[0] or params.get('hwid', [''])[0] or params.get('uuid', [''])[0]).strip().upper()

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            # Optional check: validate credentials if sent
            if owner_id and owner_id != DEFAULT_OWNER_ID:
                self.wfile.write(json.dumps({"status": 0, "message": "Invalid Owner ID"}).encode('utf-8'))
                return

            if secret_key and secret_key != DEFAULT_SECRET_KEY:
                self.wfile.write(json.dumps({"status": 0, "message": "Invalid Secret Key"}).encode('utf-8'))
                return

            if not system_uuid:
                self.wfile.write(json.dumps({"status": 0, "message": "Missing System UUID"}).encode('utf-8'))
                return

            db = load_db()
            found = None

            # Look up by system UUID
            for item in db:
                item_uuid = (item.get('system_uuid') or item.get('uuid') or '').strip().upper()
                if item_uuid == system_uuid:
                    found = item
                    break

            if not found:
                self.wfile.write(json.dumps({
                    "status": 0, 
                    "message": "System UUID is not registered on website"
                }).encode('utf-8'))
                return

            if found.get('status') == 'Revoked':
                self.wfile.write(json.dumps({
                    "status": 0, 
                    "message": "System UUID has been Revoked by Admin"
                }).encode('utf-8'))
                return

            # Check expiration
            expire_ts = found.get('expireTimestamp', 0)
            now_ts = int(time.time())
            if expire_ts > 0 and now_ts > expire_ts:
                found['status'] = 'Expired'
                save_db(db)
                self.wfile.write(json.dumps({
                    "status": 0, 
                    "message": "System UUID Access has Expired"
                }).encode('utf-8'))
                return

            # Success!
            self.wfile.write(json.dumps({
                "status": 1,
                "message": "Authorized",
                "system_uuid": system_uuid,
                "user": found.get('user', 'Client'),
                "expires": found.get('expiresFormatted', 'Lifetime')
            }).encode('utf-8'))
            return

        # 2. Get local detected machine UUID for convenient copy on website
        if parsed.path == '/api/my_uuid':
            my_uuid = get_server_machine_uuid()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"system_uuid": my_uuid}).encode('utf-8'))
            return

        # 3. Web Dashboard API - Get registered UUIDs: /api/keys
        if parsed.path == '/api/keys':
            db = load_db()
            now_ts = int(time.time())
            updated = False
            for item in db:
                exp = item.get('expireTimestamp', 0)
                if exp > 0 and now_ts > exp and item.get('status') == 'Active':
                    item['status'] = 'Expired'
                    updated = True
            if updated:
                save_db(db)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(db).encode('utf-8'))
            return

        # Default serve HTML/CSS/JS files
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/api/keys':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8')
            try:
                payload = json.loads(body)
                db = load_db()
                action = payload.get('action')

                if action == 'add':
                    days = int(payload.get('days', 30))
                    now = datetime.now()
                    now_ts = int(time.time())

                    if days > 0:
                        exp_dt = now + timedelta(days=days)
                        exp_ts = int(now_ts + (days * 86400))
                        exp_formatted = exp_dt.strftime("%Y-%m-%d %H:%M")
                    else:
                        exp_ts = 0
                        exp_formatted = "Lifetime"

                    sys_uuid = (payload.get('system_uuid') or payload.get('uuid') or '').strip().upper()

                    # Prevent duplicate entries - update existing if already added
                    existing = next((x for x in db if (x.get('system_uuid') or x.get('uuid') or '').upper() == sys_uuid), None)
                    if existing:
                        existing['user'] = payload.get('user', existing.get('user', 'Client'))
                        existing['durationDays'] = days
                        existing['expireTimestamp'] = exp_ts
                        existing['expiresFormatted'] = exp_formatted
                        existing['status'] = 'Active'
                    else:
                        new_entry = {
                            'system_uuid': sys_uuid,
                            'uuid': sys_uuid, # for backward compatibility
                            'user': payload.get('user', 'Client'),
                            'durationDays': days,
                            'expireTimestamp': exp_ts,
                            'expiresFormatted': exp_formatted,
                            'status': 'Active',
                            'createdAt': now.strftime("%Y-%m-%d %H:%M")
                        }
                        db.insert(0, new_entry)

                elif action == 'toggle':
                    target = (payload.get('system_uuid') or payload.get('uuid') or '').strip().upper()
                    for item in db:
                        item_u = (item.get('system_uuid') or item.get('uuid') or '').strip().upper()
                        if item_u == target:
                            item['status'] = 'Revoked' if item.get('status') == 'Active' else 'Active'

                elif action == 'delete':
                    target = (payload.get('system_uuid') or payload.get('uuid') or '').strip().upper()
                    db = [item for item in db if (item.get('system_uuid') or item.get('uuid') or '').strip().upper() != target]

                elif action == 'save_all' or action == 'sync':
                    keys_list = payload.get('keys', [])
                    if isinstance(keys_list, list):
                        db = keys_list

                save_db(db)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'keys': db}).encode('utf-8'))
                return
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(str(e).encode('utf-8'))
                return

        super().do_GET()

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    if not os.path.exists(DB_FILE):
        save_db([])

    print(f"[*] Bloody Auth Server starting on port {PORT}...")
    with socketserver.TCPServer(('', PORT), AuthHandler) as httpd:
        print(f"[+] Bloody Auth Server running at http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Server stopped.")
