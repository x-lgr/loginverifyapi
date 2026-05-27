from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import os
import time
from collections import defaultdict
import hmac
import hashlib

# ===== CONFIGURATION =====
EXPECTED_PASSWORD = os.environ.get("API_PASSWORD", "ChangeMe123!@#")
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "10"))
BLOCK_MINUTES = int(os.environ.get("BLOCK_MINUTES", "1"))

# ===== RATE LIMITING STORAGE =====
failed_attempts = defaultdict(list)

# ===== SECURE PASSWORD VERIFICATION =====
def verify_password(provided, expected):
    """Timing-attack safe password comparison"""
    return hmac.compare_digest(provided.encode(), expected.encode())

# ===== RATE LIMIT CHECK =====
def is_rate_limited(client_ip):
    now = time.time()
    cutoff = now - (BLOCK_MINUTES * 60)
    failed_attempts[client_ip] = [t for t in failed_attempts[client_ip] if t > cutoff]
    return len(failed_attempts[client_ip]) >= RATE_LIMIT

def record_failed_attempt(client_ip):
    failed_attempts[client_ip].append(time.time())

# ===== MAIN HANDLER =====
class handler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        provided_password = params.get("pass", [None])[0]
        
        client_ip = self.headers.get('X-Forwarded-For', 'unknown').split(',')[0].strip()
        
        if not provided_password:
            self.send_json_response(400, {"error": "Missing 'pass' parameter", "result": False})
            return
        
        if is_rate_limited(client_ip):
            self.send_json_response(429, {
                "result": False, 
                "error": f"Too many attempts. Try after {BLOCK_MINUTES} minute(s)"
            })
            return
        
        is_valid = verify_password(provided_password, EXPECTED_PASSWORD)
        
        if not is_valid:
            record_failed_attempt(client_ip)
        
        self.send_json_response(200, {"result": is_valid})
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        
        if content_length == 0:
            self.send_json_response(400, {"error": "Empty body", "result": False})
            return
        
        try:
            post_data = json.loads(self.rfile.read(content_length))
            provided_password = post_data.get("pass")
        except:
            self.send_json_response(400, {"error": "Invalid JSON", "result": False})
            return
        
        client_ip = self.headers.get('X-Forwarded-For', 'unknown').split(',')[0].strip()
        
        if not provided_password:
            self.send_json_response(400, {"error": "Missing 'pass' field", "result": False})
            return
        
        if is_rate_limited(client_ip):
            self.send_json_response(429, {
                "result": False, 
                "error": f"Too many attempts. Try after {BLOCK_MINUTES} minute(s)"
            })
            return
        
        is_valid = verify_password(provided_password, EXPECTED_PASSWORD)
        
        if not is_valid:
            record_failed_attempt(client_ip)
        
        self.send_json_response(200, {"result": is_valid})
    
    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
