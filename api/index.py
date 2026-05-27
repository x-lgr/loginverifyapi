from flask import Flask, request, jsonify
import os
import time
from collections import defaultdict

app = Flask(__name__)

EXPECTED_PASSWORD = os.environ.get("API_PASSWORD", "ChangeMe123!@#")
RATE_LIMIT = 10
failed_attempts = defaultdict(list)

@app.route('/', methods=['GET', 'POST'])
def verify():
    client_ip = request.headers.get('X-Forwarded-For', 'unknown').split(',')[0].strip()
    
    # Rate limiting check
    now = time.time()
    failed_attempts[client_ip] = [t for t in failed_attempts[client_ip] if now - t < 60]
    
    if len(failed_attempts[client_ip]) >= RATE_LIMIT:
        return jsonify({"result": False, "error": "Rate limited"}), 429
    
    # Get password
    if request.method == 'GET':
        provided_password = request.args.get('pass')
    else:
        data = request.get_json(silent=True)
        provided_password = data.get('pass') if data else None
    
    if not provided_password:
        return jsonify({"result": False, "error": "Missing pass parameter"}), 400
    
    # Verify
    is_valid = (provided_password == EXPECTED_PASSWORD)
    
    if not is_valid:
        failed_attempts[client_ip].append(now)
        return jsonify({"result": False}), 200
    
    return jsonify({"result": True}), 200

# Vercel needs this
app.debug = False
