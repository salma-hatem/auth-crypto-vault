"""Flask server for the ACV GUI.

Run:  python gui/server.py
Then open http://localhost:5000 in your browser.
"""

import base64
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, Response, jsonify, request, send_from_directory

from aes import AES_encrypt
from aes import ctr_encrypt_with_nonce as v1_ctr
from aes_v2 import BACKEND as V2_BACKEND
from aes_v2 import ctr_encrypt as v2_ctr
from hmac_kdf import derive_key, hmac_equal, hmac_sha512
from sha512 import sha512
from vault.vault import VaultError, vault_decrypt_bytes, vault_encrypt_bytes

STATIC = os.path.join(os.path.dirname(__file__), 'static')
app = Flask(__name__, static_folder=STATIC)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB upload limit

# Temporary store for file downloads — keyed by one-time token (UUID).
# Entries are consumed on first GET, so tokens don't accumulate indefinitely.
_pending_downloads: dict[str, bytes] = {}

# Pre-baked demo blob (created at startup, used by the Decrypt demo)
_DEMO_PLAINTEXT = (
    b"ACV demo payload\n"
    b"Authenticated Cryptographic Vault (AES-128-CTR + HMAC-SHA-512)\n"
    b"Built from scratch for CIE 582, Spring 2026.\n"
)
_DEMO_PASSWORD = b"demo-password"
_demo_blob: bytes = vault_encrypt_bytes(_DEMO_PLAINTEXT, _DEMO_PASSWORD, backend="v1")


def _make_token(data: bytes) -> str:
    token = str(uuid.uuid4())
    _pending_downloads[token] = data
    return token


# ── Static serving ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(STATIC, 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(STATIC, path)


# ── File download (one-time token) ────────────────────────────────────────────

@app.route('/api/download/<token>')
def api_download(token):
    data = _pending_downloads.pop(token, None)
    if data is None:
        return jsonify({'error': 'download token expired or not found'}), 404
    resp = Response(data, mimetype='application/octet-stream')
    resp.headers['Cache-Control'] = 'no-store'
    return resp


# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/api/demo')
def api_demo():
    """Return a pre-baked demo vault blob for the Decrypt demo scenarios."""
    return jsonify({
        'blob_b64': base64.b64encode(_demo_blob).decode(),
        'password': _DEMO_PASSWORD.decode(),
        'plain_size': len(_DEMO_PLAINTEXT),
    })


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    file = request.files.get('file')
    password = request.form.get('password', '').encode('utf-8')
    backend = request.form.get('backend', 'v1')

    if not file:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    plaintext = file.read()
    try:
        blob = vault_encrypt_bytes(plaintext, password, backend=backend)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

    salt       = blob[:16]
    nonce      = blob[16:28]
    ciphertext = blob[28:-64]
    tag        = blob[-64:]

    # Store blob for one-time download; return only metadata + token in JSON.
    # (Returning the full ciphertext as hex+base64 in JSON would make the
    # response O(2×plaintext_size) — hundreds of MB for large files.)
    token = _make_token(blob)

    return jsonify({
        'success': True,
        'salt': salt.hex(),
        'nonce': nonce.hex(),
        'ciphertext_preview': ciphertext[:64].hex(),  # first 64 B only, for display
        'tag': tag.hex(),
        'plain_size': len(plaintext),
        'blob_size': len(blob),
        'download_token': token,
    })


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    file = request.files.get('file')
    password = request.form.get('password', '').encode('utf-8')
    backend = request.form.get('backend', 'v1')

    if not file:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    blob = file.read()
    MIN_BLOB_LEN = 92  # 16 salt + 12 nonce + 64 tag

    if len(blob) < MIN_BLOB_LEN:
        return jsonify({
            'success': False,
            'error': 'file too short — vault truncated or corrupt',
            'stored_tag': None,
            'computed_tag': None,
        })

    salt       = blob[:16]
    nonce      = blob[16:28]
    ciphertext = blob[28:-64]
    stored_tag = blob[-64:]

    key          = derive_key(password, salt)
    computed_tag = hmac_sha512(key, salt + nonce + ciphertext)
    tags_match   = hmac_equal(computed_tag, stored_tag)

    if not tags_match:
        return jsonify({
            'success': False,
            'error': 'HMAC verification failed — file is tampered or wrong password',
            'stored_tag': stored_tag.hex(),
            'computed_tag': computed_tag.hex(),
        })

    # Tags match — safe to decrypt
    try:
        plaintext = vault_decrypt_bytes(blob, password, backend=backend)
    except VaultError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'stored_tag': stored_tag.hex(),
            'computed_tag': computed_tag.hex(),
        })

    token = _make_token(plaintext)

    return jsonify({
        'success': True,
        'plain_size': len(plaintext),
        'download_token': token,
        'salt': salt.hex(),
        'nonce': nonce.hex(),
        'ciphertext_preview': ciphertext[:64].hex(),
        'stored_tag': stored_tag.hex(),
        'computed_tag': computed_tag.hex(),
    })


@app.route('/api/kdf', methods=['POST'])
def api_kdf():
    data = request.get_json() or {}
    password = (data.get('password') or '').encode('utf-8')
    salt_hex = data.get('salt', '')
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        if len(salt_bytes) != 16:
            return jsonify({'error': 'salt must be 32 hex chars (16 bytes)'}), 400
        key = derive_key(password, salt_bytes)
        return jsonify({'key': key.hex()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/benchmark', methods=['POST'])
def api_benchmark():
    data = request.get_json() or {}
    size_mb = float(data.get('size_mb', 1))

    # Cap V1 at 64 KB — 5 MB would take several minutes in pure Python
    V1_CAP = 64 * 1024
    v1_size = min(int(size_mb * 1024 * 1024), V1_CAP)
    v2_size = int(size_mb * 1024 * 1024)

    key   = os.urandom(16)
    nonce = os.urandom(12)

    v1_data = os.urandom(v1_size)
    t0 = time.perf_counter()
    v1_ctr(v1_data, key, nonce)
    v1_dt = time.perf_counter() - t0

    v2_data = os.urandom(v2_size)
    runs = []
    for _ in range(3):
        t0 = time.perf_counter()
        v2_ctr(v2_data, key, nonce)
        runs.append(time.perf_counter() - t0)
    v2_dt = sum(runs) / len(runs)

    v1_tput = (v1_size / (1024 * 1024)) / v1_dt
    v2_tput = (v2_size / (1024 * 1024)) / v2_dt

    return jsonify({
        'v1': {
            'size_mb': v1_size / (1024 * 1024),
            'time_ms': v1_dt * 1000,
            'throughput_mbs': v1_tput,
            'capped': v1_size < v2_size,
        },
        'v2': {
            'size_mb': v2_size / (1024 * 1024),
            'time_ms': v2_dt * 1000,
            'throughput_mbs': v2_tput,
            'backend': V2_BACKEND,
        },
        'speedup': v2_tput / v1_tput,
    })


@app.route('/api/nist')
def api_nist():
    tests = []

    # AES-128 FIPS 197 Appendix B
    try:
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        pt  = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
        ct  = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')
        tests.append({'label': 'AES-128', 'spec': 'FIPS 197 · Appendix B', 'pass': AES_encrypt(pt, key) == ct})
    except Exception as e:
        tests.append({'label': 'AES-128', 'spec': 'FIPS 197 · Appendix B', 'pass': False, 'error': str(e)})

    # SHA-512 FIPS 180-4 "abc"
    try:
        expected = bytes.fromhex(
            'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2'
            '0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd'
            '454d4423643ce80e2a9ac94fa54ca49f'
        )
        tests.append({'label': 'SHA-512 ("abc")', 'spec': 'FIPS 180-4 · App. C.1', 'pass': sha512(b'abc') == expected})
    except Exception as e:
        tests.append({'label': 'SHA-512 ("abc")', 'spec': 'FIPS 180-4 · App. C.1', 'pass': False, 'error': str(e)})

    # HMAC-SHA-512 RFC 4231 Case 1
    try:
        rfc_key = bytes.fromhex('0b' * 20)
        rfc_msg = b'Hi There'
        rfc_tag = bytes.fromhex(
            '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec278'
            '7ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4'
            'be9d914eeb61f1702e696c203a126854'
        )
        tests.append({'label': 'HMAC-SHA-512 Case 1', 'spec': 'RFC 4231', 'pass': hmac_sha512(rfc_key, rfc_msg) == rfc_tag})
    except Exception as e:
        tests.append({'label': 'HMAC-SHA-512 Case 1', 'spec': 'RFC 4231', 'pass': False, 'error': str(e)})

    return jsonify({'tests': tests})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import webbrowser
    port = int(os.environ.get('ACV_PORT', 5000))
    url  = f'http://127.0.0.1:{port}'
    print(f'  ACV GUI  →  {url}')
    print(f'  V2 backend: {V2_BACKEND}')
    print(f'  Tip: run "make build" first to compile the fast C extension.')
    try:
        webbrowser.open(url)
    except Exception:
        pass
    # Listen on all IPv4 interfaces (0.0.0.0) so the browser finds the server
    # regardless of whether 'localhost' resolves to 127.0.0.1 or ::1.
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
