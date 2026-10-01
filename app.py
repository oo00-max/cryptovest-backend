"""
CryptoVest Pro — Backend
Handles: discord notifications, admin actions (server-verified), account deletion.
Secrets live in .env, never shipped to the browser.
"""

import os
import time
import requests
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# comma-separated list of allowed origins, or '*' for dev
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*').split(',')
CORS(app, origins=ALLOWED_ORIGINS)

DISCORD_WEBHOOK = os.getenv('DISCORD_WEBHOOK')
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')   # server-only, bypasses RLS
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')


# ============================================================
# HELPERS
# ============================================================
def sb_headers():
    return {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': 'application/json',
    }


def verify_token(token):
    """Ask supabase who this access token belongs to. Returns dict or None."""
    try:
        r = requests.get(
            f'{SUPABASE_URL}/auth/v1/user',
            headers={
                'apikey': SUPABASE_SERVICE_KEY,
                'Authorization': f'Bearer {token}',
            },
            timeout=10,
        )
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        print(f'verify_token error: {e}')
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'missing token'}), 401
        token = auth.split(' ', 1)[1]
        user = verify_token(token)
        if not user:
            return jsonify({'error': 'invalid token'}), 401
        request.user_id = user['id']
        request.user_email = user.get('email')
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if request.user_email != ADMIN_EMAIL:
            return jsonify({'error': 'forbidden'}), 403
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# HEALTH
# ============================================================
@app.route('/api/health')
def health():
    return jsonify({
        'ok': True,
        'service': 'cryptovest-backend',
        'time': time.time(),
    })


# ============================================================
# DISCORD NOTIFICATIONS
# ============================================================
@app.route('/api/notify', methods=['POST'])
def notify():
    """Frontend posts { message: str } here. We forward to discord."""
    if not DISCORD_WEBHOOK:
        return jsonify({'error': 'webhook not configured'}), 500

    data = request.json or {}
    message = (data.get('message') or '').strip()
    if not message:
        return jsonify({'error': 'empty message'}), 400
    if len(message) > 1800:
        message = message[:1800] + '…'

    try:
        r = requests.post(DISCORD_WEBHOOK, json={'content': message}, timeout=10)
        return jsonify({'ok': r.status_code < 300})
    except Exception as e:
        print(f'notify error: {e}')
        return jsonify({'error': str(e)}), 500


# ============================================================
# ADMIN — server-verified only
# ============================================================
@app.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_users():
    """Return all app_users rows. Service key bypasses RLS."""
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/app_users?select=*&order=created_at.desc',
        headers=sb_headers(),
        timeout=15,
    )
    if r.status_code >= 400:
        return jsonify({'error': r.text}), r.status_code
    return jsonify({'users': r.json()})


@app.route('/api/admin/add-balance', methods=['POST'])
@require_admin
def admin_add_balance():
    data = request.json or {}
    email = (data.get('email') or '').strip()
    amount = data.get('amount')

    if not email or not isinstance(amount, (int, float)):
        return jsonify({'error': 'email and numeric amount required'}), 400

    # fetch current balance
    r = requests.get(
        f'{SUPABASE_URL}/rest/v1/app_users?email=eq.{email}&select=auth_id,balance,email',
        headers=sb_headers(),
        timeout=15,
    )
    rows = r.json()
    if not rows:
        return jsonify({'error': 'user not found'}), 404

    user = rows[0]
    new_balance = float(user.get('balance') or 0) + float(amount)

    # update
    r2 = requests.patch(
        f'{SUPABASE_URL}/rest/v1/app_users?email=eq.{email}',
        headers={**sb_headers(), 'Prefer': 'return=minimal'},
        json={'balance': new_balance},
        timeout=15,
    )
    if r2.status_code >= 400:
        return jsonify({'error': r2.text}), r2.status_code

    # notify discord
    if DISCORD_WEBHOOK:
        try:
            requests.post(DISCORD_WEBHOOK, json={
                'content': (
                    f'💰 MANUAL BALANCE ADD\n'
                    f'User: {email}\n'
                    f'Amount: ${amount:+.2f}\n'
                    f'New balance: ${new_balance:.2f}'
                )
            }, timeout=10)
        except Exception as e:
            print(f'discord notify (add-balance) failed: {e}')

    return jsonify({'ok': True, 'new_balance': new_balance})


# ============================================================
# ACCOUNT DELETION
# ============================================================
@app.route('/api/account/delete', methods=['POST'])
@require_auth
def account_delete():
    """Delete the calling user's auth account. Cascades to app_users via FK."""
    user_id = request.user_id
    email = request.user_email

    # 1) delete auth user via admin API
    r = requests.delete(
        f'{SUPABASE_URL}/auth/v1/admin/users/{user_id}',
        headers={
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        },
        timeout=15,
    )
    if r.status_code >= 400 and r.status_code != 404:
        return jsonify({'error': f'auth delete failed: {r.text}'}), 500

    # 2) belt-and-suspenders — delete app_users row in case FK cascade isn't set
    requests.delete(
        f'{SUPABASE_URL}/rest/v1/app_users?auth_id=eq.{user_id}',
        headers=sb_headers(),
        timeout=15,
    )

    if DISCORD_WEBHOOK:
        try:
            requests.post(DISCORD_WEBHOOK, json={
                'content': f'🗑️ ACCOUNT DELETED\nUser: {email}'
            }, timeout=10)
        except Exception:
            pass

    return jsonify({'ok': True})


# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5050))
    print('=' * 60)
    print('🚀 CryptoVest Backend')
    print('=' * 60)
    print(f'   Port:       {port}')
    print(f'   Supabase:   {SUPABASE_URL}')
    print(f'   Admin:      {ADMIN_EMAIL}')
    print(f'   Discord:    {"configured" if DISCORD_WEBHOOK else "MISSING"}')
    print(f'   Origins:    {ALLOWED_ORIGINS}')
    print('=' * 60)
    app.run(host='0.0.0.0', port=port, debug=False)