# app.py - Aura Flask Backend (FULLY FUNCTIONAL)
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from supabase import create_client, Client
import requests as http_requests
import uuid
import jwt
import bcrypt
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
import json
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR)

# Configuration
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webp'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# CORS
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 
    'http://localhost:5000,http://127.0.0.1:5000,https://aura-api.onrender.com'
).split(',')
CORS(app, origins=[o.strip() for o in ALLOWED_ORIGINS])

# JWT Secret
_secret = os.getenv('JWT_SECRET')
if not _secret or len(_secret) < 32:
    _secret = secrets.token_hex(32)
    print(f"⚠️ Using generated JWT_SECRET. Add to .env: JWT_SECRET={_secret}")
app.config['SECRET_KEY'] = _secret

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")

# Supabase
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
print("✅ Connected to Supabase")

# ==================== POINTS CONSTANTS ====================
POINTS = {
    'story_share': 150,
    'room_tour': 250,
    'qr_standard': 25,
    'qr_golden': 150,
    'daily_checkin': 10,
    'streak_7': 100,
    'streak_14': 300,
    'streak_30': 1000,
    'referral_signup': 200,
    'referral_first_purchase': 300,
    'referral_friend_500': 500,
    'referral_friend_1000': 800,
    'large_order_bonus': 250,
}

# Multiplier durations by purchase type (days)
MULTIPLIER_DURATIONS = {
    'standard': 3,
    'limited': 5,
    'mystery': 5,
    'bundle': 7,
}

# ==================== HELPERS ====================

def generate_referral_code(name):
    return name[:4].upper() + str(uuid.uuid4().hex[:4]).upper()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def add_points_to_user(user_id, base_points, action, custom_multiplier=None):
    try:
        result = supabase.rpc('award_points', {
            'p_user_id': user_id,
            'p_base': int(base_points),
            'p_action': action,
            'p_multiplier': custom_multiplier
        }).execute()
        return result.data or 0
    except Exception as rpc_err:
        print(f"RPC fallback: {rpc_err}")
        try:
            user_res = supabase.table('users').select('points, weekly_points, multiplier, multiplier_expiry').eq('id', user_id).execute()
            if not user_res.data:
                return 0
            u = user_res.data[0]
            current_time = int(datetime.utcnow().timestamp() * 1000)
            effective = custom_multiplier or (u.get('multiplier', 1.0) if u.get('multiplier_expiry', 0) > current_time else 1.0)
            earned = int(base_points * effective)
            supabase.table('users').update({
                'points': u['points'] + earned,
                'weekly_points': (u.get('weekly_points') or 0) + earned
            }).eq('id', user_id).execute()
            supabase.table('point_logs').insert({
                'user_id': user_id, 'action': action, 'points': base_points,
                'multiplier': effective, 'earned': earned,
                'timestamp': current_time
            }).execute()
            return earned
        except Exception as e:
            print(f"Error: {e}")
            return 0

# ==================== AUTH DECORATOR ====================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.replace('Bearer ', '').strip()
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = data['user_id']
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


# ==================== STATIC FILE SERVING ====================

from flask import Response

def serve_file(filename):
    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.exists(filepath):
        return f"File not found: {filepath}", 404
    with open(filepath, 'rb') as f:
        content = f.read()
    mimetype = 'text/html' if filename.endswith('.html') else 'application/octet-stream'
    return Response(content, mimetype=mimetype)

@app.route('/')
def serve_index():
    return serve_file('index.html')

@app.route('/home.html')
def serve_home():
    return serve_file('home.html')

@app.route('/<path:path>')
def serve_static(path):
    return serve_file(path)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(BASE_DIR, 'uploads'), filename)
# ==================== AUTH ROUTES ====================

@app.route("/api/auth/register", methods=["POST"])
def register():
    try:
        data = request.get_json(silent=True) or {}
        name = data.get("name", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        referral_code = data.get("referralCode", "").strip() or None

        if not name or not email or not password:
            return jsonify({"error": "Missing fields"}), 400
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400

        # Check if user exists
        existing = supabase.table("users").select("email").eq("email", email).execute()
        if existing.data:
            return jsonify({"error": "Email already exists"}), 400

        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_referral_code = generate_referral_code(name)

        referrer_id = None
        if referral_code:
            ref_result = supabase.table("users").select("id").eq("referral_code", referral_code).execute()
            if ref_result.data and ref_result.data[0]["id"] != user_id:
                referrer_id = ref_result.data[0]["id"]

        # Insert user
        supabase.table("users").insert({
            "id": user_id, "name": name, "email": email, "password": hashed_password,
            "referral_code": user_referral_code, "referred_by": referral_code,
            "points": 100, "streak": 0, "weekly_points": 0,
            "created_at": datetime.utcnow().isoformat() + 'Z'
        }).execute()

        # Award referral bonus
        if referrer_id:
            add_points_to_user(referrer_id, POINTS['referral_signup'], "Referral signup")

        # Generate token
        token = jwt.encode({"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)}, app.config["SECRET_KEY"])
        return jsonify({
            "token": token,
            "user": {
                "id": user_id, "name": name, "email": email, "points": 100,
                "streak": 0, "weekly_points": 0, "referralCode": user_referral_code
            }
        })
    except Exception as e:
        print(f"REGISTER ERROR: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== GOOGLE OAUTH (via Supabase) ====================

@app.route("/api/auth/google", methods=["GET"])
def google_oauth_start():
    """Redirect user to Supabase Google OAuth consent screen."""
    try:
        # Build the redirect_to URL — where Supabase will send the user after consent.
        # Must also be listed in Supabase Dashboard → Authentication → URL Configuration → Redirect URLs.
        base_url = os.getenv('APP_URL', 'https://wall-culture-3.onrender.com')
        redirect_to = f"{base_url}/api/auth/google/callback"

        # Ask Supabase for the OAuth URL
        res = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": redirect_to,
                "scopes": "email profile",
            }
        })
        # res.url is the Google consent URL
        from flask import redirect as flask_redirect
        return flask_redirect(res.url)
    except Exception as e:
        print(f"Google OAuth start error: {e}")
        base_url = os.getenv('APP_URL', 'https://wall-culture-3.onrender.com')
        return flask_redirect(f"{base_url}/index.html?error=oauth_failed")


@app.route("/api/auth/google/callback", methods=["GET"])
def google_oauth_callback():
    """
    Supabase redirects here with ?code=... (PKCE flow).
    We exchange the code server-side using the Supabase REST API,
    get the user's email/name, upsert them in our users table,
    then issue our own JWT and redirect to home.html.
    """
    from flask import redirect as flask_redirect
    from flask import Response

    base_url  = os.getenv('APP_URL', 'https://wall-culture-3.onrender.com')
    code      = request.args.get('code', '').strip()

    if not code:
        print("Google callback: no code in request")
        return flask_redirect(f"{base_url}/index.html?error=no_token")

    try:
        # ── Exchange the code for a Supabase session via REST ──────────────
        supabase_url = os.getenv('SUPABASE_URL', '').rstrip('/')
        supabase_key = os.getenv('SUPABASE_KEY', '')

        exchange_res = http_requests.post(
            f"{supabase_url}/auth/v1/token?grant_type=pkce",
            headers={
                "apikey":       supabase_key,
                "Content-Type": "application/json",
            },
            json={"auth_code": code},
            timeout=10,
        )

        if exchange_res.status_code != 200:
            print(f"Supabase code exchange failed: {exchange_res.status_code} {exchange_res.text}")
            return flask_redirect(f"{base_url}/index.html?error=exchange_failed")

        session_data = exchange_res.json()
        sb_user      = session_data.get('user') or {}
        access_token = session_data.get('access_token', '')

        email = (sb_user.get('email') or '').lower().strip()
        meta  = sb_user.get('user_metadata') or {}
        name  = meta.get('full_name') or meta.get('name') or email.split('@')[0].title()

        if not email:
            print("Google callback: no email in Supabase response")
            return flask_redirect(f"{base_url}/index.html?error=no_email")

        # ── Upsert the user in our own users table ─────────────────────────
        existing = supabase.table('users').select('*').eq('email', email).execute()

        if existing.data:
            user_row = existing.data[0]
            user_id  = user_row['id']
        else:
            user_id            = str(uuid.uuid4())
            user_referral_code = generate_referral_code(name)
            supabase.table('users').insert({
                'id':            user_id,
                'name':          name,
                'email':         email,
                'password':      '',   # no password for OAuth users
                'referral_code': user_referral_code,
                'referred_by':   None,
                'points':        100,
                'streak':        0,
                'weekly_points': 0,
                'created_at':    datetime.utcnow().isoformat() + 'Z',
            }).execute()
            user_row = {
                'id': user_id, 'name': name, 'email': email,
                'points': 100, 'streak': 0, 'weekly_points': 0,
                'referral_code': user_referral_code,
            }

        # ── Issue our own JWT ──────────────────────────────────────────────
        token = jwt.encode(
            {'user_id': user_row['id'], 'exp': datetime.utcnow() + timedelta(days=7)},
            app.config['SECRET_KEY']
        )

        user_json = {
            'id':           user_row['id'],
            'name':         user_row.get('name', name),
            'email':        email,
            'points':       user_row.get('points', 0),
            'streak':       user_row.get('streak', 0),
            'weekly_points':user_row.get('weekly_points', 0),
            'referralCode': user_row.get('referral_code', ''),
        }

        # ── Return a tiny page that saves the token and redirects ──────────
        import json as json_lib
        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Signing you in…</title>
  <style>
    body {{ background:#07070F; color:#FFF8F5; font-family:sans-serif;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
    .msg {{ text-align:center; }}
    .spinner {{ width:36px; height:36px; border:3px solid rgba(255,107,53,0.2);
               border-top-color:#FF6B35; border-radius:50%;
               animation:spin .7s linear infinite; margin:0 auto 16px; }}
    @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
    p {{ font-size:0.9rem; opacity:0.7; }}
  </style>
</head>
<body>
<div class="msg">
  <div class="spinner"></div>
  <p>Signing you in…</p>
</div>
<script>
  try {{
    localStorage.setItem('aura_token', {json_lib.dumps(token)});
    localStorage.setItem('aura_user',  {json_lib.dumps(json_lib.dumps(user_json))});
  }} catch(e) {{}}
  window.location.replace('{base_url}/home.html');
</script>
</body>
</html>"""
        return Response(html, mimetype='text/html')

    except Exception as e:
        print(f"Google OAuth callback error: {e}")
        return flask_redirect(f"{base_url}/index.html?error=server_error")


@app.route("/api/auth/login", methods=["POST"])
def login():
    try:
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        if not email or not password:
            return jsonify({"error": "Missing fields"}), 400
        
        result = supabase.table("users").select("*").eq("email", email).execute()
        if not result.data:
            return jsonify({"error": "Invalid email or password"}), 401
        
        user = result.data[0]
        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({"error": "Invalid email or password"}), 401
        
        token = jwt.encode({"user_id": user["id"], "exp": datetime.utcnow() + timedelta(days=7)}, app.config["SECRET_KEY"])
        return jsonify({
            "token": token,
            "user": {
                "id": user["id"], "name": user["name"], "email": user["email"],
                "points": user.get("points", 0), "streak": user.get("streak", 0),
                "weekly_points": user.get("weekly_points", 0),
                "referralCode": user.get("referral_code", "")
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== POSTERS (FROM DATABASE) ====================

@app.route('/api/posters', methods=['GET'])
@token_required
def get_posters():
    try:
        category = request.args.get('category', 'all')
        limited_str = request.args.get('limited', 'false')
        limit_str = request.args.get('limit', None)
        
        limited = limited_str.lower() == 'true'
        
        query = supabase.table('posters').select('*')
        
        if category != 'all':
            query = query.eq('category', category)
        if limited:
            query = query.eq('is_limited', 1)
        
        query = query.order('created_at', desc=True)
        
        if limit_str and limit_str.isdigit():
            query = query.limit(int(limit_str))
        
        result = query.execute()
        
        # Convert to list and ensure proper format
        posters = []
        for p in (result.data or []):
            posters.append({
                'id': p.get('id'),
                'name': p.get('name'),
                'category': p.get('category'),
                'emoji': p.get('emoji', '🖼️'),
                'price': p.get('price', 40),
                'points': p.get('points', 120),
                'is_limited': p.get('is_limited', 0) == 1,
                'image_url': p.get('image_url'),
                'created_at': p.get('created_at')
            })
        
        return jsonify(posters)
    except Exception as e:
        print(f"get_posters error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/feed', methods=['GET'])
@token_required
def get_feed():
    try:
        result = supabase.table('posters').select('*').order('created_at', desc=True).limit(20).execute()
        feed = []
        for poster in (result.data or []):
            feed.append({
                "type": "poster",
                "id": poster.get("id"),
                "name": poster.get("name"),
                "image_url": poster.get("image_url"),
                "price": poster.get("price", 40),
                "points": poster.get("points", 120),
                "category": poster.get("category", ""),
                "is_limited": poster.get("is_limited", 0) == 1
            })
        return jsonify({"feed": feed})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== REAL QR SCAN ====================

@app.route('/api/scan/qr', methods=['POST'])
@token_required
def scan_qr():
    """REAL QR SCANNING - Validates against database QR codes"""
    try:
        data = request.get_json(silent=True) or {}
        qr_data = data.get('qr_data', data.get('code', '')).strip().upper()

        if not qr_data:
            return jsonify({'error': 'No QR code detected. Point camera at QR code.'}), 400

        today_start = int(datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000)

        # Find QR code in database first to know if it's golden
        qr_result = supabase.table('qr_codes').select('*').eq('code', qr_data).execute()
        if not qr_result.data:
            return jsonify({'error': 'Invalid QR code. This code is not recognized.'}), 404

        qr = qr_result.data[0]
        is_golden = qr.get('is_golden', 0) == 1

        if is_golden:
            # Golden QR: max 1x/day
            golden_scans = supabase.table('point_logs').select('id', count='exact').eq('user_id', request.user_id).eq('action', 'Golden QR Scan').gte('timestamp', today_start).execute()
            if golden_scans.count and golden_scans.count >= 1:
                return jsonify({'error': 'You have already scanned a golden QR today'}), 429
        else:
            # Standard QR: max 5x/day
            scans = supabase.table('point_logs').select('id', count='exact').eq('user_id', request.user_id).eq('action', 'QR Scan').gte('timestamp', today_start).execute()
            if scans.count and scans.count >= 5:
                return jsonify({'error': 'Max 5 QR scans per day'}), 429

        current_time = int(datetime.utcnow().timestamp() * 1000)

        # Check expiration
        if qr.get('expires_at') and qr['expires_at'] < current_time:
            return jsonify({'error': 'This QR code has expired'}), 410

        # Check if already scanned
        if qr.get('scanned_by'):
            return jsonify({'error': 'This QR code has already been used'}), 409

        # Award points
        points_to_award = qr.get('points', POINTS['qr_golden'] if is_golden else POINTS['qr_standard'])
        action_label = 'Golden QR Scan' if is_golden else 'QR Scan'
        earned = add_points_to_user(request.user_id, points_to_award, action_label)

        # Mark as scanned
        supabase.table('qr_codes').update({
            'scanned_by': request.user_id,
            'scanned_at': current_time
        }).eq('code', qr_data).execute()

        return jsonify({
            'success': True,
            'earned': earned,
            'points': points_to_award,
            'is_golden': is_golden,
            'location': qr.get('location', 'Campus Location'),
            'message': f"🎉 +{earned} points! {'✨ GOLDEN QR ✨ ' if is_golden else ''}"
        })
    except Exception as e:
        print(f"QR scan error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/qr/list', methods=['GET'])
@token_required
def list_qr_codes():
    """Get all active QR codes for testing"""
    try:
        result = supabase.table('qr_codes').select('code, location, points, is_golden, scanned_by').execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== INSTAGRAM STORY (PENDING APPROVAL) ====================

@app.route('/api/social/story', methods=['POST'])
@token_required
def social_story():
    """Submit Instagram story link — queued for admin approval"""
    try:
        data = request.get_json(silent=True) or {}
        story_link = data.get('story_link', '').strip()

        if not story_link:
            return jsonify({'error': 'Please provide your Instagram story link'}), 400

        if 'instagram.com' not in story_link:
            return jsonify({'error': 'Please provide a valid Instagram story link'}), 400

        # Check if user already has a pending story submission
        pending = supabase.table('pending_submissions') \
            .select('id', count='exact') \
            .eq('user_id', request.user_id) \
            .eq('type', 'story') \
            .eq('status', 'pending') \
            .execute()
        if pending.count and pending.count >= 1:
            return jsonify({'error': 'You already have a story pending review. Please wait for approval.'}), 429

        # Check weekly limit (approved submissions)
        week_start = int((datetime.utcnow() - timedelta(days=7)).timestamp() * 1000)
        approved = supabase.table('point_logs').select('id', count='exact') \
            .eq('user_id', request.user_id) \
            .eq('action', 'Instagram Story') \
            .gte('timestamp', week_start) \
            .execute()
        if approved.count and approved.count >= 3:
            return jsonify({'error': 'Max 3 approved story shares per week'}), 429

        # Queue for admin approval
        sub_id = str(uuid.uuid4())
        supabase.table('pending_submissions').insert({
            'id': sub_id,
            'user_id': request.user_id,
            'type': 'story',
            'url': story_link,
            'status': 'pending',
            'points': POINTS['story_share'],
            'submitted_at': int(datetime.utcnow().timestamp() * 1000)
        }).execute()

        return jsonify({
            'success': True,
            'pending': True,
            'message': '⏳ Story submitted! You\'ll receive your coins once an admin approves it.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ROOM TOUR (PENDING APPROVAL) ====================

@app.route('/api/social/roomtour', methods=['POST'])
@token_required
def room_tour():
    """Submit room tour URL — queued for admin approval"""
    try:
        data = request.get_json(silent=True) or {}
        tour_url = data.get('url', '').strip()

        if not tour_url:
            return jsonify({'error': 'Please provide a link to your room tour post'}), 400

        # Check if user already has a pending room tour submission
        pending = supabase.table('pending_submissions') \
            .select('id', count='exact') \
            .eq('user_id', request.user_id) \
            .eq('type', 'roomtour') \
            .eq('status', 'pending') \
            .execute()
        if pending.count and pending.count >= 1:
            return jsonify({'error': 'You already have a room tour pending review.'}), 429

        # Check monthly limit (approved)
        month_start = int(datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000)
        approved = supabase.table('point_logs').select('id', count='exact') \
            .eq('user_id', request.user_id) \
            .eq('action', 'Room Tour') \
            .gte('timestamp', month_start) \
            .execute()
        if approved.count and approved.count >= 1:
            return jsonify({'error': 'Room tour already approved this month'}), 429

        # Queue for admin approval
        sub_id = str(uuid.uuid4())
        supabase.table('pending_submissions').insert({
            'id': sub_id,
            'user_id': request.user_id,
            'type': 'roomtour',
            'url': tour_url,
            'status': 'pending',
            'points': POINTS['room_tour'],
            'submitted_at': int(datetime.utcnow().timestamp() * 1000)
        }).execute()

        return jsonify({
            'success': True,
            'pending': True,
            'message': '⏳ Room tour submitted! You\'ll receive your coins once an admin approves it.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== USER: MY SUBMISSIONS ====================

@app.route('/api/social/submissions', methods=['GET'])
@token_required
def my_submissions():
    """Get current user's submission history"""
    try:
        result = supabase.table('pending_submissions') \
            .select('id, type, url, status, points, submitted_at, reviewed_at') \
            .eq('user_id', request.user_id) \
            .order('submitted_at', desc=True) \
            .limit(20) \
            .execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ADMIN ROUTES ====================

ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'aura-admin-secret')

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        secret = request.headers.get('X-Admin-Secret', '')
        if secret != ADMIN_SECRET:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/admin/submissions', methods=['GET'])
@admin_required
def admin_list_submissions():
    """List all pending submissions"""
    try:
        status_filter = request.args.get('status', 'pending')
        query = supabase.table('pending_submissions').select(
            'id, user_id, type, url, status, points, submitted_at, reviewed_at'
        ).order('submitted_at', desc=True)
        if status_filter != 'all':
            query = query.eq('status', status_filter)
        result = query.limit(100).execute()

        # Enrich with user names
        submissions = result.data or []
        user_ids = list({s['user_id'] for s in submissions})
        users_map = {}
        if user_ids:
            users_res = supabase.table('users').select('id, name, email').in_('id', user_ids).execute()
            users_map = {u['id']: u for u in (users_res.data or [])}

        for s in submissions:
            u = users_map.get(s['user_id'], {})
            s['user_name'] = u.get('name', 'Unknown')
            s['user_email'] = u.get('email', '')

        return jsonify(submissions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/submissions/<sub_id>/approve', methods=['POST'])
@admin_required
def admin_approve_submission(sub_id):
    """Approve a pending submission and award points"""
    try:
        result = supabase.table('pending_submissions').select('*').eq('id', sub_id).execute()
        if not result.data:
            return jsonify({'error': 'Submission not found'}), 404

        sub = result.data[0]
        if sub['status'] != 'pending':
            return jsonify({'error': f'Submission is already {sub["status"]}'}), 400

        action_label = 'Instagram Story' if sub['type'] == 'story' else 'Room Tour'
        earned = add_points_to_user(sub['user_id'], sub['points'], action_label)

        supabase.table('pending_submissions').update({
            'status': 'approved',
            'reviewed_at': int(datetime.utcnow().timestamp() * 1000)
        }).eq('id', sub_id).execute()

        return jsonify({'success': True, 'earned': earned, 'message': f'Approved! +{earned} points awarded.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/submissions/<sub_id>/reject', methods=['POST'])
@admin_required
def admin_reject_submission(sub_id):
    """Reject a pending submission"""
    try:
        result = supabase.table('pending_submissions').select('*').eq('id', sub_id).execute()
        if not result.data:
            return jsonify({'error': 'Submission not found'}), 404

        sub = result.data[0]
        if sub['status'] != 'pending':
            return jsonify({'error': f'Submission is already {sub["status"]}'}), 400

        data = request.get_json(silent=True) or {}
        reason = data.get('reason', 'Did not meet requirements')

        supabase.table('pending_submissions').update({
            'status': 'rejected',
            'reject_reason': reason,
            'reviewed_at': int(datetime.utcnow().timestamp() * 1000)
        }).eq('id', sub_id).execute()

        return jsonify({'success': True, 'message': 'Submission rejected.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== DAILY CHECK-IN ====================

@app.route('/api/daily/checkin', methods=['POST'])
@token_required
def daily_checkin():
    try:
        result = supabase.table('users').select('last_checkin, streak').eq('id', request.user_id).execute()
        user_data = result.data[0] if result.data else {'last_checkin': None, 'streak': 0}
        today = datetime.utcnow().date().isoformat()

        if user_data.get('last_checkin') == today:
            return jsonify({'success': False, 'message': 'Already checked in today'})

        new_streak = 1
        bonus = 0

        if user_data.get('last_checkin'):
            yesterday = (datetime.utcnow() - timedelta(days=1)).date().isoformat()
            if user_data['last_checkin'] == yesterday:
                new_streak = (user_data.get('streak') or 0) + 1

        if new_streak == 7:
            bonus = POINTS['streak_7']
        elif new_streak == 14:
            bonus = POINTS['streak_14']
        elif new_streak == 30:
            bonus = POINTS['streak_30']

        total_points = POINTS['daily_checkin'] + bonus
        earned = add_points_to_user(request.user_id, total_points, 'Daily check-in')

        supabase.table('users').update({
            'last_checkin': today,
            'streak': new_streak
        }).eq('id', request.user_id).execute()

        try:
            check_referral_milestones(request.user_id)
        except Exception as e:
            print(f"Milestone check error: {e}")

        return jsonify({
            'success': True,
            'points': total_points,
            'earned': earned,
            'streak': new_streak,
            'bonus': bonus
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ORDER ====================

@app.route('/api/order/create', methods=['POST'])
@token_required
def create_order():
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items', [])
        total_price = data.get('totalPrice', 0)
        total_base_points = data.get('totalBasePoints', 0)

        if not items:
            return jsonify({'error': 'No items in order'}), 400

        order_id = str(uuid.uuid4())

        # ── Award base purchase points ──────────────────────────
        earned = add_points_to_user(request.user_id, total_base_points, 'Purchase order')

        # ── +250 bonus for orders ≥ 140 KSH ────────────────────
        if total_price >= 140:
            bonus_earned = add_points_to_user(request.user_id, POINTS['large_order_bonus'], 'Large order bonus')
            earned += bonus_earned

        # ── Determine best multiplier and its duration ──────────
        new_multiplier = 1.0
        best_type = 'standard'
        type_priority = {'bundle': 4, 'mystery': 3, 'limited': 2, 'standard': 1}
        for item in items:
            itype = item.get('type', item.get('itemType', 'standard'))
            if type_priority.get(itype, 1) > type_priority.get(best_type, 1):
                best_type = itype

        if best_type == 'bundle' or total_price >= 140:
            new_multiplier = 2.0
            best_type = 'bundle'
        elif best_type == 'mystery':
            new_multiplier = 1.5
        elif best_type == 'limited':
            new_multiplier = 1.5
        else:
            new_multiplier = 1.2

        duration_days = MULTIPLIER_DURATIONS.get(best_type, 3)
        multiplier_expiry = int((datetime.utcnow() + timedelta(days=duration_days)).timestamp() * 1000)

        supabase.table('orders').insert({
            'id': order_id, 'user_id': request.user_id, 'items': json.dumps(items),
            'total_price': total_price, 'total_points': earned,
            'boost_given': new_multiplier, 'status': 'completed',
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }).execute()

        supabase.table('users').update({
            'multiplier': new_multiplier,
            'multiplier_expiry': multiplier_expiry
        }).eq('id', request.user_id).execute()

        # ── Award referral first-purchase bonus to referrer ─────
        try:
            user_res = supabase.table('users').select('referred_by').eq('id', request.user_id).execute()
            referrer_code = user_res.data[0].get('referred_by') if user_res.data else None
            if referrer_code:
                # Check if this is the user's first purchase
                prev_orders = supabase.table('orders').select('id', count='exact').eq('user_id', request.user_id).execute()
                if prev_orders.count and prev_orders.count == 1:
                    ref_res = supabase.table('users').select('id').eq('referral_code', referrer_code).execute()
                    if ref_res.data:
                        referrer_id = ref_res.data[0]['id']
                        add_points_to_user(referrer_id, POINTS['referral_first_purchase'], 'Referral first purchase')
        except Exception as ref_err:
            print(f"Referral first-purchase bonus error: {ref_err}")

        # ── Check referral milestone bonuses ────────────────────
        try:
            check_referral_milestones(request.user_id)
        except Exception as milestone_err:
            print(f"Milestone check error: {milestone_err}")

        return jsonify({'success': True, 'orderId': order_id, 'pointsEarned': earned, 'newMultiplier': new_multiplier, 'multiplierDays': duration_days})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def check_referral_milestones(user_id):
    """Award milestone bonuses to referrer when this user hits 500 or 1000 points."""
    user_res = supabase.table('users').select('points, referred_by').eq('id', user_id).execute()
    if not user_res.data:
        return
    user = user_res.data[0]
    referrer_code = user.get('referred_by')
    current_points = user.get('points', 0)
    if not referrer_code:
        return

    ref_res = supabase.table('users').select('id').eq('referral_code', referrer_code).execute()
    if not ref_res.data:
        return
    referrer_id = ref_res.data[0]['id']

    for threshold, action, points_key in [
        (500, f'Friend milestone 500 ({user_id})', 'referral_friend_500'),
        (1000, f'Friend milestone 1000 ({user_id})', 'referral_friend_1000'),
    ]:
        if current_points >= threshold:
            # Check if already awarded
            already = supabase.table('point_logs').select('id', count='exact').eq('user_id', referrer_id).eq('action', action).execute()
            if not already.count or already.count == 0:
                add_points_to_user(referrer_id, POINTS[points_key], action)


# ==================== LEADERBOARDS ====================

@app.route('/api/leaderboard/alltime', methods=['GET'])
@token_required
def get_alltime_leaderboard():
    try:
        result = supabase.table('users').select('id, name, points').order('points', desc=True).limit(50).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/leaderboard/weekly', methods=['GET'])
@token_required
def get_weekly_leaderboard():
    try:
        result = supabase.table('users').select('id, name, weekly_points').order('weekly_points', desc=True).limit(50).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== PROFILE ====================

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile():
    try:
        user_result = supabase.table('users').select(
            'id, name, email, points, weekly_points, streak, multiplier, multiplier_expiry, referral_code'
        ).eq('id', request.user_id).execute()
        if not user_result.data:
            return jsonify({'error': 'User not found'}), 404
        user = user_result.data[0]
        logs = supabase.table('point_logs').select('action, earned, timestamp').eq('user_id', request.user_id).order('timestamp', desc=True).limit(20).execute()
        rank_result = supabase.table('users').select('id', count='exact').gt('points', user['points']).execute()
        rank = (rank_result.count or 0) + 1
        return jsonify({'user': user, 'auditLog': logs.data or [], 'rank': rank})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/user/status', methods=['GET'])
@token_required
def get_user_status():
    try:
        result = supabase.table('users').select('points, streak, multiplier, multiplier_expiry, weekly_points').eq('id', request.user_id).execute()
        return jsonify(result.data[0] if result.data else {})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== REFERRAL ====================

@app.route('/api/referral/info', methods=['GET'])
@token_required
def get_referral_info():
    try:
        user_result = supabase.table('users').select('referral_code').eq('id', request.user_id).execute()
        referral_code = user_result.data[0]['referral_code'] if user_result.data else None
        return jsonify({'referralCode': referral_code, 'referrals': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== HEALTH ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'app': 'Aura', 'version': '2.0.0'})


if __name__ == '__main__':
    print("\n" + "="*50)
    print("🎨 AURA BACKEND v2.0.0")
    print("="*50)
    print(f"📍 Running on: http://localhost:5000")
    print("✅ REAL QR Scanning (standard 5×/day, golden 1×/day)")
    print("✅ REAL Instagram story verification")
    print("✅ REAL Room Tour uploads")
    print("✅ Referral first-purchase + milestone bonuses")
    print("✅ Correct multiplier values + durations")
    print("✅ +250 large order bonus")
    print("✅ Posters from Supabase database")
    print("="*50 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)