# app.py - Aura Flask Backend v3.0.0 (Multi-Product Architecture)
from flask import Flask, request, jsonify, send_from_directory, Response, redirect as flask_redirect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from supabase import create_client, Client
import uuid
import jwt
import bcrypt
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
import json
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR)

# ==================== CONFIGURATION ====================

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
    print(f"⚠️  Using generated JWT_SECRET. Add to .env: JWT_SECRET={_secret}")
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

# Admin secret
ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'aura-admin-secret')

# ==================== SHOP CONFIG ====================
# To add a new business: add one entry here. Nothing else in the backend needs changing.
SHOP_CONFIG = {
    'poster':    {'points_rate': 10, 'multiplier_cap': 2.0, 'label': 'Wall Art',  'emoji': '🖼️'},
    'clothing':  {'points_rate': 15, 'multiplier_cap': 2.5, 'label': 'Fits',      'emoji': '👕'},
    'food':      {'points_rate': 5,  'multiplier_cap': 1.5, 'label': 'Bites',     'emoji': '🍔'},
    'accessory': {'points_rate': 12, 'multiplier_cap': 2.0, 'label': 'Extras',    'emoji': '💎'},
    'digital':   {'points_rate': 20, 'multiplier_cap': 3.0, 'label': 'Digital',   'emoji': '📲'},
}

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

# Multiplier durations by purchase item_type (days)
MULTIPLIER_DURATIONS = {
    'standard': 3,
    'limited':  5,
    'mystery':  5,
    'bundle':   7,
}

# ==================== HELPERS ====================

def generate_referral_code(name):
    return name[:4].upper() + str(uuid.uuid4().hex[:4]).upper()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def add_points_to_user(user_id, base_points, action, custom_multiplier=None):
    """Award points to a user. Tries Supabase RPC first, falls back to manual update."""
    try:
        result = supabase.rpc('award_points', {
            'p_user_id': user_id,
            'p_base': int(base_points),
            'p_action': action,
            'p_multiplier': custom_multiplier
        }).execute()
        return result.data or 0
    except Exception as rpc_err:
        print(f"RPC fallback triggered: {rpc_err}")
        try:
            user_res = supabase.table('users').select(
                'points, weekly_points, multiplier, multiplier_expiry'
            ).eq('id', user_id).execute()
            if not user_res.data:
                return 0
            u = user_res.data[0]
            current_time = int(datetime.utcnow().timestamp() * 1000)
            effective = custom_multiplier or (
                u.get('multiplier', 1.0)
                if u.get('multiplier_expiry', 0) > current_time
                else 1.0
            )
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
            print(f"add_points_to_user fallback error: {e}")
            return 0

def check_referral_milestones(user_id):
    """Award milestone bonuses to referrer when this user hits 500 or 1000 points."""
    try:
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
            (500,  f'Friend milestone 500 ({user_id})',  'referral_friend_500'),
            (1000, f'Friend milestone 1000 ({user_id})', 'referral_friend_1000'),
        ]:
            if current_points >= threshold:
                already = supabase.table('point_logs').select('id', count='exact') \
                    .eq('user_id', referrer_id).eq('action', action).execute()
                if not already.count or already.count == 0:
                    add_points_to_user(referrer_id, POINTS[points_key], action)
    except Exception as e:
        print(f"check_referral_milestones error: {e}")

# ==================== DECORATORS ====================

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
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        secret = request.headers.get('X-Admin-Secret', '')
        if secret != ADMIN_SECRET:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ==================== STATIC FILE SERVING ====================

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

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(BASE_DIR, 'uploads'), filename)

@app.route('/<path:path>')
def serve_static(path):
    if path.startswith('api/'):
        return jsonify({'error': 'Not found'}), 404
    return serve_file(path)

# ==================== AUTH ROUTES ====================

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("20 per hour")
def register():
    try:
        data = request.get_json(silent=True) or {}
        name          = data.get("name", "").strip()
        email         = data.get("email", "").strip().lower()
        password      = data.get("password", "")
        referral_code = data.get("referralCode", "").strip() or None

        if not name or not email or not password:
            return jsonify({"error": "Missing fields"}), 400
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400

        existing = supabase.table("users").select("email").eq("email", email).execute()
        if existing.data:
            return jsonify({"error": "Email already exists"}), 400

        user_id            = str(uuid.uuid4())
        hashed_password    = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_referral_code = generate_referral_code(name)

        referrer_id = None
        if referral_code:
            ref_result = supabase.table("users").select("id").eq("referral_code", referral_code).execute()
            if ref_result.data and ref_result.data[0]["id"] != user_id:
                referrer_id = ref_result.data[0]["id"]

        supabase.table("users").insert({
            "id": user_id, "name": name, "email": email, "password": hashed_password,
            "referral_code": user_referral_code, "referred_by": referral_code,
            "points": 100, "streak": 0, "weekly_points": 0,
            "created_at": datetime.utcnow().isoformat() + 'Z'
        }).execute()

        if referrer_id:
            add_points_to_user(referrer_id, POINTS['referral_signup'], "Referral signup")

        token = jwt.encode(
            {"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)},
            app.config["SECRET_KEY"]
        )
        return jsonify({
            "token": token,
            "user": {
                "id": user_id, "name": name, "email": email, "points": 100,
                "streak": 0, "weekly_points": 0, "referralCode": user_referral_code
            }
        })
    except Exception as e:
        print(f"REGISTER ERROR: {e}")
        return jsonify({"error": "Registration failed. Please try again."}), 500


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    try:
        data     = request.get_json(silent=True) or {}
        email    = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not email or not password:
            return jsonify({"error": "Missing fields"}), 400

        result = supabase.table("users").select("*").eq("email", email).execute()
        if not result.data:
            return jsonify({"error": "Invalid email or password"}), 401

        user = result.data[0]

        stored_password = user.get("password") or ""
        if not stored_password:
            return jsonify({"error": "This account uses Google sign-in. Please log in with Google."}), 401

        try:
            password_matches = bcrypt.checkpw(password.encode(), stored_password.encode())
        except Exception as bcrypt_err:
            print(f"LOGIN BCRYPT ERROR for {email}: {bcrypt_err}")
            return jsonify({"error": "Invalid email or password"}), 401

        if not password_matches:
            return jsonify({"error": "Invalid email or password"}), 401

        token = jwt.encode(
            {"user_id": user["id"], "exp": datetime.utcnow() + timedelta(days=7)},
            app.config["SECRET_KEY"]
        )
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
        print(f"LOGIN ERROR for {data.get('email', 'unknown')}: {e}")
        return jsonify({"error": "Login failed. Please try again."}), 500


@app.route("/api/auth/reset-password", methods=["POST"])
@limiter.limit("5 per hour")
def reset_password():
    """Send password reset email via Supabase Auth."""
    try:
        data  = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()
        if not email:
            return jsonify({"error": "Email is required"}), 400
        supabase.auth.reset_password_email(email)
        return jsonify({"message": "If that email exists, a reset link has been sent."})
    except Exception as e:
        print(f"RESET PASSWORD ERROR: {e}")
        return jsonify({"message": "If that email exists, a reset link has been sent."})


# ==================== GOOGLE OAUTH ====================

@app.route("/api/auth/google", methods=["GET"])
def google_oauth_start():
    try:
        base_url    = os.getenv('APP_URL', 'https://wall-culture-2.onrender.com')
        redirect_to = f"{base_url}/api/auth/google/callback"
        res = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": redirect_to,
                "scopes": "email profile",
                "flow_type": "implicit",
            }
        })
        return flask_redirect(res.url)
    except Exception as e:
        print(f"Google OAuth start error: {e}")
        base_url = os.getenv('APP_URL', 'https://wall-culture-2.onrender.com')
        return flask_redirect(f"{base_url}/index.html?error=oauth_failed")


@app.route("/api/auth/google/callback", methods=["GET"])
def google_oauth_callback():
    base_url = os.getenv('APP_URL', 'https://wall-culture-2.onrender.com')
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Signing you in...</title>
  <style>
    body {{ background:#07070F; color:#FFF8F5; font-family:sans-serif;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
    .msg {{ text-align:center; }}
    .spinner {{ width:40px; height:40px; border:3px solid rgba(255,107,53,0.2);
               border-top-color:#FF6B35; border-radius:50%;
               animation:spin .7s linear infinite; margin:0 auto 16px; }}
    @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
    p {{ font-size:0.9rem; opacity:0.6; margin:0; }}
  </style>
</head>
<body>
<div class="msg">
  <div class="spinner"></div>
  <p>Signing you in with Google...</p>
</div>
<script>
  const hash        = window.location.hash.substring(1);
  const params      = new URLSearchParams(hash);
  const accessToken = params.get('access_token');
  const refreshToken= params.get('refresh_token') || '';
  if (!accessToken) {{
    const qp  = new URLSearchParams(window.location.search);
    const err = qp.get('error') || 'no_token';
    window.location.replace('{base_url}/index.html?error=' + encodeURIComponent(err));
  }} else {{
    fetch('/api/auth/google/exchange', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ access_token: accessToken, refresh_token: refreshToken }})
    }})
    .then(r => r.json())
    .then(data => {{
      if (data.token) {{
        localStorage.setItem('aura_token', data.token);
        localStorage.setItem('aura_user', JSON.stringify(data.user));
        window.location.replace('{base_url}/home.html');
      }} else {{
        window.location.replace('{base_url}/index.html?error=' + encodeURIComponent(data.error || 'exchange_failed'));
      }}
    }})
    .catch(() => window.location.replace('{base_url}/index.html?error=network'));
  }}
</script>
</body>
</html>"""
    return Response(html, mimetype='text/html')


@app.route("/api/auth/google/exchange", methods=["POST"])
def google_oauth_exchange():
    try:
        data         = request.get_json(silent=True) or {}
        access_token = data.get('access_token', '').strip()
        if not access_token:
            return jsonify({'error': 'Missing access token'}), 400

        user_res = supabase.auth.get_user(access_token)
        sb_user  = user_res.user if user_res else None
        if not sb_user:
            return jsonify({'error': 'Invalid token'}), 401

        email = (sb_user.email or '').lower().strip()
        meta  = sb_user.user_metadata or {}
        name  = meta.get('full_name') or meta.get('name') or email.split('@')[0].title()

        if not email:
            return jsonify({'error': 'No email from Google'}), 400

        existing = supabase.table('users').select('*').eq('email', email).execute()
        if existing.data:
            user_row = existing.data[0]
        else:
            user_id            = str(uuid.uuid4())
            user_referral_code = generate_referral_code(name)
            supabase.table('users').insert({
                'id': user_id, 'name': name, 'email': email,
                'password': '', 'referral_code': user_referral_code,
                'referred_by': None, 'points': 100, 'streak': 0,
                'weekly_points': 0, 'created_at': datetime.utcnow().isoformat() + 'Z',
            }).execute()
            user_row = {
                'id': user_id, 'name': name, 'email': email,
                'points': 100, 'streak': 0, 'weekly_points': 0,
                'referral_code': user_referral_code,
            }

        token = jwt.encode(
            {'user_id': user_row['id'], 'exp': datetime.utcnow() + timedelta(days=7)},
            app.config['SECRET_KEY']
        )
        return jsonify({
            'token': token,
            'user': {
                'id':            user_row['id'],
                'name':          user_row.get('name', name),
                'email':         email,
                'points':        user_row.get('points', 0),
                'streak':        user_row.get('streak', 0),
                'weekly_points': user_row.get('weekly_points', 0),
                'referralCode':  user_row.get('referral_code', ''),
            }
        })
    except Exception as e:
        print(f"Google exchange error: {e}")
        return jsonify({'error': 'Sign-in failed. Please try again.'}), 500


# ==================== PRODUCTS (unified catalog) ====================

@app.route('/api/products', methods=['GET'])
@token_required
def get_products():
    """
    Unified product endpoint. Supports filtering by:
      - type:     product_type (poster, clothing, food, accessory, digital)
      - category: sub-category within a type
      - section:  shop_section tab label
      - limited:  true/false
      - limit:    max number of results
    """
    try:
        product_type = request.args.get('type', None)
        category     = request.args.get('category', 'all')
        section      = request.args.get('section', None)
        limited_str  = request.args.get('limited', 'false')
        limit_str    = request.args.get('limit', None)
        limited      = limited_str.lower() == 'true'

        query = supabase.table('products').select('*')

        if product_type:
            query = query.eq('product_type', product_type)
        if section:
            query = query.eq('shop_section', section)
        if category and category != 'all':
            query = query.eq('category', category)
        if limited:
            query = query.eq('is_limited', True)

        query = query.order('created_at', desc=True)

        if limit_str and str(limit_str).isdigit():
            query = query.limit(int(limit_str))

        result   = query.execute()
        products = []
        for p in (result.data or []):
            ptype  = p.get('product_type', 'poster')
            config = SHOP_CONFIG.get(ptype, SHOP_CONFIG['poster'])
            products.append({
                'id':           p.get('id'),
                'name':         p.get('name'),
                'category':     p.get('category'),
                'product_type': ptype,
                'shop_section': p.get('shop_section', 'wall-art'),
                'emoji':        p.get('emoji') or config['emoji'],
                'price':        p.get('price', 40),
                'points':       p.get('points') or int(p.get('price', 40) * config['points_rate']),
                'points_rate':  p.get('points_rate') or config['points_rate'],
                'is_limited':   bool(p.get('is_limited')),
                'image_url':    p.get('image_url'),
                'variants':     p.get('variants') or {},
                'stock':        p.get('stock', 999),
                'created_at':   p.get('created_at'),
            })

        return jsonify(products)
    except Exception as e:
        print(f"GET PRODUCTS ERROR: {e}")
        return jsonify({'error': 'Could not load products.'}), 500


@app.route('/api/posters', methods=['GET'])
@token_required
def get_posters():
    """Backwards-compatible alias — returns only poster-type products."""
    try:
        category    = request.args.get('category', 'all')
        limited_str = request.args.get('limited', 'false')
        limit_str   = request.args.get('limit', None)
        limited     = limited_str.lower() == 'true'

        query = supabase.table('products').select('*').eq('product_type', 'poster')
        if category != 'all':
            query = query.eq('category', category)
        if limited:
            query = query.eq('is_limited', True)
        query = query.order('created_at', desc=True)
        if limit_str and str(limit_str).isdigit():
            query = query.limit(int(limit_str))

        result  = query.execute()
        posters = []
        for p in (result.data or []):
            posters.append({
                'id':         p.get('id'),
                'name':       p.get('name'),
                'category':   p.get('category'),
                'emoji':      p.get('emoji', '🖼️'),
                'price':      p.get('price', 40),
                'points':     p.get('points', 120),
                'is_limited': bool(p.get('is_limited')),
                'image_url':  p.get('image_url'),
                'created_at': p.get('created_at'),
            })
        return jsonify(posters)
    except Exception as e:
        print(f"GET POSTERS ERROR: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/feed', methods=['GET'])
@token_required
def get_feed():
    """Home feed — latest products across all types."""
    try:
        result = supabase.table('products').select('*').order('created_at', desc=True).limit(20).execute()
        feed   = []
        for p in (result.data or []):
            ptype  = p.get('product_type', 'poster')
            config = SHOP_CONFIG.get(ptype, SHOP_CONFIG['poster'])
            feed.append({
                "type":         "product",
                "product_type": ptype,
                "id":           p.get("id"),
                "name":         p.get("name"),
                "image_url":    p.get("image_url"),
                "price":        p.get("price", 40),
                "points":       p.get("points") or int(p.get("price", 40) * config['points_rate']),
                "category":     p.get("category", ""),
                "is_limited":   bool(p.get("is_limited")),
                "shop_section": p.get("shop_section", "wall-art"),
                "emoji":        p.get("emoji") or config['emoji'],
            })
        return jsonify({"feed": feed})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/shop/config', methods=['GET'])
def get_shop_config():
    """Return available shop sections so the frontend can build tabs dynamically."""
    return jsonify(SHOP_CONFIG)


# ==================== QR SCANNING ====================

@app.route('/api/scan/qr', methods=['POST'])
@token_required
def scan_qr():
    try:
        data    = request.get_json(silent=True) or {}
        qr_data = data.get('qr_data', data.get('code', '')).strip().upper()

        if not qr_data:
            return jsonify({'error': 'No QR code detected. Point camera at QR code.'}), 400

        today_start = int(datetime.utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0
        ).timestamp() * 1000)

        qr_result = supabase.table('qr_codes').select('*').eq('code', qr_data).execute()
        if not qr_result.data:
            return jsonify({'error': 'Invalid QR code. This code is not recognized.'}), 404

        qr        = qr_result.data[0]
        is_golden = qr.get('is_golden', 0) == 1

        if is_golden:
            golden_scans = supabase.table('point_logs').select('id', count='exact') \
                .eq('user_id', request.user_id).eq('action', 'Golden QR Scan') \
                .gte('timestamp', today_start).execute()
            if golden_scans.count and golden_scans.count >= 1:
                return jsonify({'error': 'You have already scanned a golden QR today'}), 429
        else:
            scans = supabase.table('point_logs').select('id', count='exact') \
                .eq('user_id', request.user_id).eq('action', 'QR Scan') \
                .gte('timestamp', today_start).execute()
            if scans.count and scans.count >= 5:
                return jsonify({'error': 'Max 5 QR scans per day'}), 429

        current_time = int(datetime.utcnow().timestamp() * 1000)

        if qr.get('expires_at') and qr['expires_at'] < current_time:
            return jsonify({'error': 'This QR code has expired'}), 410

        if qr.get('scanned_by'):
            return jsonify({'error': 'This QR code has already been used'}), 409

        points_to_award = qr.get('points', POINTS['qr_golden'] if is_golden else POINTS['qr_standard'])
        action_label    = 'Golden QR Scan' if is_golden else 'QR Scan'
        earned          = add_points_to_user(request.user_id, points_to_award, action_label)

        supabase.table('qr_codes').update({
            'scanned_by': request.user_id,
            'scanned_at': current_time
        }).eq('code', qr_data).execute()

        return jsonify({
            'success':   True,
            'earned':    earned,
            'points':    points_to_award,
            'is_golden': is_golden,
            'location':  qr.get('location', 'Campus Location'),
            'message':   f"🎉 +{earned} points! {'✨ GOLDEN QR ✨ ' if is_golden else ''}"
        })
    except Exception as e:
        print(f"QR scan error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/qr/list', methods=['GET'])
@token_required
def list_qr_codes():
    try:
        result = supabase.table('qr_codes').select('code, location, points, is_golden, scanned_by').execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== SOCIAL SUBMISSIONS ====================

@app.route('/api/social/story', methods=['POST'])
@token_required
def social_story():
    try:
        data       = request.get_json(silent=True) or {}
        story_link = data.get('story_link', '').strip()

        if not story_link:
            return jsonify({'error': 'Please provide your Instagram story link'}), 400
        if 'instagram.com' not in story_link:
            return jsonify({'error': 'Please provide a valid Instagram story link'}), 400

        pending = supabase.table('pending_submissions').select('id', count='exact') \
            .eq('user_id', request.user_id).eq('type', 'story').eq('status', 'pending').execute()
        if pending.count and pending.count >= 1:
            return jsonify({'error': 'You already have a story pending review.'}), 429

        week_start = int((datetime.utcnow() - timedelta(days=7)).timestamp() * 1000)
        approved   = supabase.table('point_logs').select('id', count='exact') \
            .eq('user_id', request.user_id).eq('action', 'Instagram Story') \
            .gte('timestamp', week_start).execute()
        if approved.count and approved.count >= 3:
            return jsonify({'error': 'Max 3 approved story shares per week'}), 429

        supabase.table('pending_submissions').insert({
            'id': str(uuid.uuid4()), 'user_id': request.user_id,
            'type': 'story', 'url': story_link, 'status': 'pending',
            'points': POINTS['story_share'],
            'submitted_at': int(datetime.utcnow().timestamp() * 1000)
        }).execute()

        return jsonify({
            'success': True, 'pending': True,
            'message': "⏳ Story submitted! You'll receive your coins once an admin approves it."
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/social/roomtour', methods=['POST'])
@token_required
def room_tour():
    try:
        data     = request.get_json(silent=True) or {}
        tour_url = data.get('url', '').strip()

        if not tour_url:
            return jsonify({'error': 'Please provide a link to your room tour post'}), 400

        pending = supabase.table('pending_submissions').select('id', count='exact') \
            .eq('user_id', request.user_id).eq('type', 'roomtour').eq('status', 'pending').execute()
        if pending.count and pending.count >= 1:
            return jsonify({'error': 'You already have a room tour pending review.'}), 429

        month_start = int(datetime.utcnow().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        ).timestamp() * 1000)
        approved = supabase.table('point_logs').select('id', count='exact') \
            .eq('user_id', request.user_id).eq('action', 'Room Tour') \
            .gte('timestamp', month_start).execute()
        if approved.count and approved.count >= 1:
            return jsonify({'error': 'Room tour already approved this month'}), 429

        supabase.table('pending_submissions').insert({
            'id': str(uuid.uuid4()), 'user_id': request.user_id,
            'type': 'roomtour', 'url': tour_url, 'status': 'pending',
            'points': POINTS['room_tour'],
            'submitted_at': int(datetime.utcnow().timestamp() * 1000)
        }).execute()

        return jsonify({
            'success': True, 'pending': True,
            'message': "⏳ Room tour submitted! You'll receive your coins once an admin approves it."
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/social/submissions', methods=['GET'])
@token_required
def my_submissions():
    try:
        result = supabase.table('pending_submissions') \
            .select('id, type, url, status, points, submitted_at, reviewed_at') \
            .eq('user_id', request.user_id) \
            .order('submitted_at', desc=True).limit(20).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ADMIN ROUTES ====================

@app.route('/api/admin/submissions', methods=['GET'])
@admin_required
def admin_list_submissions():
    try:
        status_filter = request.args.get('status', 'pending')
        query = supabase.table('pending_submissions').select(
            'id, user_id, type, url, status, points, submitted_at, reviewed_at'
        ).order('submitted_at', desc=True)
        if status_filter != 'all':
            query = query.eq('status', status_filter)
        result = query.limit(100).execute()

        submissions = result.data or []
        user_ids    = list({s['user_id'] for s in submissions})
        users_map   = {}
        if user_ids:
            users_res = supabase.table('users').select('id, name, email').in_('id', user_ids).execute()
            users_map = {u['id']: u for u in (users_res.data or [])}
        for s in submissions:
            u = users_map.get(s['user_id'], {})
            s['user_name']  = u.get('name', 'Unknown')
            s['user_email'] = u.get('email', '')
        return jsonify(submissions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/submissions/<sub_id>/approve', methods=['POST'])
@admin_required
def admin_approve_submission(sub_id):
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
    try:
        result = supabase.table('pending_submissions').select('*').eq('id', sub_id).execute()
        if not result.data:
            return jsonify({'error': 'Submission not found'}), 404
        sub = result.data[0]
        if sub['status'] != 'pending':
            return jsonify({'error': f'Submission is already {sub["status"]}'}), 400
        data   = request.get_json(silent=True) or {}
        reason = data.get('reason', 'Did not meet requirements')
        supabase.table('pending_submissions').update({
            'status': 'rejected', 'reject_reason': reason,
            'reviewed_at': int(datetime.utcnow().timestamp() * 1000)
        }).eq('id', sub_id).execute()
        return jsonify({'success': True, 'message': 'Submission rejected.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/products', methods=['POST'])
@admin_required
def admin_create_product():
    """Admin: create a new product of any type."""
    try:
        data         = request.get_json(silent=True) or {}
        product_type = data.get('product_type', 'poster')
        config       = SHOP_CONFIG.get(product_type, SHOP_CONFIG['poster'])

        for field in ['name', 'price', 'product_type']:
            if not data.get(field):
                return jsonify({'error': f'Missing field: {field}'}), 400

        price       = float(data['price'])
        points_rate = int(data.get('points_rate') or config['points_rate'])

        product = {
            'id':           str(uuid.uuid4()),
            'name':         data['name'],
            'price':        price,
            'product_type': product_type,
            'category':     data.get('category', 'general'),
            'shop_section': data.get('shop_section', config['label'].lower()),
            'image_url':    data.get('image_url', ''),
            'emoji':        data.get('emoji', config['emoji']),
            'points':       int(price * points_rate),
            'points_rate':  points_rate,
            'is_limited':   bool(data.get('is_limited', False)),
            'variants':     data.get('variants', {}),
            'stock':        int(data.get('stock', 999)),
            'created_at':   datetime.utcnow().isoformat() + 'Z',
        }

        supabase.table('products').insert(product).execute()
        return jsonify({'success': True, 'product': product}), 201
    except Exception as e:
        print(f"ADMIN CREATE PRODUCT ERROR: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/products/<product_id>', methods=['PATCH'])
@admin_required
def admin_update_product(product_id):
    """Admin: update an existing product."""
    try:
        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        for field in ['id', 'created_at']:
            data.pop(field, None)
        supabase.table('products').update(data).eq('id', product_id).execute()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== DAILY CHECK-IN ====================

@app.route('/api/daily/checkin', methods=['POST'])
@token_required
def daily_checkin():
    try:
        result    = supabase.table('users').select('last_checkin, streak').eq('id', request.user_id).execute()
        user_data = result.data[0] if result.data else {'last_checkin': None, 'streak': 0}
        today     = datetime.utcnow().date().isoformat()

        if user_data.get('last_checkin') == today:
            return jsonify({'success': False, 'message': 'Already checked in today'})

        new_streak = 1
        bonus      = 0

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
        earned       = add_points_to_user(request.user_id, total_points, 'Daily check-in')

        supabase.table('users').update({
            'last_checkin': today,
            'streak':       new_streak
        }).eq('id', request.user_id).execute()

        check_referral_milestones(request.user_id)

        return jsonify({
            'success': True, 'points': total_points,
            'earned': earned, 'streak': new_streak, 'bonus': bonus
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ORDER ====================

@app.route('/api/order/create', methods=['POST'])
@token_required
def create_order():
    try:
        data        = request.get_json(silent=True) or {}
        items       = data.get('items', [])
        total_price = data.get('totalPrice', 0)

        if not items:
            return jsonify({'error': 'No items in order'}), 400

        order_id = str(uuid.uuid4())

        # Calculate points dynamically from each item's product_type
        total_base_points = 0
        for item in items:
            ptype  = item.get('product_type', item.get('type', 'poster'))
            config = SHOP_CONFIG.get(ptype, SHOP_CONFIG['poster'])
            rate   = item.get('points_rate') or config['points_rate']
            total_base_points += int(item.get('price', 0) * rate)

        earned = add_points_to_user(request.user_id, total_base_points, 'Purchase order')

        # +250 bonus for orders >= KSH 140
        if total_price >= 140:
            bonus_earned = add_points_to_user(request.user_id, POINTS['large_order_bonus'], 'Large order bonus')
            earned += bonus_earned

        # Determine best multiplier
        new_multiplier = 1.0
        best_type      = 'standard'
        type_priority  = {'bundle': 4, 'mystery': 3, 'limited': 2, 'standard': 1}
        for item in items:
            itype = item.get('type', item.get('itemType', 'standard'))
            if type_priority.get(itype, 1) > type_priority.get(best_type, 1):
                best_type = itype

        if best_type == 'bundle' or total_price >= 140:
            new_multiplier = 2.0
            best_type      = 'bundle'
        elif best_type in ('mystery', 'limited'):
            new_multiplier = 1.5
        else:
            new_multiplier = 1.2

        duration_days     = MULTIPLIER_DURATIONS.get(best_type, 3)
        multiplier_expiry = int((datetime.utcnow() + timedelta(days=duration_days)).timestamp() * 1000)

        supabase.table('orders').insert({
            'id': order_id, 'user_id': request.user_id,
            'items': json.dumps(items), 'total_price': total_price,
            'total_points': earned, 'boost_given': new_multiplier,
            'status': 'completed', 'created_at': datetime.utcnow().isoformat() + 'Z'
        }).execute()

        supabase.table('users').update({
            'multiplier':        new_multiplier,
            'multiplier_expiry': multiplier_expiry
        }).eq('id', request.user_id).execute()

        # Referral first-purchase bonus
        try:
            user_res      = supabase.table('users').select('referred_by').eq('id', request.user_id).execute()
            referrer_code = user_res.data[0].get('referred_by') if user_res.data else None
            if referrer_code:
                prev_orders = supabase.table('orders').select('id', count='exact').eq('user_id', request.user_id).execute()
                if prev_orders.count and prev_orders.count == 1:
                    ref_res = supabase.table('users').select('id').eq('referral_code', referrer_code).execute()
                    if ref_res.data:
                        add_points_to_user(ref_res.data[0]['id'], POINTS['referral_first_purchase'], 'Referral first purchase')
        except Exception as ref_err:
            print(f"Referral first-purchase bonus error: {ref_err}")

        check_referral_milestones(request.user_id)

        return jsonify({
            'success':        True,
            'orderId':        order_id,
            'pointsEarned':   earned,
            'newMultiplier':  new_multiplier,
            'multiplierDays': duration_days
        })
    except Exception as e:
        print(f"CREATE ORDER ERROR: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== LEADERBOARDS ====================

@app.route('/api/leaderboard/alltime', methods=['GET'])
@token_required
def get_alltime_leaderboard():
    try:
        result = supabase.table('users').select('id, name, points') \
            .order('points', desc=True).limit(50).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/leaderboard/weekly', methods=['GET'])
@token_required
def get_weekly_leaderboard():
    try:
        result = supabase.table('users').select('id, name, weekly_points') \
            .order('weekly_points', desc=True).limit(50).execute()
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
        user        = user_result.data[0]
        logs        = supabase.table('point_logs').select('action, earned, timestamp') \
            .eq('user_id', request.user_id).order('timestamp', desc=True).limit(20).execute()
        rank_result = supabase.table('users').select('id', count='exact').gt('points', user['points']).execute()
        rank        = (rank_result.count or 0) + 1
        return jsonify({'user': user, 'auditLog': logs.data or [], 'rank': rank})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/user/status', methods=['GET'])
@token_required
def get_user_status():
    try:
        result = supabase.table('users').select(
            'points, streak, multiplier, multiplier_expiry, weekly_points'
        ).eq('id', request.user_id).execute()
        return jsonify(result.data[0] if result.data else {})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== REFERRAL ====================

@app.route('/api/referral/info', methods=['GET'])
@token_required
def get_referral_info():
    try:
        user_result   = supabase.table('users').select('referral_code').eq('id', request.user_id).execute()
        referral_code = user_result.data[0]['referral_code'] if user_result.data else None
        return jsonify({'referralCode': referral_code, 'referrals': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== HEALTH ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status':  'healthy',
        'app':     'Aura',
        'version': '3.0.0',
        'shops':   list(SHOP_CONFIG.keys())
    })


# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 55)
    print("🎨  AURA BACKEND v3.0.0 — Multi-Product Architecture")
    print("=" * 55)
    print(f"📍  Running on: http://localhost:5000")
    print(f"🛍️   Active shop types: {', '.join(SHOP_CONFIG.keys())}")
    print("✅  /api/products  — unified product endpoint")
    print("✅  /api/posters   — backwards-compatible alias")
    print("✅  /api/shop/config — dynamic shop tabs")
    print("✅  Admin: create & update products via API")
    print("✅  Dynamic points_rate per product type")
    print("✅  Password reset endpoint implemented")
    print("✅  Rate limiting on login (10/min) and register (20/hr)")
    print("✅  QR Scanning, Streaks, Referrals, Leaderboards")
    print("=" * 55 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)