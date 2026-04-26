# app.py - Wall Culture Flask Backend (FIXED)
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from supabase import create_client, Client
import uuid
import jwt
import bcrypt
import os
import secrets
import hashlib
import re
from datetime import datetime, timedelta
from functools import wraps
import json
from dotenv import load_dotenv
import sys

load_dotenv()

app = Flask(__name__, static_folder='.')

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Security
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5000,http://127.0.0.1:5000,https://wall-culture-3.onrender.com').split(',')
CORS(app, origins=[o.strip() for o in ALLOWED_ORIGINS])

# Secret Key - ensure minimum 32 bytes
_secret = os.getenv('JWT_SECRET')
if not _secret or len(_secret) < 32:
    print("⚠️ JWT_SECRET too short. Generating secure key...")
    _secret = secrets.token_hex(32)
    print(f"Add this to your .env: JWT_SECRET={_secret}")
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
}

# ==================== HELPERS ====================

def generate_referral_code(name):
    return name[:4].upper() + str(uuid.uuid4().hex[:4]).upper()

def parse_bool(value):
    """Convert string boolean to integer for Supabase"""
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, str):
        return 1 if value.lower() in ('true', '1', 'yes') else 0
    return 1 if value else 0

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
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# ==================== STATIC FILE SERVING ====================

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/home.html')
def serve_home():
    return send_from_directory('.', 'home.html')

@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory('.', path)

# ==================== AUTH ROUTES ====================

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("10 per minute")
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

        supabase.table("users").insert({
            "id": user_id, "name": name, "email": email, "password": hashed_password,
            "referral_code": user_referral_code, "referred_by": referral_code,
            "points": 100, "streak": 0, "weekly_points": 0,
            "created_at": datetime.utcnow().isoformat() + 'Z'
        }).execute()

        if referrer_id:
            add_points_to_user(referrer_id, POINTS['referral_signup'], "Referral signup")

        token = jwt.encode({"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)}, app.config["SECRET_KEY"])
        return jsonify({"token": token, "user": {
            "id": user_id, "name": name, "email": email, "points": 100,
            "streak": 0, "weekly_points": 0, "referralCode": user_referral_code
        }})
    except Exception as e:
        print(f"REGISTER ERROR: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
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
        return jsonify({"token": token, "user": {
            "id": user["id"], "name": user["name"], "email": user["email"],
            "points": user.get("points", 0), "streak": user.get("streak", 0),
            "weekly_points": user.get("weekly_points", 0), "referralCode": user.get("referral_code", "")
        }})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== POSTERS (FIXED BOOLEAN HANDLING) ====================

@app.route('/api/posters', methods=['GET'])
@token_required
def get_posters():
    try:
        category = request.args.get('category', 'all')
        limited_str = request.args.get('limited', 'false')
        limit_str = request.args.get('limit', None)
        
        # FIX: Convert string 'true'/'false' to boolean properly
        limited = limited_str.lower() == 'true'
        
        query = supabase.table('posters').select('*')
        
        if category != 'all':
            query = query.eq('category', category)
        if limited:
            query = query.eq('is_limited', 1)  # Use integer 1 instead of True
        
        query = query.order('created_at', desc=True)
        
        if limit_str and limit_str.isdigit():
            query = query.limit(int(limit_str))
        
        result = query.execute()
        return jsonify(result.data or [])
    except Exception as e:
        print(f"get_posters error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== QR SCAN ====================

@app.route('/api/scan/qr', methods=['POST'])
@token_required
@limiter.limit("20 per minute")
def scan_qr():
    try:
        data = request.get_json(silent=True) or {}
        qr_data = data.get('qr_data', '').strip().upper()

        if not qr_data:
            return jsonify({'error': 'No QR code detected'}), 400

        today_start = int(datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000)
        scans = supabase.table('point_logs').select('id', count='exact').eq('user_id', request.user_id).eq('action', 'QR Scan').gte('timestamp', today_start).execute()
        
        if scans.count and scans.count >= 5:
            return jsonify({'error': 'Max 5 QR scans per day'}), 429

        qr_result = supabase.table('qr_codes').select('*').eq('code', qr_data).execute()
        
        if not qr_result.data:
            return jsonify({'error': 'Invalid QR code'}), 404

        qr = qr_result.data[0]
        current_time = int(datetime.utcnow().timestamp() * 1000)

        if qr.get('expires_at') and qr['expires_at'] < current_time:
            return jsonify({'error': 'QR code expired'}), 410

        if qr.get('scanned_by'):
            return jsonify({'error': 'QR code already used'}), 409

        points_to_award = qr['points']
        is_golden = qr.get('is_golden', 0) == 1
        earned = add_points_to_user(request.user_id, points_to_award, 'QR Scan')

        supabase.table('qr_codes').update({
            'scanned_by': request.user_id,
            'scanned_at': current_time
        }).eq('code', qr_data).execute()

        return jsonify({
            'success': True,
            'earned': earned,
            'points': points_to_award,
            'is_golden': is_golden,
            'message': f"🎉 +{earned} points! {'✨ GOLDEN QR ✨ ' if is_golden else ''}"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== DAILY CHECK-IN ====================

@app.route('/api/daily/checkin', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
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

        return jsonify({
            'success': True,
            'points': total_points,
            'earned': earned,
            'streak': new_streak,
            'bonus': bonus
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== SOCIAL ACTIONS ====================

@app.route('/api/social/story', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def social_story():
    try:
        week_start = int((datetime.utcnow() - timedelta(days=7)).timestamp() * 1000)
        shares = supabase.table('point_logs').select('id', count='exact').eq('user_id', request.user_id).eq('action', 'Instagram Story').gte('timestamp', week_start).execute()
        
        if shares.count and shares.count >= 3:
            return jsonify({'error': 'Max 3 story shares per week'}), 429

        earned = add_points_to_user(request.user_id, POINTS['story_share'], 'Instagram Story')
        return jsonify({'success': True, 'earned': earned})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/social/roomtour', methods=['POST'])
@token_required
@limiter.limit("5 per minute")
def room_tour():
    try:
        month_start = int(datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000)
        tours = supabase.table('point_logs').select('id', count='exact').eq('user_id', request.user_id).eq('action', 'Room Tour').gte('timestamp', month_start).execute()
        
        if tours.count and tours.count >= 1:
            return jsonify({'error': 'Room tour already used this month'}), 429

        earned = add_points_to_user(request.user_id, POINTS['room_tour'], 'Room Tour')
        return jsonify({'success': True, 'earned': earned})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ORDER / CHECKOUT ====================

@app.route('/api/order/create', methods=['POST'])
@token_required
@limiter.limit("20 per minute")
def create_order():
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items', [])
        total_price = data.get('totalPrice', 0)
        total_base_points = data.get('totalBasePoints', 0)

        if not items:
            return jsonify({'error': 'No items in order'}), 400

        order_id = str(uuid.uuid4())
        earned = add_points_to_user(request.user_id, total_base_points, 'Purchase order')

        new_multiplier = 1.2
        for item in items:
            if item.get('type') == 'mystery':
                new_multiplier = max(new_multiplier, 1.5)
            elif item.get('type') == 'limited':
                new_multiplier = max(new_multiplier, 1.8)
        if total_price >= 140:
            new_multiplier = max(new_multiplier, 2.0)

        supabase.table('orders').insert({
            'id': order_id, 'user_id': request.user_id, 'items': json.dumps(items),
            'total_price': total_price, 'total_points': earned,
            'boost_given': new_multiplier, 'status': 'completed',
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }).execute()

        supabase.table('users').update({
            'multiplier': new_multiplier,
            'multiplier_expiry': int((datetime.utcnow() + timedelta(days=7)).timestamp() * 1000)
        }).eq('id', request.user_id).execute()

        return jsonify({'success': True, 'orderId': order_id, 'pointsEarned': earned, 'newMultiplier': new_multiplier})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== LEADERBOARDS & PROFILE ====================

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


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'app': 'Wall Culture', 'version': '1.4.0'})


if __name__ == '__main__':
    print("\n" + "="*50)
    print("🎨 WALL CULTURE BACKEND v1.4.0")
    print("="*50)
    print(f"📍 Running on: http://localhost:5000")
    print("✅ JWT_SECRET: " + ("Set" if _secret else "Missing"))
    print("✅ Supabase: Connected")
    print("="*50 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)