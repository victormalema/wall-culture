 # app.py - Wall Culture Flask Backend (UPDATED v1.3.0)
# KSH Pricing | Enhanced Points | Social Growth Optimized
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
from datetime import datetime, timedelta
from functools import wraps
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ==================== SECURITY: Strict CORS ====================
ALLOWED_ORIGINS = os.getenv(
    'ALLOWED_ORIGINS',
    'http://localhost:5000,http://127.0.0.1:5000,https://wall-culture.onrender.com'
).split(',')
CORS(app, origins=[o.strip() for o in ALLOWED_ORIGINS])

# ==================== SECRET KEY ====================
_secret = os.getenv('JWT_SECRET')
if not _secret:
    raise RuntimeError("JWT_SECRET environment variable is not set.")
app.config['SECRET_KEY'] = _secret

# ==================== RATE LIMITING ====================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# ==================== SUPABASE ====================
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_KEY in .env file")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
print("✅ Connected to Supabase")

# ==================== POINTS CONSTANTS ====================
POINTS = {
    'story_share': 150,
    'referral_signup': 200,
    'referral_purchase': 300,
    'referral_milestone_500': 500,
    'referral_milestone_1000': 800,
    'qr_standard': 25,
    'qr_golden': 150,
    'daily_checkin_base': 10,
    'daily_streak_7': 100,
    'daily_streak_14': 300,
    'daily_streak_30': 1000,
    'room_tour': 250,
    'tag_friend': 50,
    'whatsapp_share': 80,
    'challenge_entry': 400,
    'challenge_first10': 200,
    'challenge_share': 100
}

# ==================== HELPERS ====================

def generate_referral_code(name):
    return name[:4].upper() + str(uuid.uuid4().hex[:4]).upper()


def add_points_to_user(user_id, base_points, action, custom_multiplier=None):
    """Award points atomically via Supabase RPC"""
    try:
        result = supabase.rpc('award_points', {
            'p_user_id': user_id,
            'p_base': int(base_points),
            'p_action': action,
            'p_multiplier': custom_multiplier
        }).execute()
        return result.data or 0
    except Exception as rpc_err:
        print(f"Warning: award_points RPC failed, using fallback: {rpc_err}")
        try:
            user_res = supabase.table('users').select(
                'points, weekly_points, multiplier, multiplier_expiry'
            ).eq('id', user_id).execute()
            if not user_res.data:
                return 0
            u = user_res.data[0]
            current_time = int(datetime.utcnow().timestamp() * 1000)
            if custom_multiplier:
                effective = custom_multiplier
            elif u.get('multiplier_expiry') and u['multiplier_expiry'] > current_time:
                effective = u.get('multiplier', 1.0)
            else:
                effective = 1.0
            earned = int(base_points * effective)
            supabase.table('users').update({
                'points': u['points'] + earned,
                'weekly_points': (u.get('weekly_points') or 0) + earned
            }).eq('id', user_id).execute()
            try:
                supabase.table('point_logs').insert({
                    'user_id': user_id,
                    'action': action,
                    'points': base_points,
                    'multiplier': effective,
                    'earned': earned,
                    'timestamp': current_time
                }).execute()
            except Exception as log_err:
                print(f"Warning: could not write point_log: {log_err}")
            return earned
        except Exception as e:
            print(f"Error adding points (fallback): {e}")
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
            return jsonify({"error": "An account with this email already exists"}), 400

        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_referral_code = generate_referral_code(name)

        referrer_id = None
        if referral_code:
            ref_result = supabase.table("users").select("id").eq("referral_code", referral_code).execute()
            if ref_result.data and ref_result.data[0]["id"] != user_id:
                referrer_id = ref_result.data[0]["id"]
            else:
                referral_code = None

        now_iso = datetime.utcnow().isoformat() + 'Z'

        supabase.table("users").insert({
            "id": user_id,
            "name": name,
            "email": email,
            "password": hashed_password,
            "referral_code": user_referral_code,
            "referred_by": referral_code,
            "points": 100,
            "streak": 0,
            "weekly_points": 0,
            "created_at": now_iso
        }).execute()

        if referrer_id:
            try:
                supabase.table("referrals").insert({
                    "referrer_id": referrer_id,
                    "referee_id": user_id,
                    "created_at": int(datetime.utcnow().timestamp() * 1000)
                }).execute()
                add_points_to_user(referrer_id, POINTS['referral_signup'], "Referral bonus")
            except Exception as ref_err:
                print(f"Warning: could not record referral: {ref_err}")

        token = jwt.encode(
            {"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)},
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({
            "token": token,
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
                "points": 100,
                "streak": 0,
                "weekly_points": 0,
                "referral_code": user_referral_code,
                "referralCode": user_referral_code
            }
        })
    except Exception as e:
        print("REGISTER ERROR:", str(e))
        return jsonify({"error": "Server error"}), 500


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

        dummy_hash = "$2b$12$placeholderplaceholderplaceholderplaceholderplaceholde"
        stored_hash = result.data[0]["password"] if result.data else dummy_hash
        password_ok = bcrypt.checkpw(password.encode(), stored_hash.encode())

        if not result.data or not password_ok:
            return jsonify({"error": "Invalid email or password"}), 401

        user = result.data[0]

        token = jwt.encode(
            {"user_id": user["id"], "exp": datetime.utcnow() + timedelta(days=7)},
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        if isinstance(token, bytes):
            token = token.decode('utf-8')

        return jsonify({
            "token": token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "points": user.get("points", 0),
                "streak": user.get("streak", 0),
                "weekly_points": user.get("weekly_points", 0),
                "referral_code": user.get("referral_code", ""),
                "referralCode": user.get("referral_code", "")
            }
        })
    except Exception as e:
        print("LOGIN ERROR:", str(e))
        return jsonify({"error": "Server error"}), 500


# ==================== QR / CAMERA SCAN ====================

@app.route('/api/scan/qr', methods=['POST'])
@token_required
@limiter.limit("20 per minute")
def scan_qr():
    try:
        data = request.get_json(silent=True) or {}
        code = data.get('code')

        today_start = int(datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000)

        scans = supabase.table('point_logs').select(
            'id', count='exact'
        ).eq('user_id', request.user_id).eq('action', 'QR Scan').gte('timestamp', today_start).execute()

        if scans.count and scans.count >= 5:
            return jsonify({'error': 'Max 5 QR scans per day'}), 429

        if not code:
            earned = add_points_to_user(request.user_id, POINTS['qr_standard'], 'QR Scan')
            return jsonify({'success': True, 'earned': earned, 'points': POINTS['qr_standard']})

        qr_result = supabase.table('qr_codes').select('*').eq('code', code.upper()).execute()
        if not qr_result.data:
            return jsonify({'error': 'Invalid QR code'}), 404

        qr = qr_result.data[0]
        current_time = int(datetime.utcnow().timestamp() * 1000)

        if qr.get('expires_at') and qr['expires_at'] < current_time:
            return jsonify({'error': 'QR code expired'}), 410

        if qr.get('scanned_by'):
            return jsonify({'error': 'QR code already used'}), 409

        earned = add_points_to_user(request.user_id, qr['points'], 'QR Scan')

        supabase.table('qr_codes').update({
            'scanned_by': request.user_id,
            'scanned_at': current_time
        }).eq('code', code.upper()).execute()

        return jsonify({
            'success': True,
            'earned': earned,
            'points': qr['points'],
            'is_golden': qr.get('is_golden', 0) == 1,
            'message': f"You earned {earned} points from {'✨ GOLDEN ✨ ' if qr.get('is_golden') else ''}QR code!"
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
        shares = supabase.table('point_logs').select(
            'id', count='exact'
        ).eq('user_id', request.user_id).eq('action', 'Instagram Story').gte('timestamp', week_start).execute()

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
        month_start_dt = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_start = int(month_start_dt.timestamp() * 1000)

        tours = supabase.table('point_logs').select(
            'id', count='exact'
        ).eq('user_id', request.user_id).eq('action', 'Room Tour').gte('timestamp', month_start).execute()

        if tours.count and tours.count >= 1:
            return jsonify({'error': 'Room tour already used this month'}), 429

        earned = add_points_to_user(request.user_id, POINTS['room_tour'], 'Room Tour')
        return jsonify({'success': True, 'earned': earned})
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
            bonus = POINTS['daily_streak_7']
        elif new_streak == 14:
            bonus = POINTS['daily_streak_14']
        elif new_streak == 30:
            bonus = POINTS['daily_streak_30']

        total_points = POINTS['daily_checkin_base'] + bonus
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


# ==================== REFERRAL MILESTONE ====================

@app.route('/api/referral/milestone', methods=['POST'])
@token_required
def referral_milestone():
    try:
        data = request.get_json(silent=True) or {}
        friend_id = data.get('friend_id')
        milestone = data.get('milestone')

        result = supabase.table('users').select('referred_by').eq('id', friend_id).execute()
        if not result.data or not result.data[0].get('referred_by'):
            return jsonify({'error': 'No referrer found'}), 404

        referrer_code = result.data[0]['referred_by']
        referrer = supabase.table('users').select('id').eq('referral_code', referrer_code).execute()

        if not referrer.data:
            return jsonify({'error': 'Referrer not found'}), 404

        points_map = {500: POINTS['referral_milestone_500'], 1000: POINTS['referral_milestone_1000']}
        points = points_map.get(milestone, 0)

        if points:
            earned = add_points_to_user(referrer.data[0]['id'], points, f'Referral milestone: friend reached {milestone} pts')
            return jsonify({'success': True, 'earned': earned})

        return jsonify({'success': False})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== POSTERS / FEED ====================

@app.route('/api/posters', methods=['GET'])
@token_required
def get_posters():
    try:
        category = request.args.get('category', 'all')
        limited = request.args.get('limited', 'false').lower() == 'true'
        limit = request.args.get('limit', None)

        query = supabase.table('posters').select('*')

        if category != 'all':
            query = query.eq('category', category)
        if limited:
            query = query.eq('is_limited', True)

        query = query.order('created_at', desc=True)

        if limit:
            query = query.limit(int(limit))

        result = query.execute()
        return jsonify(result.data or [])
    except Exception as e:
        print(f"get_posters error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/feed', methods=['GET'])
@token_required
def get_feed():
    try:
        result = supabase.table('posters').select('*').order('created_at', desc=True).execute()
        feed = []
        for poster in (result.data or []):
            feed.append({
                "type": "poster",
                "id": poster["id"],
                "name": poster["name"],
                "image_url": poster.get("image_url", ""),
                "price": poster.get("price", 0),
                "points": poster.get("points", 0),
                "category": poster.get("category", ""),
                "is_limited": poster.get("is_limited", False)
            })
        return jsonify({"feed": feed}), 200
    except Exception as e:
        print(f"get_feed error: {e}")
        return jsonify({"error": str(e)}), 500


# ==================== ORDERS ====================

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
        now_iso = datetime.utcnow().isoformat() + 'Z'

        user_result = supabase.table('users').select('multiplier, multiplier_expiry').eq('id', request.user_id).execute()
        u = user_result.data[0] if user_result.data else {'multiplier': 1.0, 'multiplier_expiry': 0}

        earned = add_points_to_user(request.user_id, total_base_points, 'Purchase order')

        # Determine new multiplier based on cart (KSH pricing)
        new_multiplier = 1.2
        for item in items:
            if item.get('type') == 'mystery':
                new_multiplier = max(new_multiplier, 1.5)
            elif item.get('type') == 'limited':
                new_multiplier = max(new_multiplier, 1.8)

        if total_price >= 140:  # Room bundle (140 KSH) or more
            new_multiplier = max(new_multiplier, 2.0)

        supabase.table('orders').insert({
            'id': order_id,
            'user_id': request.user_id,
            'items': json.dumps(items),
            'total_price': total_price,
            'total_points': earned,
            'boost_given': new_multiplier,
            'status': 'completed',
            'created_at': now_iso
        }).execute()

        supabase.table('users').update({
            'multiplier': new_multiplier,
            'multiplier_expiry': int((datetime.utcnow() + timedelta(days=7)).timestamp() * 1000)
        }).eq('id', request.user_id).execute()

        return jsonify({
            'success': True,
            'orderId': order_id,
            'pointsEarned': earned,
            'newMultiplier': new_multiplier
        })
    except Exception as e:
        print(f"create_order error: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== QR CODE GENERATION ====================

@app.route('/api/qr/generate', methods=['POST'])
@token_required
def generate_qr():
    try:
        data = request.get_json(silent=True) or {}
        qr_type = data.get('type', 'sticker')

        timestamp = int(datetime.utcnow().timestamp() * 1000)
        unique_string = f"{qr_type}_{data.get('poster_id', data.get('location', ''))}_{timestamp}_{secrets.token_hex(4)}"
        code = hashlib.md5(unique_string.encode()).hexdigest()[:16].upper()

        existing = supabase.table('qr_codes').select('code').eq('code', code).execute()
        if existing.data:
            code = hashlib.md5((unique_string + secrets.token_hex(4)).encode()).hexdigest()[:16].upper()

        is_golden = data.get('is_golden', False)
        points = data.get('points', POINTS['qr_golden'] if is_golden else POINTS['qr_standard'])

        qr_data = {
            'code': code,
            'points': points,
            'is_golden': 1 if is_golden else 0,
            'created_by': request.user_id,
            'created_at': timestamp,
            'expires_at': timestamp + (24 * 60 * 60 * 1000) if is_golden else None
        }

        if qr_type == 'poster':
            poster = supabase.table('posters').select('id, name').eq('id', data.get('poster_id')).execute()
            if not poster.data:
                return jsonify({'error': 'Poster not found'}), 404
            qr_data['poster_id'] = data.get('poster_id')
            qr_data['location'] = f"Poster: {poster.data[0].get('name', data.get('poster_id'))}"
        else:
            qr_data['location'] = data.get('location', 'Campus Location')

        supabase.table('qr_codes').insert(qr_data).execute()

        qr_api_url = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={code}"

        return jsonify({
            'success': True,
            'qr_code': code,
            'qr_image_url': qr_api_url,
            'points': qr_data['points'],
            'is_golden': qr_data['is_golden'] == 1,
            'location': qr_data['location']
        })
    except Exception as e:
        print(f"QR generation error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/qr/list', methods=['GET'])
@token_required
def get_qr_codes():
    try:
        result = supabase.table('qr_codes').select('*').is_('scanned_by', 'null').execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


# ==================== USER PROFILE ====================

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile():
    try:
        user_result = supabase.table('users').select(
            'id, name, email, points, weekly_points, streak, multiplier, '
            'multiplier_expiry, referral_code, last_checkin'
        ).eq('id', request.user_id).execute()

        if not user_result.data:
            return jsonify({'error': 'User not found'}), 404

        user = user_result.data[0]

        audit_log = []
        try:
            logs = supabase.table('point_logs').select(
                'action, earned, timestamp'
            ).eq('user_id', request.user_id).order('timestamp', desc=True).limit(20).execute()
            audit_log = logs.data or []
        except Exception:
            pass

        rank = 1
        try:
            rank_result = supabase.table('users').select('id', count='exact').gt('points', user['points']).execute()
            rank = (rank_result.count or 0) + 1
        except Exception:
            pass

        return jsonify({
            'user': user,
            'auditLog': audit_log,
            'rank': rank
        })
    except Exception as e:
        print(f"get_profile error: {e}")
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


# ==================== PASSWORD RESET ====================

@app.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit("5 per minute")
def request_password_reset():
    try:
        data = request.get_json(silent=True) or {}
        email = data.get('email', '').strip().lower()
        if email:
            try:
                supabase.auth.reset_password_email(email)
            except Exception as e:
                print(f"Password reset error (not exposed): {e}")
        return jsonify({'success': True, 'message': 'If that email exists, a reset link has been sent.'})
    except Exception as e:
        return jsonify({'error': 'Server error'}), 500


# ==================== STATIC FILE SERVING ====================

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')


@app.route('/home.html')
def serve_home():
    return send_from_directory('.', 'home.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)


# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'app': 'Wall Culture',
        'version': '1.3.0',
        'points_version': 'KSH Optimized',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })


if __name__ == '__main__':
    print("\n" + "="*50)
    print("🎨 WALL CULTURE BACKEND v1.3.0")
    print("="*50)
    print(f"📍 Running on: http://localhost:5000")
    print(f"📡 Supabase:   {SUPABASE_URL}")
    print(f"🔒 CORS:       {ALLOWED_ORIGINS}")
    print(f"⭐ Points System: KSH Optimized")
    print("="*50 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)