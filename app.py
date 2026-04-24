# app.py - Wall Culture Flask Backend
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from supabase import create_client, Client
import uuid
import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from functools import wraps
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'wall_culture_secret_key_2025')

# ==================== SUPABASE SETUP ====================
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    print("❌ ERROR: Missing SUPABASE_URL or SUPABASE_KEY in .env file")
    exit(1)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
print("✅ Connected to Supabase")

# ==================== HELPER FUNCTIONS ====================
def generate_referral_code(name):
    return name[:4].upper() + str(uuid.uuid4().hex[:4]).upper()

def add_points_to_user(user_id, base_points, action, custom_multiplier=None):
    try:
        user_res = supabase.table('users').select(
            'points, weekly_points, multiplier, multiplier_expiry'
        ).eq('id', user_id).execute()

        if not user_res.data:
            return 0

        user = user_res.data[0]
        current_time = int(datetime.now().timestamp() * 1000)

        # Determine effective multiplier
        if custom_multiplier:
            effective_multiplier = custom_multiplier
        elif user.get('multiplier_expiry') and user['multiplier_expiry'] > current_time:
            effective_multiplier = user.get('multiplier', 1.0)
        else:
            effective_multiplier = 1.0

        earned = int(base_points * effective_multiplier)

        supabase.table('users').update({
            'points': user['points'] + earned,
            'weekly_points': (user.get('weekly_points') or 0) + earned
        }).eq('id', user_id).execute()

        # FIX: point_logs may not exist yet — wrap separately so points still save
        try:
            supabase.table('point_logs').insert({
                'user_id': user_id,
                'action': action,
                'points': base_points,
                'multiplier': effective_multiplier,
                'earned': earned,
                'timestamp': current_time
            }).execute()
        except Exception as log_err:
            print(f"Warning: could not write point_log: {log_err}")

        return earned

    except Exception as e:
        print(f"Error adding points: {e}")
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
def register():
    try:
        data = request.get_json(silent=True) or {}
        print("REGISTER DATA:", data)

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
            "created_at": int(datetime.now().timestamp() * 1000)
        }).execute()

        # Award referral bonus to referrer
        if referral_code:
            ref_result = supabase.table("users").select("id").eq("referral_code", referral_code).execute()
            if ref_result.data:
                add_points_to_user(ref_result.data[0]["id"], 50, "Referral bonus")

        token = jwt.encode(
            {"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)},
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )

        # jwt.encode returns str in PyJWT >= 2.0, bytes in older versions
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
def login():
    try:
        data = request.get_json(silent=True) or {}
        print("LOGIN DATA:", data)

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not email or not password:
            return jsonify({"error": "Missing fields"}), 400

        result = supabase.table("users").select("*").eq("email", email).execute()
        if not result.data:
            # Generic message to avoid user enumeration
            return jsonify({"error": "Invalid email or password"}), 401

        user = result.data[0]

        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({"error": "Invalid email or password"}), 401

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


# ==================== POINTS ROUTES ====================
@app.route('/api/points/add', methods=['POST'])
@token_required
def add_points():
    try:
        data = request.get_json(silent=True) or {}
        action = data.get('action', 'Unknown action')
        base_points = data.get('basePoints', 0)

        if not isinstance(base_points, (int, float)) or base_points <= 0:
            return jsonify({'error': 'Invalid points value'}), 400

        earned = add_points_to_user(request.user_id, int(base_points), action)
        return jsonify({'success': True, 'earned': earned})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/qr', methods=['POST'])
@token_required
def scan_qr():
    try:
        data = request.get_json(silent=True) or {}
        code = data.get('code')

        if not code:
            # Generic QR scan without a specific code — just award points
            earned = add_points_to_user(request.user_id, 15, 'QR Scan')
            return jsonify({'success': True, 'earned': earned, 'points': 15})

        qr_result = supabase.table('qr_codes').select('*').eq('code', code).execute()
        if not qr_result.data:
            return jsonify({'error': 'Invalid QR code'}), 404

        qr = qr_result.data[0]

        today_start = int(datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        ).timestamp() * 1000)

        scans = supabase.table('point_logs').select(
            'id', count='exact'
        ).eq('user_id', request.user_id).eq('action', 'QR Scan').gte('timestamp', today_start).execute()

        if scans.count and scans.count >= 5:
            return jsonify({'error': 'Max 5 QR scans per day'}), 429

        earned = add_points_to_user(request.user_id, qr['points'], 'QR Scan')

        supabase.table('qr_codes').update({
            'scanned_by': request.user_id,
            'scanned_at': int(datetime.now().timestamp() * 1000)
        }).eq('code', code).execute()

        return jsonify({'success': True, 'earned': earned, 'points': qr['points']})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily/checkin', methods=['POST'])
@token_required
def daily_checkin():
    try:
        result = supabase.table('users').select(
            'last_checkin, streak'
        ).eq('id', request.user_id).execute()

        user = result.data[0] if result.data else {'last_checkin': None, 'streak': 0}
        today = datetime.now().date().isoformat()

        if user.get('last_checkin') == today:
            return jsonify({'success': False, 'message': 'Already checked in today'})

        new_streak = 1
        bonus = 0

        if user.get('last_checkin'):
            yesterday = (datetime.now() - timedelta(days=1)).date().isoformat()
            if user['last_checkin'] == yesterday:
                new_streak = (user.get('streak') or 0) + 1

        if new_streak >= 7:
            bonus = 100

        total_points = 5 + bonus
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


# ==================== POSTERS / FEED ====================
@app.route('/api/posters', methods=['GET'])
@token_required
def get_posters():
    try:
        category = request.args.get('category', 'all')
        limited = request.args.get('limited', 'false').lower() == 'true'

        query = supabase.table('posters').select('*')

        if category != 'all':
            query = query.eq('category', category)

        if limited:
            # FIX: is_limited is boolean in Supabase, not int
            query = query.eq('is_limited', True)

        result = query.order('created_at', desc=True).execute()
        return jsonify(result.data or [])

    except Exception as e:
        print(f"get_posters error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/feed', methods=['GET'])
@token_required
def get_feed():
    try:
        # FIX: removed @token_required conflict — auth is now consistent
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
def create_order():
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items', [])
        total_price = data.get('totalPrice', 0)
        total_base_points = data.get('totalBasePoints', 0)

        if not items:
            return jsonify({'error': 'No items in order'}), 400

        order_id = str(uuid.uuid4())
        current_time = int(datetime.now().timestamp() * 1000)

        user_result = supabase.table('users').select(
            'multiplier, multiplier_expiry'
        ).eq('id', request.user_id).execute()

        user = user_result.data[0] if user_result.data else {'multiplier': 1.0, 'multiplier_expiry': 0}
        expiry = user.get('multiplier_expiry') or 0
        effective_multiplier = user['multiplier'] if expiry > current_time else 1.0
        final_points = int(total_base_points * effective_multiplier)

        # Determine new multiplier from cart contents
        new_multiplier = 1.2
        for item in items:
            if item.get('type') == 'mystery':
                new_multiplier = max(new_multiplier, 1.5)
            elif item.get('type') == 'limited':
                new_multiplier = max(new_multiplier, 1.8)

        # Upgrade multiplier for large spend
        if total_price >= 49:
            new_multiplier = max(new_multiplier, 2.0)

        supabase.table('orders').insert({
            'id': order_id,
            'user_id': request.user_id,
            'items': json.dumps(items),
            'total_price': total_price,
            'total_points': final_points,
            'boost_given': new_multiplier,
            'status': 'completed',
            'created_at': current_time
        }).execute()

        # Award points (uses current multiplier for this purchase)
        earned = add_points_to_user(request.user_id, total_base_points, 'Purchase order')

        # Update multiplier for future purchases
        supabase.table('users').update({
            'multiplier': new_multiplier,
            'multiplier_expiry': int((datetime.now() + timedelta(days=7)).timestamp() * 1000)
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


# ==================== LEADERBOARDS ====================
@app.route('/api/leaderboard/alltime', methods=['GET'])
@token_required
def get_alltime_leaderboard():
    try:
        result = supabase.table('users').select(
            'id, name, points'
        ).order('points', desc=True).limit(50).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/leaderboard/weekly', methods=['GET'])
@token_required
def get_weekly_leaderboard():
    try:
        result = supabase.table('users').select(
            'id, name, weekly_points'
        ).order('weekly_points', desc=True).limit(50).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== USER PROFILE ====================
@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile():
    try:
        user_result = supabase.table('users').select(
            'id, name, email, points, weekly_points, streak, multiplier, multiplier_expiry, referral_code, last_checkin'
        ).eq('id', request.user_id).execute()

        if not user_result.data:
            return jsonify({'error': 'User not found'}), 404

        user = user_result.data[0]

        # Audit log — gracefully handle missing table
        audit_log = []
        try:
            logs = supabase.table('point_logs').select(
                'action, earned, timestamp'
            ).eq('user_id', request.user_id).order('timestamp', desc=True).limit(20).execute()
            audit_log = logs.data or []
        except Exception:
            pass

        # Rank = number of users with more points + 1
        rank = 1
        try:
            rank_result = supabase.table('users').select(
                'id', count='exact'
            ).gt('points', user['points']).execute()
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


# ==================== STATIC FILE SERVING ====================
@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')

@app.route('/home.html')
def serve_dashboard():
    return send_from_directory('.', 'home.html')

# Serve any other static assets (CSS, JS, images) from current directory
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)


# ==================== HEALTH CHECK ====================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'app': 'Wall Culture',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("\n" + "="*50)
    print("🎨 WALL CULTURE BACKEND")
    print("="*50)
    print(f"📍 Running on: http://localhost:5000")
    print(f"📡 Supabase: {SUPABASE_URL}")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)