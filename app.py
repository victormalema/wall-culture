# app.py - Wall Culture Flask Backend
from flask import Flask, request, jsonify
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

# Load environment variables
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
        user_res = supabase.table('users').select('points, weekly_points, multiplier, multiplier_expiry').eq('id', user_id).execute()
        if not user_res.data:
            return 0
        
        user = user_res.data[0]
        current_time = int(datetime.now().timestamp() * 1000)
        
        effective_multiplier = custom_multiplier or (user['multiplier'] if user.get('multiplier_expiry', 0) > current_time else 1.0)
        earned = int(base_points * effective_multiplier)
        
        supabase.table('users').update({
            'points': user['points'] + earned,
            'weekly_points': (user.get('weekly_points') or 0) + earned
        }).eq('id', user_id).execute()
        
        supabase.table('point_logs').insert({
            'user_id': user_id,
            'action': action,
            'points': base_points,
            'multiplier': effective_multiplier,
            'earned': earned,
            'timestamp': current_time
        }).execute()
        
        return earned
    except Exception as e:
        print(f"Error adding points: {e}")
        return 0

# ==================== AUTH DECORATOR ====================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
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

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({"error": "Missing fields"}), 400

        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        supabase.table("users").insert({
            "id": user_id,
            "name": name,
            "email": email,
            "password": hashed_password,
            "points": 100,
            "created_at": int(datetime.now().timestamp() * 1000)
        }).execute()

        return jsonify({"success": True})

    except Exception as e:
        print("REGISTER ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

# ==================== POINTS ROUTES ====================
@app.route('/api/points/add', methods=['POST'])
@token_required
def add_points():
    data = request.json
    action = data.get('action')
    base_points = data.get('basePoints')
    earned = add_points_to_user(request.user_id, base_points, action)
    return jsonify({'success': True, 'earned': earned})

@app.route('/api/scan/qr', methods=['POST'])
@token_required
def scan_qr():
    try:
        data = request.json
        code = data.get('code')
        
        qr_result = supabase.table('qr_codes').select('*').eq('code', code).execute()
        if not qr_result.data:
            return jsonify({'error': 'Invalid QR code'}), 404
        
        qr = qr_result.data[0]
        
        today_start = int(datetime.now().replace(hour=0, minute=0, second=0).timestamp() * 1000)
        scans = supabase.table('point_logs').select('id', count='exact').eq('user_id', request.user_id).eq('action', 'QR Scan').gte('timestamp', today_start).execute()
        
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
        result = supabase.table('users').select('last_checkin, streak').eq('id', request.user_id).execute()
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
        
        return jsonify({'success': True, 'points': total_points, 'streak': new_streak, 'bonus': bonus})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== SHOP & POSTERS ====================
@app.route('/api/posters', methods=['GET'])
@token_required
def get_posters():
    try:
        category = request.args.get('category', 'all')
        limited = request.args.get('limited', 'false') == 'true'
        
        query = supabase.table('posters').select('*')
        
        if category != 'all':
            query = query.eq('category', category)
        if limited:
            query = query.eq('is_limited', 1)
        
        result = query.execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/order/create', methods=['POST'])
@token_required
def create_order():
    try:
        data = request.json
        items = data.get('items')
        total_price = data.get('totalPrice')
        total_base_points = data.get('totalBasePoints')
        
        order_id = str(uuid.uuid4())
        
        user_result = supabase.table('users').select('multiplier, multiplier_expiry').eq('id', request.user_id).execute()
        user = user_result.data[0] if user_result.data else {'multiplier': 1.0, 'multiplier_expiry': 0}
        
        current_time = int(datetime.now().timestamp() * 1000)
        effective_multiplier = user['multiplier'] if user.get('multiplier_expiry', 0) > current_time else 1.0
        final_points = int(total_base_points * effective_multiplier)
        
        new_multiplier = 1.2
        for item in items:
            if item.get('type') == 'mystery':
                new_multiplier = 1.5
            elif item.get('type') == 'limited':
                new_multiplier = 1.8
        
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
        
        add_points_to_user(request.user_id, total_base_points, 'Purchase order')
        
        supabase.table('users').update({
            'multiplier': new_multiplier,
            'multiplier_expiry': int((datetime.now() + timedelta(days=7)).timestamp() * 1000)
        }).eq('id', request.user_id).execute()
        
        return jsonify({'success': True, 'orderId': order_id, 'pointsEarned': final_points, 'newMultiplier': new_multiplier})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== LEADERBOARDS ====================
@app.route('/api/leaderboard/alltime', methods=['GET'])
@token_required
def get_alltime_leaderboard():
    try:
        result = supabase.table('users').select('id, name, points').order('points', desc=True).limit(50).execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/leaderboard/weekly', methods=['GET'])
@token_required
def get_weekly_leaderboard():
    try:
        result = supabase.table('users').select('id, name, weekly_points').order('weekly_points', desc=True).limit(50).execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== USER PROFILE ====================
@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile():
    try:
        user_result = supabase.table('users').select('id, name, email, points, weekly_points, streak, multiplier, multiplier_expiry, referral_code').eq('id', request.user_id).execute()
        if not user_result.data:
            return jsonify({'error': 'User not found'}), 404
        
        user = user_result.data[0]
        
        logs = supabase.table('point_logs').select('action, earned, timestamp').eq('user_id', request.user_id).order('timestamp', desc=True).limit(20).execute()
        
        rank_result = supabase.table('users').select('id', count='exact').gt('points', user['points']).execute()
        rank = rank_result.count + 1 if rank_result.count else 1
        
        return jsonify({'user': user, 'auditLog': logs.data, 'rank': rank})
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

# ==================== HEALTH ====================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'app': 'Wall Culture', 'version': '1.0.0'})

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🎨 WALL CULTURE BACKEND")
    print("="*50)
    print(f"📍 Running on: http://localhost:5000")
    print(f"📡 Supabase: {SUPABASE_URL}")
    print("="*50 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
from flask import send_from_directory

@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'index.html')
CHANGE_TEST_Fri 24 Apr 2026 01:17:08 PM EAT
