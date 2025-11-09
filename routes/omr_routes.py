"""
OMR Routes - Refactored and optimized
Handles user authentication and OMR sheet checking with dual storage (GitHub + Local CSV)
"""

from flask import Blueprint, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import re
import jwt
import datetime
from functools import wraps
from typing import Dict, Any, Tuple, Optional
import csv
import io
import os
import requests
import base64
import traceback

# ============================================
# BLUEPRINT & CONFIGURATION
# ============================================

omr_bp = Blueprint('omr_bp', __name__)

# Environment Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "")
TOKEN_EXPIRY_HOURS = 24

# GitHub Configuration
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_USERNAME = "XHiman"
GITHUB_REPO = "backend"
GITHUB_BRANCH = "master"
USERS_CSV_PATH = "data/users.csv"

# Local Storage Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_CSV_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "data", "users.csv"))

# GitHub API URLs
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/{USERS_CSV_PATH}"
GITHUB_REPO_URL = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}"

# Initialize
os.makedirs(os.path.dirname(LOCAL_CSV_PATH), exist_ok=True)
USE_GITHUB = bool(GITHUB_TOKEN)

# CSV Headers
CSV_HEADERS = ['email', 'phone_number', 'password_hash', 'ip_address', 'created_at', 'last_login']


# ============================================
# UTILITY FUNCTIONS
# ============================================

def get_client_ip() -> str:
    """Extract client IP address from request headers"""
    return (
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
        request.headers.get('X-Real-IP', '').strip() or
        request.remote_addr or
        'Unknown'
    )


def validate_email(email: str) -> bool:
    """Validate email format using regex"""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def validate_phone(phone: str) -> bool:
    """Validate phone number (10 digits)"""
    return bool(re.match(r'^\d{10}$', phone))


def generate_token(email: str) -> str:
    """Generate JWT authentication token"""
    try:
        payload = {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS),
            'iat': datetime.datetime.utcnow()
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    except Exception as e:
        print(f"Token generation error: {e}")
        return ""


# ============================================
# GITHUB STORAGE FUNCTIONS
# ============================================

def get_github_headers() -> Dict[str, str]:
    """Get standardized GitHub API headers"""
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


def get_github_file() -> Tuple[str, str]:
    """Fetch users.csv from GitHub repository"""
    if not USE_GITHUB:
        return "", ""
    
    try:
        response = requests.get(GITHUB_API_URL, headers=get_github_headers(), timeout=10)
        
        if response.status_code == 404:
            return f"{','.join(CSV_HEADERS)}\n", ""
        
        if response.status_code == 200:
            data = response.json()
            content = base64.b64decode(data['content']).decode('utf-8')
            return content, data['sha']
        
        print(f"GitHub API error: {response.status_code} - {response.text}")
        return "", ""
    
    except Exception as e:
        print(f"Error fetching from GitHub: {e}")
        return "", ""


def update_github_file(content: str, message: str, sha: str = "") -> bool:
    """Update or create users.csv file on GitHub"""
    if not USE_GITHUB:
        return False
    
    try:
        payload = {
            "message": message,
            "content": base64.b64encode(content.encode('utf-8')).decode('utf-8'),
            "branch": GITHUB_BRANCH
        }
        
        if sha:
            payload["sha"] = sha
        
        response = requests.put(GITHUB_API_URL, headers=get_github_headers(), json=payload, timeout=10)
        
        if response.status_code in [200, 201]:
            print(f"✓ GitHub: {message}")
            return True
        
        print(f"GitHub API error: {response.status_code} - {response.text}")
        return False
    
    except Exception as e:
        print(f"Error updating GitHub: {e}")
        return False


# ============================================
# LOCAL CSV STORAGE FUNCTIONS
# ============================================

def ensure_local_csv_exists():
    """Create local CSV file with headers if it doesn't exist"""
    try:
        if not os.path.exists(LOCAL_CSV_PATH):
            print(f"→ Creating new CSV file at: {LOCAL_CSV_PATH}")
            os.makedirs(os.path.dirname(LOCAL_CSV_PATH), exist_ok=True)
            with open(LOCAL_CSV_PATH, 'w', newline='', encoding='utf-8') as f:
                csv.writer(f).writerow(CSV_HEADERS)
            print(f"✓ CSV file created with headers")
        else:
            print(f"→ CSV file already exists at: {LOCAL_CSV_PATH}")
    except Exception as e:
        print(f"✗ Error creating CSV: {e}")
        traceback.print_exc()


def load_users_from_local() -> Dict[str, Dict[str, Any]]:
    """Load all users from local CSV file"""
    users = {}
    
    if not os.path.exists(LOCAL_CSV_PATH):
        return users
    
    try:
        with open(LOCAL_CSV_PATH, 'r', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                users[row['email']] = {
                    'email': row['email'],
                    'phoneNumber': row['phone_number'],
                    'password_hash': row['password_hash'],
                    'ip_address': row['ip_address'],
                    'created_at': row['created_at'],
                    'last_login': row.get('last_login', '')
                }
    except Exception as e:
        print(f"Error reading local CSV: {e}")
    
    return users


def save_user_to_local(email: str, phone_number: str, password_hash: str, ip_address: str) -> bool:
    """Append new user to local CSV file"""
    try:
        ensure_local_csv_exists()
        print(f"→ Local CSV path: {LOCAL_CSV_PATH}")
        print(f"→ CSV exists: {os.path.exists(LOCAL_CSV_PATH)}")
        
        with open(LOCAL_CSV_PATH, 'a', newline='', encoding='utf-8') as f:
            csv.writer(f).writerow([
                email, phone_number, password_hash, ip_address,
                datetime.datetime.utcnow().isoformat(), ''
            ])
        
        print(f"✓ Saved to local CSV: {email}")
        
        # Verify it was written
        if os.path.exists(LOCAL_CSV_PATH):
            file_size = os.path.getsize(LOCAL_CSV_PATH)
            print(f"→ CSV file size: {file_size} bytes")
        
        return True
    except Exception as e:
        print(f"✗ Error saving to local CSV: {e}")
        traceback.print_exc()
        return False


def update_users_in_local(users: Dict[str, Dict[str, Any]]) -> bool:
    """Rewrite entire local CSV with updated user data"""
    try:
        with open(LOCAL_CSV_PATH, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADERS)
            
            for user in users.values():
                writer.writerow([
                    user['email'],
                    user['phoneNumber'],
                    user['password_hash'],
                    user['ip_address'],
                    user['created_at'],
                    user['last_login']
                ])
        
        return True
    except Exception as e:
        print(f"Error updating local CSV: {e}")
        return False


# ============================================
# UNIFIED STORAGE FUNCTIONS
# ============================================

def load_users() -> Dict[str, Dict[str, Any]]:
    """Load users from GitHub (primary) or local CSV (fallback)"""
    # Try GitHub first
    if USE_GITHUB:
        content, _ = get_github_file()
        if content:
            try:
                users = {}
                for row in csv.DictReader(io.StringIO(content)):
                    users[row['email']] = {
                        'email': row['email'],
                        'phoneNumber': row['phone_number'],
                        'password_hash': row['password_hash'],
                        'ip_address': row['ip_address'],
                        'created_at': row['created_at'],
                        'last_login': row.get('last_login', '')
                    }
                print("✓ Loaded users from GitHub")
                return users
            except Exception as e:
                print(f"Error parsing GitHub CSV: {e}")
    
    # Fallback to local
    print("→ Using local CSV storage")
    return load_users_from_local()


def save_user(email: str, phone_number: str, password_hash: str, ip_address: str) -> bool:
    """Save new user to both GitHub and local storage"""
    print(f"→ Attempting to save user: {email}")
    
    # Always save locally first
    local_success = save_user_to_local(email, phone_number, password_hash, ip_address)
    print(f"→ Local save: {'✓ Success' if local_success else '✗ Failed'}")
    
    # Try GitHub
    if USE_GITHUB:
        try:
            print("→ Fetching current GitHub file...")
            content, sha = get_github_file()
            print(f"→ Current content length: {len(content)}, SHA: {sha[:8] if sha else 'none'}")
            
            created_at = datetime.datetime.utcnow().isoformat()
            new_row = f"{email},{phone_number},{password_hash},{ip_address},{created_at},\n"
            updated_content = content + new_row
            
            print(f"→ Updating GitHub with new content (length: {len(updated_content)})...")
            if update_github_file(updated_content, f"Register: {email}", sha):
                print("✓ GitHub save successful")
                return True
            else:
                print("✗ GitHub save failed")
        except Exception as e:
            print(f"✗ GitHub save exception: {e}")
            traceback.print_exc()
    else:
        print("→ GitHub disabled (no token)")
    
    return local_success


def update_last_login(email: str, ip_address: str) -> bool:
    """Update user's last login time and IP address"""
    # Update locally
    users = load_users_from_local()
    
    if email not in users:
        return False
    
    users[email]['last_login'] = datetime.datetime.utcnow().isoformat()
    users[email]['ip_address'] = ip_address
    
    local_success = update_users_in_local(users)
    
    # Try GitHub
    if USE_GITHUB:
        try:
            content, sha = get_github_file()
            if not content:
                return local_success
            
            lines = content.strip().split('\n')
            header, data_lines = lines[0], lines[1:]
            updated_lines = [header]
            last_login = datetime.datetime.utcnow().isoformat()
            
            for line in data_lines:
                if not line.strip():
                    continue
                
                parts = line.split(',')
                if len(parts) >= 6 and parts[0] == email:
                    parts[3] = ip_address
                    parts[5] = last_login
                
                updated_lines.append(','.join(parts))
            
            if update_github_file('\n'.join(updated_lines) + '\n', f"Login: {email}", sha):
                return True
        except Exception as e:
            print(f"GitHub update failed: {e}")
    
    return local_success


# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

@omr_bp.route('/v3rify', methods=['POST'])
def v3rify() -> Tuple[Any, int]:
    """
    Unified authentication endpoint for login and registration
    
    Request Body:
        {
            "action": "login" | "register",
            "email": "user@example.com",
            "password": "password123",
            "phoneNumber": "1234567890"  // required for register
        }
    
    Response:
        {
            "success": true,
            "message": "Success message",
            "token": "jwt_token",
            "user": {"email": "...", "phoneNumber": "..."}
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data provided"}), 400
        
        action = data.get('action', '').lower()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        ip_address = get_client_ip()
        
        # Validate action
        if action not in ['login', 'register']:
            return jsonify({"success": False, "message": "Invalid action"}), 400
        
        # Validate email
        if not email or not validate_email(email):
            return jsonify({"success": False, "message": "Invalid email address"}), 400
        
        # Validate password
        if not password or len(password) < 6:
            return jsonify({"success": False, "message": "Password must be at least 6 characters"}), 400
        
        users_db = load_users()
        
        # === REGISTRATION ===
        if action == 'register':
            phone_number = data.get('phoneNumber', '').strip()
            
            if not phone_number or not validate_phone(phone_number):
                return jsonify({"success": False, "message": "Invalid phone number (10 digits required)"}), 400
            
            if email in users_db:
                return jsonify({"success": False, "message": "Email already registered"}), 409
            
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            
            if not save_user(email, phone_number, password_hash, ip_address):
                return jsonify({"success": False, "message": "Failed to save user data"}), 500
            
            token = generate_token(email)
            print(f"✓ User registered: {email} from {ip_address}")
            
            return jsonify({
                "success": True,
                "message": "Registration successful",
                "token": token,
                "user": {"email": email, "phoneNumber": phone_number}
            }), 201
        
        # === LOGIN ===
        if email not in users_db:
            return jsonify({"success": False, "message": "Invalid email or password"}), 401
        
        user = users_db[email]
        
        if not check_password_hash(user['password_hash'], password):
            return jsonify({"success": False, "message": "Invalid email or password"}), 401
        
        update_last_login(email, ip_address)
        token = generate_token(email)
        print(f"✓ User logged in: {email} from {ip_address}")
        
        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": {"email": user['email'], "phoneNumber": user['phoneNumber']}
        }), 200
    
    except Exception as e:
        print(f"✗ Error in v3rify: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "message": "Internal server error"}), 500


# ============================================
# TOKEN AUTHENTICATION DECORATOR
# ============================================

def token_required(f):
    """Decorator to protect routes requiring authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '')
        
        if not token:
            return jsonify({"success": False, "message": "Token is missing"}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            token = token[7:] if token.startswith('Bearer ') else token
            
            # Decode and verify token
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user_email = payload['email']
            
            # Check if user exists
            users_db = load_users()
            if current_user_email not in users_db:
                return jsonify({"success": False, "message": "Invalid token"}), 401
            
            # Attach user to request context
            g.current_user = users_db[current_user_email]
            
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    
    return decorated


# ============================================
# PROTECTED ROUTES
# ============================================

@omr_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """Get authenticated user's profile information"""
    user = g.current_user
    return jsonify({
        "success": True,
        "user": {
            "email": user['email'],
            "phoneNumber": user['phoneNumber'],
            "created_at": user['created_at'],
            "last_login": user.get('last_login', ''),
            "ip_address": user.get('ip_address', '')
        }
    }), 200


# ============================================
# OMR CHECKING ENDPOINT
# ============================================

@omr_bp.route('/omrcheck', methods=['POST'])
def omr_check():
    """
    Check OMR sheet against answer key
    
    Expects: CSV file upload with 'question' and 'answer' columns
    Returns: Score statistics
    """
    try:
        # Validate file upload
        if 'csv' not in request.files:
            return jsonify({"error": "No CSV file uploaded"}), 400
        
        # Parse submitted answers
        file = request.files['csv']
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.reader(stream)
        headers = next(reader)
        
        # Find question and answer columns
        q_col = a_col = None
        for i, h in enumerate(headers):
            lower = h.strip().lower()
            if "question" in lower:
                q_col = i
            elif "answer" in lower:
                a_col = i
        
        if q_col is None or a_col is None:
            return jsonify({"error": "CSV must contain 'question' and 'answer' columns"}), 400
        
        # Collect submitted answers
        submitted_answers = {}
        for row in reader:
            if row and len(row) > max(q_col, a_col):
                q = row[q_col].strip()
                a = row[a_col].strip()
                if q and a:
                    submitted_answers[q] = a
        
        # Load correct answers
        correct_answers_path = os.path.normpath(
            os.path.join(BASE_DIR, "..", "data", "Answerkey_Test.csv")
        )
        
        with open(correct_answers_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            
            q_col = a_col = None
            for i, h in enumerate(headers):
                lower = h.strip().lower()
                if "question" in lower:
                    q_col = i
                elif "answer" in lower:
                    a_col = i
            
            if q_col is None or a_col is None:
                return jsonify({"error": "Invalid answer key format"}), 500
            
            correct_answers = {}
            for row in reader:
                if row and len(row) > max(q_col, a_col):
                    q = row[q_col].strip()
                    a = row[a_col].strip()
                    if q and a:
                        correct_answers[q] = a
        
        # Calculate results
        correct_count = sum(
            1 for q, ans in correct_answers.items()
            if submitted_answers.get(q) == ans
        )
        attempted_count = len(submitted_answers)
        total_questions = len(correct_answers)
        
        result = {
            "message": "OMR sheet checked successfully!",
            "total_correct": correct_count,
            "total_attempted": attempted_count,
            "total_questions": total_questions,
            "skipped": total_questions - attempted_count
        }
        
        print(f"✓ OMR Check: {correct_count}/{attempted_count} correct")
        return jsonify(result), 200
    
    except FileNotFoundError:
        return jsonify({"error": "Answer key file not found"}), 500
    except Exception as e:
        print(f"✗ OMR Check error: {e}")
        traceback.print_exc()
        return jsonify({"error": "Error processing OMR sheet"}), 500


# ============================================
# DEBUG ENDPOINTS
# ============================================

@omr_bp.route('/debug/config', methods=['GET'])
def debug_config():
    """Display current configuration (for debugging)"""
    return jsonify({
        "github_token_set": bool(GITHUB_TOKEN),
        "github_token_length": len(GITHUB_TOKEN),
        "github_username": GITHUB_USERNAME,
        "github_repo": GITHUB_REPO,
        "github_branch": GITHUB_BRANCH,
        "users_csv_path": USERS_CSV_PATH,
        "secret_key_set": bool(SECRET_KEY),
        "use_github": USE_GITHUB,
        "local_csv_path": LOCAL_CSV_PATH,
        "local_csv_exists": os.path.exists(LOCAL_CSV_PATH)
    }), 200


@omr_bp.route('/debug/test-github', methods=['GET'])
def test_github():
    """Test GitHub API connectivity"""
    if not GITHUB_TOKEN:
        return jsonify({
            "success": False,
            "message": "GITHUB_TOKEN not set"
        }), 200
    
    try:
        response = requests.get(GITHUB_REPO_URL, headers=get_github_headers(), timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                "success": True,
                "message": "GitHub API connection successful",
                "repo_name": data.get('name'),
                "private": data.get('private')
            }), 200
        
        return jsonify({
            "success": False,
            "message": "GitHub API connection failed",
            "status_code": response.status_code,
            "error": response.text
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 200


@omr_bp.route('/debug/test-csv-write', methods=['GET'])
def test_csv_write():
    """Test if we can write to CSV"""
    try:
        test_email = f"test_{datetime.datetime.utcnow().timestamp()}@test.com"
        test_phone = "1234567890"
        test_hash = "test_hash"
        test_ip = "127.0.0.1"
        
        print(f"\n{'='*50}")
        print(f"TESTING CSV WRITE")
        print(f"{'='*50}")
        
        result = save_user(test_email, test_phone, test_hash, test_ip)
        
        # Check if file exists
        file_exists = os.path.exists(LOCAL_CSV_PATH)
        file_size = os.path.getsize(LOCAL_CSV_PATH) if file_exists else 0
        
        # Try to read the file
        users = load_users_from_local()
        
        # Check GitHub
        github_content, github_sha = get_github_file()
        
        return jsonify({
            "success": result,
            "local_csv_path": LOCAL_CSV_PATH,
            "local_csv_exists": file_exists,
            "local_csv_size": file_size,
            "users_loaded_from_local": len(users),
            "test_user_in_local": test_email in users,
            "github_enabled": USE_GITHUB,
            "github_content_length": len(github_content),
            "github_sha": github_sha[:8] if github_sha else None,
            "test_email": test_email
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500


@omr_bp.route('/debug/list-users', methods=['GET'])
def list_users():
    """List all users (for debugging)"""
    try:
        users = load_users()
        
        return jsonify({
            "success": True,
            "total_users": len(users),
            "users": [
                {
                    "email": u['email'],
                    "phone": u['phoneNumber'],
                    "created_at": u['created_at'],
                    "last_login": u.get('last_login', 'Never')
                }
                for u in users.values()
            ]
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500