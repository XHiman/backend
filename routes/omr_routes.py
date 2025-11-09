from flask import Blueprint, request, jsonify
import json
from werkzeug.security import generate_password_hash, check_password_hash
import re
import jwt  # PyJWT
import datetime
from functools import wraps
from typing import Dict, Any, Tuple
import csv
import io
import os
import requests
import base64

# Create a blueprint named 'omr_bp'
omr_bp = Blueprint('omr_bp', __name__)

# Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "")
TOKEN_EXPIRY_HOURS = 24

# GitHub Configuration
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")  # Set this in Render.com environment variables
GITHUB_USERNAME = "XHiman"
GITHUB_REPO = "backend"
GITHUB_BRANCH = "master"
USERS_CSV_PATH = "data/users.csv"  # Path in the repository

# GitHub API base URL
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}/contents/{USERS_CSV_PATH}"


def get_client_ip() -> str:
    """Get client IP address from request, safely."""
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()

    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip

    return request.remote_addr or 'Unknown'


def get_github_file() -> Tuple[str, str]:
    """
    Get the users.csv file from GitHub
    Returns: (content, sha) tuple
    """
    if not GITHUB_TOKEN:
        print("Warning: GITHUB_TOKEN not set")
        return "", ""
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        response = requests.get(GITHUB_API_URL, headers=headers)
        
        if response.status_code == 404:
            # File doesn't exist, create initial CSV structure
            return "email,phone_number,password_hash,ip_address,created_at,last_login\n", ""
        
        if response.status_code == 200:
            data = response.json()
            content = base64.b64decode(data['content']).decode('utf-8')
            sha = data['sha']
            return content, sha
        else:
            print(f"GitHub API error: {response.status_code} - {response.text}")
            return "", ""
    
    except Exception as e:
        print(f"Error fetching file from GitHub: {e}")
        return "", ""


def update_github_file(content: str, message: str, sha: str = "") -> bool:
    """
    Update or create the users.csv file on GitHub
    """
    if not GITHUB_TOKEN:
        print("Error: GITHUB_TOKEN not set")
        return False
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Encode content to base64
    content_bytes = content.encode('utf-8')
    content_base64 = base64.b64encode(content_bytes).decode('utf-8')
    
    payload = {
        "message": message,
        "content": content_base64,
        "branch": GITHUB_BRANCH
    }
    
    # Add SHA if file exists (for update)
    if sha:
        payload["sha"] = sha
    
    try:
        response = requests.put(GITHUB_API_URL, headers=headers, json=payload)
        
        if response.status_code in [200, 201]:
            print(f"Successfully updated GitHub file: {message}")
            return True
        else:
            print(f"GitHub API error: {response.status_code} - {response.text}")
            return False
    
    except Exception as e:
        print(f"Error updating GitHub file: {e}")
        return False


def load_users() -> Dict[str, Dict[str, Any]]:
    """Load users from GitHub CSV file"""
    users = {}
    
    content, _ = get_github_file()
    
    if not content:
        return users
    
    try:
        # Parse CSV content
        csv_reader = csv.DictReader(io.StringIO(content))
        for row in csv_reader:
            users[row['email']] = {
                'email': row['email'],
                'phoneNumber': row['phone_number'],
                'password_hash': row['password_hash'],
                'ip_address': row['ip_address'],
                'created_at': row['created_at'],
                'last_login': row.get('last_login', '')
            }
    except Exception as e:
        print(f"Error parsing users CSV: {e}")
    
    return users


def save_user(email: str, phone_number: str, password_hash: str, ip_address: str) -> bool:
    """Save new user to GitHub CSV file"""
    try:
        # Get current file content and SHA
        content, sha = get_github_file()
        
        # Add new user row
        created_at = datetime.datetime.utcnow().isoformat()
        new_row = f"{email},{phone_number},{password_hash},{ip_address},{created_at},\n"
        
        # Append to content
        updated_content = content + new_row
        
        # Commit to GitHub
        commit_message = f"Register new user: {email}"
        return update_github_file(updated_content, commit_message, sha)
    
    except Exception as e:
        print(f"Error saving user: {e}")
        return False


def update_last_login(email: str, ip_address: str) -> bool:
    """Update last login timestamp and IP for a user in GitHub"""
    try:
        # Get current file
        content, sha = get_github_file()
        
        if not content:
            return False
        
        # Parse CSV
        lines = content.strip().split('\n')
        if len(lines) < 1:
            return False
        
        header = lines[0]
        data_lines = lines[1:]
        
        # Update the user's row
        updated_lines = [header]
        user_found = False
        last_login = datetime.datetime.utcnow().isoformat()
        
        for line in data_lines:
            if not line.strip():
                continue
            
            parts = line.split(',')
            if len(parts) >= 6 and parts[0] == email:
                # Update this user's last_login and ip_address
                parts[3] = ip_address  # Update IP
                parts[5] = last_login  # Update last_login
                user_found = True
            
            updated_lines.append(','.join(parts))
        
        if not user_found:
            return False
        
        # Reconstruct CSV content
        updated_content = '\n'.join(updated_lines) + '\n'
        
        # Commit to GitHub
        commit_message = f"Update login for user: {email}"
        return update_github_file(updated_content, commit_message, sha)
    
    except Exception as e:
        print(f"Error updating last login: {e}")
        return False


@omr_bp.route('/omrcheck', methods=['POST'])
def omr_check():
    print("OMR check endpoint hit.")

    # ----------------------------
    # 1. Get the uploaded CSV file (submitted answers)
    # ----------------------------
    try:
        if 'csv' not in request.files:
            return jsonify({"error": "No CSV file uploaded"}), 400

        file = request.files['csv']
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.reader(stream)

        headers = next(reader)
        print(f"Uploaded CSV headers: {headers}")

        q_col, a_col = None, None
        for h in headers:
            lower = h.strip().lower()
            if "question" in lower:
                q_col = headers.index(h)
            elif "answer" in lower:
                a_col = headers.index(h)

        if q_col is None or a_col is None:
            return jsonify({"error": "CSV must contain columns for question number and answer"}), 400

        # Collect whatever answers are provided (incomplete allowed)
        submitted_answers = {}
        for row in reader:
            if not row or len(row) <= max(q_col, a_col):
                continue
            q = row[q_col].strip()
            a = row[a_col].strip()
            if q and a:
                submitted_answers[q] = a

    except Exception as e:
        print(f"Error reading submitted CSV: {e}")
        return jsonify({"error": "Invalid CSV format"}), 400

    # ----------------------------
    # 2. Read the correct answers CSV
    # ----------------------------
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))   # backend/routes/
        correct_answers_path = os.path.join(base_dir, "..", "data", "Answerkey_Test.csv")
        correct_answers_path = os.path.normpath(correct_answers_path)

        with open(correct_answers_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)

            q_col, a_col = None, None
            for h in headers:
                lower = h.strip().lower()
                if "question" in lower:
                    q_col = headers.index(h)
                elif "answer" in lower:
                    a_col = headers.index(h)

            if q_col is None or a_col is None:
                return jsonify({"error": "Answer key CSV must contain columns for question number and answer"}), 500

            correct_answers = {}
            for row in reader:
                if not row or len(row) <= max(q_col, a_col):
                    continue
                q = row[q_col].strip()
                a = row[a_col].strip()
                if q and a:
                    correct_answers[q] = a

    except FileNotFoundError:
        print("backend/data/Answerkey_Test.csv not found.")
        return jsonify({"error": "Correct answers file not found"}), 500
    except Exception as e:
        print(f"Error reading correct answers CSV: {e}")
        return jsonify({"error": "Error processing correct answers file"}), 500

    # ----------------------------
    # 3. Compare (treat missing answers as wrong)
    # ----------------------------
    correct_count = 0
    attempted_count = 0

    for q_num, correct_ans in correct_answers.items():
        user_ans = submitted_answers.get(q_num, None)
        if user_ans:
            attempted_count += 1
            if user_ans == correct_ans:
                correct_count += 1

    result = {
        "message": "OMR sheet checked successfully!",
        "total_correct": correct_count,
        "total_attempted": attempted_count,
        "total_questions": len(correct_answers),
        "skipped": len(correct_answers) - attempted_count
    }

    print(f"Result: {result}")
    return jsonify(result)


def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone: str) -> bool:
    """Validate phone number (10 digits)"""
    pattern = r'^\d{10}$'
    return re.match(pattern, phone) is not None


def generate_token(email: str) -> str:
    """Generate JWT token"""
    try:
        payload = {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        print(f"Token generation error: {e}")
        return ""


@omr_bp.route('/v3rify', methods=['POST'])
def v3rify() -> Tuple[Any, int]:
    """
    Unified endpoint for user authentication (login/register)
    Saves user data to GitHub repository
    
    Expected JSON body:
    {
        "action": "login" | "register",
        "email": "user@example.com",
        "password": "password123",
        "phoneNumber": "1234567890"  # Only for register
    }
    
    Returns:
    {
        "success": true/false,
        "message": "Success or error message",
        "token": "jwt_token",  # Only on success
        "user": {
            "email": "user@example.com",
            "phoneNumber": "1234567890"
        }
    }
    """
    
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "No data provided"
            }), 400
        
        action = data.get('action', '').lower()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Get client IP address
        ip_address = get_client_ip()
        
        # Validate action
        if action not in ['login', 'register']:
            return jsonify({
                "success": False,
                "message": "Invalid action. Must be 'login' or 'register'"
            }), 400
        
        # Validate email
        if not email or not validate_email(email):
            return jsonify({
                "success": False,
                "message": "Invalid email address"
            }), 400
        
        # Validate password
        if not password or len(password) < 6:
            return jsonify({
                "success": False,
                "message": "Password must be at least 6 characters long"
            }), 400
        
        # Load existing users from GitHub
        users_db = load_users()
        
        # REGISTRATION
        if action == 'register':
            phone_number = data.get('phoneNumber', '').strip()
            
            # Validate phone number
            if not phone_number or not validate_phone(phone_number):
                return jsonify({
                    "success": False,
                    "message": "Invalid phone number. Must be 10 digits"
                }), 400
            
            # Check if user already exists
            if email in users_db:
                return jsonify({
                    "success": False,
                    "message": "User with this email already exists"
                }), 409
            
            # Hash the password
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            
            # Save user to GitHub
            if not save_user(email, phone_number, password_hash, ip_address):
                return jsonify({
                    "success": False,
                    "message": "Failed to save user data to GitHub"
                }), 500
            
            # Generate token
            token = generate_token(email)
            
            print(f"User registered: {email} from IP: {ip_address}")
            return jsonify({
                "success": True,
                "message": "Registration successful",
                "token": token,
                "user": {
                    "email": email,
                    "phoneNumber": phone_number
                }
            }), 201
        
        # LOGIN
        elif action == 'login':
            # Check if user exists
            if email not in users_db:
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 401
            
            user = users_db[email]
            
            # Verify password
            if not check_password_hash(user['password_hash'], password):
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 401
            
            # Update last login timestamp and IP on GitHub
            update_last_login(email, ip_address)
            
            # Generate token
            token = generate_token(email)
            
            print(f"User logged in: {email} from IP: {ip_address}")
            return jsonify({
                "success": True,
                "message": "Login successful",
                "token": token,
                "user": {
                    "email": user['email'],
                    "phoneNumber": user['phoneNumber']
                }
            }), 200
    
    except Exception as e:
        print(f"Error in v3rify endpoint: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An internal error occurred. Please try again later."
        }), 500
    return jsonify({"success": False, "message": "Unhandled case"}), 400


# Optional: Token verification decorator
def token_required(f):
    """Decorator to protect routes that require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({
                "success": False,
                "message": "Token is missing"
            }), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            # Decode token
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user_email = payload['email']
            
            # Load users from GitHub and check if user exists
            users_db = load_users()
            if current_user_email not in users_db:
                return jsonify({
                    "success": False,
                    "message": "Invalid token"
                }), 401
            
            # Pass user info to the route via g object
            from flask import g
            g.current_user = users_db[current_user_email]
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                "success": False,
                "message": "Token has expired"
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "success": False,
                "message": "Invalid token"
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated


# Example of protected route usage:
@omr_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """Example protected route"""
    from flask import g
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

@omr_bp.route('/debug/config', methods=['GET'])
def debug_config():
    """Debug endpoint to check configuration"""
    return jsonify({
        "github_token_set": bool(GITHUB_TOKEN),
        "github_token_length": len(GITHUB_TOKEN) if GITHUB_TOKEN else 0,
        "github_username": GITHUB_USERNAME,
        "github_repo": GITHUB_REPO,
        "github_branch": GITHUB_BRANCH,
        "users_csv_path": USERS_CSV_PATH,
        "secret_key_set": bool(SECRET_KEY)
    }), 200


@omr_bp.route('/debug/test-github', methods=['GET'])
def test_github():
    """Test GitHub API connection"""
    if not GITHUB_TOKEN:
        return jsonify({
            "success": False,
            "message": "GITHUB_TOKEN not set in environment variables"
        }), 500
    
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        # Test repository access
        repo_url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO}"
        response = requests.get(repo_url, headers=headers)
        
        if response.status_code == 200:
            return jsonify({
                "success": True,
                "message": "GitHub API connection successful",
                "repo_access": True,
                "repo_name": response.json().get('name'),
                "private": response.json().get('private')
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "GitHub API connection failed",
                "status_code": response.status_code,
                "error": response.text
            }), 500
    
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500