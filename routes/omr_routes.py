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

# Create a blueprint named 'omr_bp'
omr_bp = Blueprint('omr_bp', __name__)

# Configuration
SECRET_KEY = "your-secret-key-here-change-this-in-production"
TOKEN_EXPIRY_HOURS = 24

# In-memory database (replace with actual database)
users_db: Dict[str, Dict[str, Any]] = {}


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
            
            # Save user to database
            users_db[email] = {
                "email": email,
                "phoneNumber": phone_number,
                "password_hash": password_hash,
                "created_at": datetime.datetime.utcnow().isoformat()
            }
            
            # Generate token
            token = generate_token(email)
            
            print(f"User registered: {email}")
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
            
            # Generate token
            token = generate_token(email)
            
            print(f"User logged in: {email}")
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
            
            # Check if user exists
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
            "created_at": user['created_at']
        }
    }), 200