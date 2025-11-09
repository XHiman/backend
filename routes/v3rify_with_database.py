"""
Complete v3rify endpoint with database integration
Choose your database implementation below
"""

from flask import jsonify, request, Response
from typing import Union, Tuple
from werkzeug.security import generate_password_hash, check_password_hash
import re
import jwt
import datetime

# Configuration
SECRET_KEY = "your-secret-key-here-change-this"  # IMPORTANT: Change this!
TOKEN_EXPIRY_HOURS = 24

# ============================================
# OPTION 1: Using SQLAlchemy
# ============================================

from database_models import db, User
from routes.omr_routes import omr_bp

@omr_bp.route('/v3rify', methods=['POST'])
def v3rify_sqlalchemy() -> Union[Tuple[Response, int], Response]:
    """v3rify endpoint with SQLAlchemy"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "message": "No data provided"}), 400
        
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
            return jsonify({"success": False, "message": "Invalid email address"}), 400
        
        # Validate password
        if not password or len(password) < 6:
            return jsonify({
                "success": False,
                "message": "Password must be at least 6 characters long"
            }), 400
        
        # REGISTRATION
        if action == 'register':
            phone_number = data.get('phoneNumber', '').strip()
            
            if not phone_number or not validate_phone(phone_number):
                return jsonify({
                    "success": False,
                    "message": "Invalid phone number. Must be 10 digits"
                }), 400
            
            # Check if user exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                return jsonify({
                    "success": False,
                    "message": "User with this email already exists"
                }), 409
            
            # Create new user
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(
                email=email,
                phone_number=phone_number,
                password_hash=password_hash
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            token = generate_token(email)
            
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
        else:  # action == 'login'
            user = User.query.filter_by(email=email).first()
            
            if not user or not check_password_hash(user.password_hash, password):
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password"
                }), 401
            
            token = generate_token(email)
            
            return jsonify({
                "success": True,
                "message": "Login successful",
                "token": token,
                "user": {
                    "email": user.email,
                    "phoneNumber": user.phone_number
                }
            }), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"Error in v3rify: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An internal error occurred"
        }), 500

# ============================================
# Helper Functions (Common to both)
# ============================================

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
        print(f"Token generation error: {str(e)}")
        return ""