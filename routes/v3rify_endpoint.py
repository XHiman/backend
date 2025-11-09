from flask import jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
import re
import jwt
import datetime
from functools import wraps

# Configuration (adjust these to your setup)
SECRET_KEY = "your-secret-key-here"  # Change this to a secure secret key
TOKEN_EXPIRY_HOURS = 24

# Database setup (adjust based on your database choice)
# This example uses a simple dict for demonstration
# Replace with your actual database (MongoDB, PostgreSQL, SQLite, etc.)
users_db = {}  # Format: { "email": { "email": "", "phone": "", "password_hash": "" } }

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number (10 digits)"""
    pattern = r'^\d{10}$'
    return re.match(pattern, phone) is not None

def generate_token(email):
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
        return None

@omr_bp.route('/v3rify', methods=['POST'])
def v3rify():
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
        email = data.get('email', '').strip()
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
            
            # Pass user info to the route
            request.current_user = users_db[current_user_email]
            
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
# @omr_bp.route('/protected', methods=['GET'])
# @token_required
# def protected_route():
#     user = request.current_user
#     return jsonify({
#         "success": True,
#         "message": f"Hello {user['email']}!"
#     })