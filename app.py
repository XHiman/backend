from flask import Flask
from flask_cors import CORS
from routes.omr_routes import omr_bp  # Import your blueprint

app = Flask(__name__)

# Configure CORS for production
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://hippos.digital",
            "https://backend-x873.onrender.com/",
            "http://localhost:3000",
            "http://localhost:5173"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Register the blueprint
app.register_blueprint(omr_bp)

# Define a simple home route for testing
@app.route('/')
def home():
    return '<h1>Welcome to the OMR Backend!</h1>'

if __name__ == '__main__':
    # Make sure to run this file with 'python app.py'
    app.run(host="0.0.0.0", debug=False, port=5000)