from flask import Flask
from flask_cors import CORS
from routes.omr_routes_csv import omr_bpc # Import your blueprint

app = Flask(__name__)
# Enable CORS for all routes within the omr_bp blueprint
CORS(app, resources={r"/omrcheck/*": {"origins": "*"}})

# Register the blueprint
app.register_blueprint(omr_bpc)

# Define a simple home route for testing
@app.route('/')
def home():
    return '<h1>Welcome to the OMR Backend!</h1>'

if __name__ == '__main__':
    # Make sure to run this file with 'python app.py'
    app.run(debug=True)