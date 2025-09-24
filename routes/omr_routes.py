from flask import Blueprint, request, jsonify
import json

# Create a blueprint named 'omr_bp'
omr_bp = Blueprint('omr_bp', __name__)

@omr_bp.route('/omrcheck', methods=['POST'])
def omr_check():
    print("OMR check endpoint hit.")

    # 1. Get the JSON data from the request
    try:
        submitted_data = request.get_json(force=True)
        submitted_answers = submitted_data.get('omr_answers', {})
    except Exception as e:
        print(f"Error reading JSON: {e}")
        return jsonify({"error": "Invalid JSON format"}), 400

    # 2. Read the correct answers from backend/data/Answerkey_Test.json
    try:
        # Note: The path is relative to where the main app is running
        with open('backend/data/Answerkey_Test.json', 'r') as f:
            correct_answers_data = json.load(f)
            correct_answers = correct_answers_data.get('omr_answers', {})
    except FileNotFoundError:
        print("backend/data/Answerkey_Test.json not found.")
        return jsonify({"error": "Correct answers file not found"}), 500
    except Exception as e:
        print(f"Error reading correct answers file: {e}")
        return jsonify({"error": "Error processing correct answers file"}), 500
        
    # 3. Compare the answers and calculate the score
    correct_count = 0
    for question_number, user_answer in submitted_answers.items():
        if question_number in correct_answers and user_answer == correct_answers[question_number]:
            correct_count += 1

    # 4. Return the result to the frontend
    result = {
        "message": "OMR sheet checked successfully!",
        "total_correct": correct_count,
        "total_questions": len(correct_answers)
    }
    
    print(f"Result: {result}")
    return jsonify(result)