from flask import Blueprint, request, jsonify
import csv
import io
import os

# Create a blueprint named 'omr_bpc'
omr_bpc = Blueprint('omr_bpc', __name__)

@omr_bpc.route('/omrcheck', methods=['POST'])
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