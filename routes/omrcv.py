import cv2
import numpy as np
import pandas as pd

def process_omr(image_path, set_name="A", output_csv=None):
    if output_csv is None:
        output_csv = f"set{set_name}_omr.csv"

    # Load image
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Could not load image: {image_path}")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Threshold to get filled bubbles
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

    # Sheet dimensions (after warp)
    height, width = thresh.shape

    # --------------------------
    # PARAMETERS (tune for sheet)
    # --------------------------
    num_questions = 150
    num_options = 4  # A-D
    top_offset = 380   # px where questions grid starts
    left_offset = 60   # px where first option column starts
    row_height = 38    # px between rows
    col_width = 72     # px between option columns

    answers = {}
    for q in range(num_questions):
        y = top_offset + q * row_height
        row_values = []
        for opt in range(num_options):
            x = left_offset + opt * col_width
            roi = thresh[y:y+row_height, x:x+col_width]

            # ratio of filled pixels
            filled_ratio = cv2.countNonZero(roi) / float(roi.size)
            row_values.append(filled_ratio)

        chosen = np.argmax(row_values)
        if row_values[chosen] > 0.25:  # threshold: adjust if faint marks
            answers[q+1] = chr(ord("A")+chosen)
        else:
            answers[q+1] = ""

    # Save CSV
    df = pd.DataFrame(list(answers.items()), columns=["question", "answer"])
    df.to_csv(output_csv, index=False, encoding="utf-8")
    print(f"OMR processed. Output saved: {output_csv}")

if __name__ == "__main__":
    process_omr("backend/routes/omr_sample.png", set_name="A")
