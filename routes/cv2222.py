import cv2
import numpy as np
import pandas as pd

def detect_filled_option(thresh, boxes, labels, threshold=0.2):
    """Detect which option is filled among given boxes"""
    values = []
    for (x, y, w, h) in boxes:
        roi = thresh[y:y+h, x:x+w]
        if roi.size == 0:
            values.append(0)
        else:
            values.append(cv2.countNonZero(roi) / float(roi.size))
    idx = np.argmax(values)
    return labels[idx] if values[idx] > threshold else ""

def process_omr(image_path, output_csv=None):
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Could not load image: {image_path}")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 0, 255,
                              cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

    # -----------------------
    # Detect SET (A/B/C/D)
    # -----------------------
    # Crop ROI (adjust values as per template)
    set_roi = thresh[250:400, 1150:1400]
    # Define 4 bubbles manually (x,y,w,h) relative to set_roi
    set_boxes = [
        (20, 40, 40, 40),   # A
        (100, 40, 40, 40),  # B
        (180, 40, 40, 40),  # C
        (260, 40, 40, 40)   # D
    ]
    set_labels = ["A", "B", "C", "D"]

    set_detected = detect_filled_option(set_roi, set_boxes, set_labels)

    if output_csv is None:
        output_csv = f"set{set_detected}_omr.csv"

    # -----------------------
    # Detect Answers
    # -----------------------
    # Crop big answering region (adjust y1:y2, x1:x2 as per your sheet)
    ans_roi = thresh[500:2200, 100:1600]

    num_questions = 100
    num_options = 4
    row_height = ans_roi.shape[0] // (num_questions // 5) // 5
    col_width = ans_roi.shape[1] // num_options

    answers = {}
    q_no = 1
    for block_row in range(5):          # 5 blocks down
        for block_col in range(5):      # 5 blocks across
            block_y = block_row * (row_height*20)
            block_x = block_col * (col_width*4)
            for i in range(20):         # 20 Qs per block
                y = block_y + i * row_height
                row_vals = []
                for opt in range(num_options):
                    x = block_x + opt * col_width
                    roi = ans_roi[y:y+row_height, x:x+col_width]
                    if roi.size == 0:
                        ratio = 0
                    else:
                        ratio = cv2.countNonZero(roi) / float(roi.size)
                    row_vals.append(ratio)
                chosen = np.argmax(row_vals)
                if row_vals[chosen] > 0.2:
                    answers[q_no] = chr(ord("A") + chosen)
                else:
                    answers[q_no] = ""
                q_no += 1

    # Save CSV
    df = pd.DataFrame(list(answers.items()), columns=["question", "answer"])
    df.to_csv(output_csv, index=False, encoding="utf-8")

    print(f"OMR processed. Set={set_detected}, Output={output_csv}")


if __name__ == "__main__":
    process_omr("backend/data/1.png")
