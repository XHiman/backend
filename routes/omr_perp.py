import cv2
import numpy as np
import pandas as pd

def align_omr_sheet(img):
    # Convert to grayscale and blur
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5,5), 0)
    # Find edges
    edged = cv2.Canny(blurred, 75, 200)
    # Find contours, select largest contour assuming it's the sheet
    cnts, _ = cv2.findContours(edged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    cnts = sorted(cnts, key=cv2.contourArea, reverse=True)
    for c in cnts:
        peri = cv2.arcLength(c, True)
        approx = cv2.approxPolyDP(c, 0.02 * peri, True)
        if len(approx) == 4:  # Found rectangle
            sheet_cnt = approx
            break
    else:
        raise Exception("Sheet border not found")
    # Warp perspective
    pts = sheet_cnt.reshape(4,2)
    rect = np.zeros((4,2), dtype="float32")
    s = pts.sum(axis=1)
    rect[0] = pts[np.argmin(s)]
    rect[2] = pts[np.argmax(s)]
    diff = np.diff(pts, axis=1)
    rect[1] = pts[np.argmin(diff)]
    rect[3] = pts[np.argmax(diff)]
    (tl,tr,br,bl) = rect
    widthA = np.linalg.norm(br-bl)
    widthB = np.linalg.norm(tr-tl)
    heightA = np.linalg.norm(tr-br)
    heightB = np.linalg.norm(tl-bl)
    maxWidth = max(int(widthA), int(widthB))
    maxHeight = max(int(heightA), int(heightB))
    dst = np.array([[0,0],[maxWidth-1,0],[maxWidth-1,maxHeight-1],[0,maxHeight-1]], dtype="float32")
    M = cv2.getPerspectiveTransform(rect, dst)
    warped = cv2.warpPerspective(img, M, (maxWidth, maxHeight))
    return warped

def detect_bubbles_and_answers(aligned_img, num_options=4, answer_threshold=0.2):
    gray = cv2.cvtColor(aligned_img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    # Find all contours that look like bubbles
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    bubble_cnts = []
    for c in contours:
        (x, y, w, h) = cv2.boundingRect(c)
        aspectRatio = w / float(h)
        # Filter bubbles: dimension/shape, ignore small/noise
        if w >= 15 and h >= 15 and 0.8 <= aspectRatio <= 1.2:
            bubble_cnts.append(c)
    # Sort bubbles (e.g., top-to-bottom, left-to-right)
    bubble_cnts = sorted(bubble_cnts, key=lambda c: cv2.boundingRect(c)[1])
    # Assuming the bubbles are arranged in grid, group into rows
    answers = {}
    question_num = 1
    row_bubbles = []
    prev_y = None
    for c in bubble_cnts:
        (x, y, w, h) = cv2.boundingRect(c)
        if prev_y is None or abs(y-prev_y) < 10:
            row_bubbles.append((x, y, w, h, c))
        else:
            # Analyze previous row
            row_bubbles = sorted(row_bubbles, key=lambda b: b[0])
            bubble_status = []
            for bx, by, bw, bh, bc in row_bubbles:
                roi = thresh[by:by+bh, bx:bx+bw]
                filled_ratio = cv2.countNonZero(roi)/float(roi.size)
                bubble_status.append(filled_ratio)
            best_choice = np.argmax(bubble_status)
            if bubble_status[best_choice] > answer_threshold:
                answers[question_num] = chr(ord('A')+best_choice)
            else:
                answers[question_num] = ''
            question_num += 1
            row_bubbles = [(x, y, w, h, c)]
        prev_y = y
    # Final row
    if row_bubbles:
        row_bubbles = sorted(row_bubbles, key=lambda b: b[0])
        bubble_status = []
        for bx, by, bw, bh, bc in row_bubbles:
            roi = thresh[by:by+bh, bx:bx+bw]
            filled_ratio = cv2.countNonZero(roi)/float(roi.size)
            bubble_status.append(filled_ratio)
        best_choice = np.argmax(bubble_status)
        if bubble_status[best_choice] > answer_threshold:
            answers[question_num] = chr(ord('A')+best_choice)
        else:
            answers[question_num] = ''
    return answers

def process_omr_auto(image_path, output_csv=None):
    img = cv2.imread(image_path)
    aligned = align_omr_sheet(img)
    answers = detect_bubbles_and_answers(aligned)
    all_questions = list(range(1, 201))  # e.g., 100
    rows = []
    for q_num in all_questions:
        ans = answers.get(q_num, "")  # blank if not found
        rows.append([q_num, ans])
    df = pd.DataFrame(list(answers.items()), columns=["question", "answer"])
    if not output_csv:
        output_csv = "omr_result.csv"
    df.to_csv(output_csv, index=False)
    print(f"Results written to {output_csv}")

if __name__ == "__main__":
    process_omr_auto("backend/data/1.png")

