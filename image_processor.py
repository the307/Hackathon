import os
import cv2
import numpy as np
import easyocr
from PIL import Image, ImageEnhance

reader = easyocr.Reader(['ru', 'en'], gpu=False)


# -----------------------------
# 🔥 ПРЕДОБРАБОТКА
# -----------------------------
def preprocess_image(file_path, save_debug=True):
    img = Image.open(file_path).convert("RGB")

    img = img.resize((img.width * 2, img.height * 2))

    img = ImageEnhance.Contrast(img).enhance(2.0)
    img = ImageEnhance.Sharpness(img).enhance(2.0)

    img_np = np.array(img)

    gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)

    gray = cv2.fastNlMeansDenoising(gray, None, 30, 7, 21)

    # ⚠️ ВАЖНО: НЕ threshold (он ухудшает EasyOCR)
    processed = gray

    # ✔ сохранение debug
    if save_debug:
        folder = os.path.dirname(file_path)
        name = os.path.splitext(os.path.basename(file_path))[0]

        debug_path = os.path.join(folder, f"{name}_processed.png")

        Image.fromarray(processed).save(debug_path)
        print(f"✔ Сохранено: {debug_path}")

    return processed


# -----------------------------
# 🔥 OCR
# -----------------------------
def extract_text_from_file(file_path):
    try:
        img = preprocess_image(file_path, save_debug=True)

        # ✔ EasyOCR любит 3 канала
        img = cv2.cvtColor(img, cv2.COLOR_GRAY2RGB)

        result = reader.readtext(
            img,
            detail=1,
            paragraph=True,
            contrast_ths=0.1,
            adjust_contrast=0.7,
            text_threshold=0.5
        )

        text = " ".join([r[1] for r in result])

        return text

    except Exception as e:
        print(f"Ошибка {file_path}: {e}")
        return ""


# -----------------------------
# 🔥 ПАПКА
# -----------------------------
def extract_text_from_folder(folder_path):
    supported = ('.png', '.jpg', '.jpeg', '.tif', '.tiff', '.bmp')

    all_text = []

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(supported):
                path = os.path.join(root, file)

                print(f"Читаю: {path}")

                text = extract_text_from_file(path)

                if text.strip():
                    all_text.append(text)

    return "\n".join(all_text)


# -----------------------------
# 🚀 RUN
# -----------------------------
text = extract_text_from_folder(r"D:\ПДнDataset\share\Архив сканы\x\zzx36d00")

print("=== РЕЗУЛЬТАТ ===")
print(text)