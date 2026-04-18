from PIL import Image  # pip install Pillow

def process_image_file(file_path):
    """
    Открывает файл изображения по указанному пути и предоставляет
    место для пользовательской обработки.

    :param file_path: строка с полным путём к файлу изображения.
                      Поддерживаются форматы, которые может открыть Pillow
                      (TIFF, JPEG, PNG, BMP, GIF и др.).
    """
    if not isinstance(file_path, str):
        raise TypeError("file_path должен быть строкой")

    print(f"Открываю: {file_path}")

    try:
        # Открываем изображение. Контекстный менеджер автоматически закроет файл.
        with Image.open(file_path) as img:
            # ==================================================
            # ===   ВСТАВЬТЕ СВОЙ КОД ОБРАБОТКИ СЮДА   ===========
            # ==================================================
            # Например:
            # width, height = img.size
            # print(f"Размер: {width} x {height}")
            # img_processed = img.rotate(45)
            # img_processed.save("output.jpg")
            pass
            # ==================================================
    except FileNotFoundError:
        print(f"Файл не найден: {file_path}")
    except Exception as e:
        print(f"Ошибка при обработке {file_path}: {e}")