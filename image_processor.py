import os
from PIL import Image  # pip install Pillow

def process_image_files(root_folder, valid_extensions=None):
    """
    Рекурсивно обходит папку root_folder и её подпапки,
    открывает каждый найденный файл с заданными расширениями изображений.

    :param root_folder: путь к корневой папке
    :param valid_extensions: кортеж допустимых расширений (например, ('.tif', '.jpg')).
                             Если None, используются расширения по умолчанию.
    """
    # Расширения по умолчанию, если не переданы явно
    if valid_extensions is None:
        valid_extensions = ('.tif', '.tiff', '.jpg', '.jpeg', '.png', '.bmp', '.gif')

    # Приводим к нижнему регистру для корректного сравнения
    valid_extensions = tuple(ext.lower() for ext in valid_extensions)

    if not os.path.isdir(root_folder):
        print(f"Ошибка: папка '{root_folder}' не найдена.")
        return

    # os.walk генерирует пути ко всем файлам во всех подпапках
    for dirpath, dirnames, filenames in os.walk(root_folder):
        for filename in filenames:
            # Проверяем расширение (регистронезависимо)
            if filename.lower().endswith(valid_extensions):
                file_path = os.path.join(dirpath, filename)
                print(f"Открываю: {file_path}")

                try:
                    # Открываем изображение с помощью Pillow
                    with Image.open(file_path) as img:
                        # ==================================================
                        # ===   ВСТАВЬТЕ СВОЙ КОД ОБРАБОТКИ СЮДА   ===========
                        # ==================================================
                        # Например:
                        # width, height = img.size
                        # print(f"Размер изображения: {width} x {height}")
                        pass
                        # ==================================================
                except Exception as e:
                    print(f"Не удалось обработать {file_path}: {e}")

if __name__ == "__main__":
    # Укажите здесь путь к вашей папке X
    folder_X = r"D:\ПДнDataset\share\Выгрузки\Сайты"

    # Пример 1: использовать расширения по умолчанию (tif, jpg, png и т.д.)
    process_image_files(folder_X)

    # Пример 2: передать только нужные расширения
    # process_image_files(folder_X, valid_extensions=('.tif', '.jpeg', '.png'))