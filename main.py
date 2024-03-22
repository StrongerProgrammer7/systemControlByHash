import tkinter as tk
from tkinter import filedialog, ttk
from backend.SHA import SHA
from backend.Stribog import Stribog, EncryptMethods
from backend.SHAKE import SHAKE
from backend.utils import add_text_to_file, clear_and_write

from ui.ui import *

from backend.BD_system.work_with_db import CRUD

db = CRUD()
def workHash(hash, file_path):
    hash.hashingFile(file_path)
    clear_and_write("test_files/example2.txt", "test_files/ex3.txt")
    hash.check_integrity(file_path)


def generateReport(hash):
    hash.generate_report()


def choose_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        print("Выбранный файл:", file_path)
        file_name, file_content = read_file_content(file_path)
        update_text_widget(file_name, file_content)
        # Активируем кнопки для вычисления хэша и генерации отчета после выбора файла
        button_hash.config(state=tk.NORMAL)
        button_report.config(state=tk.NORMAL)
        # Сохраняем путь к выбранному файлу для последующего использования
        root.file_path = file_path


def read_file_content(file_path):
    file_name = os.path.basename(file_path)
    with open(file_path, 'r') as file:
        content = file.read()
    return file_name, content


def update_text_widget(file_name, file_content):
    text_widget.config(state=tk.NORMAL)  # Установка состояния на "нормальное" для возможности редактирования
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, f"Название файла: {file_name}\n\n")
    text_widget.insert(tk.END, "Содержимое файла:\n")
    text_widget.insert(tk.END, file_content)
    text_widget.config(state=tk.DISABLED)  # Установка состояния на "заблокированное" для только чтения


def compute_hash():
    algorithm = algorithm_combobox.get()
    if algorithm == "Stribog":
        checker = Stribog(256, encryptMethod=None)
    elif algorithm == "SHA":
        checker = SHA(256, encryptMethod=None)
    elif algorithm == "SHAKE":
        checker = SHAKE(256)
    workHash(checker, root.file_path)


def generate_report():
    algorithm = algorithm_combobox.get()
    if algorithm == "Stribog":
        checker = Stribog(256, encryptMethod=None)
    elif algorithm == "SHA":
        checker = SHA(256, encryptMethod=None)
    elif algorithm == "SHAKE":
        checker = SHAKE(256)
    generateReport(checker)


def check_integrity():
    algorithm = algorithm_combobox.get()
    if algorithm == "Stribog":
        checker = Stribog(256, encryptMethod=None)
    elif algorithm == "SHA":
        checker = SHA(256, encryptMethod=None)
    elif algorithm == "SHAKE":
        checker = SHAKE(256)
    record = db.get_data(root.file_path)
    if record:
        with open(root.file_path, 'rb') as file:
            file_data = file.read()
            hash_value = hash(file_data)  # Рассчитываем хэш файла

        if record[2] == hash_value:  # Проверяем совпадение хэшей
            tk.messagebox.showinfo("Проверка целостности", "Хэши совпадают.")
        else:
            display_difference(record)
    else:
        tk.messagebox.showerror("Проверка целостности", "Файл не найден в базе данных.")


def display_difference(record):
    diff_window = tk.Toplevel(root)
    diff_window.title("Различия в записи базы данных")

    diff_text_widget = tk.Text(diff_window, wrap="word", height=10)
    diff_text_widget.pack(fill="both", expand=True)

    diff_text_widget.insert(tk.END, "Абсолютный путь файла: {}\n".format(record[1]))
    diff_text_widget.insert(tk.END, "Хэш в базе данных: {}\n".format(record[2]))
    diff_text_widget.insert(tk.END, "Хэш, рассчитанный сейчас: {}\n".format(hash_value))
    diff_text_widget.insert(tk.END, "Тип хэша: {}\n".format(record[4]))
    if record[5]:
        diff_text_widget.insert(tk.END, "Тип шифрования: {}\n".format(record[5]))
    if record[6]:
        diff_text_widget.insert(tk.END, "Дополнительная информация о шифровании: {}\n".format(", ".join(record[6])))
    if record[7]:
        diff_text_widget.insert(tk.END, "Ключ для расшифровки хэша: {}\n".format(record[7]))


if __name__ == '__main__':
    # Создание главного окна
    root = tk.Tk()
    root.title("Выбор файла")

    # Установка размеров окна
    root.geometry("600x400")

    # Создание кнопки для выбора файла и установка положения
    button_choose = tk.Button(root, text="Выбрать файл", command=choose_file)
    button_choose.pack(pady=20, padx=20, side=tk.LEFT)

    # Создание текстового виджета для отображения названия файла и его содержимого
    text_widget = tk.Text(root, wrap="word", height=20)
    text_widget.pack(fill="both", expand=True)
    text_widget.config(state=tk.DISABLED)  # Начальное состояние виджета - только для чтения

    # Создание выпадающего списка для выбора алгоритма хэширования
    algorithms = ["Stribog", "SHA", "SHAKE"]
    algorithm_combobox = ttk.Combobox(root, values=algorithms)
    algorithm_combobox.pack(pady=20, padx=20, side=tk.LEFT)
    algorithm_combobox.set("Stribog")  # Установка значения по умолчанию

    # Создание кнопки для вычисления хэша файла
    button_hash = tk.Button(root, text="Хэш", command=compute_hash)
    button_hash.pack(pady=20, padx=20, side=tk.RIGHT)

    # Создание кнопки для генерации отчета
    button_report = tk.Button(root, text="Сгенерировать отчет", command=generate_report)
    button_report.pack(pady=20, padx=20, side=tk.RIGHT)

    # Создание кнопки для проверки целостности файла
    button_check_integrity = tk.Button(root, text="Проверить целостность", command=check_integrity)
    button_check_integrity.pack(pady=20, padx=20, side=tk.BOTTOM)

    # Запуск цикла обработки событий
    root.mainloop()
