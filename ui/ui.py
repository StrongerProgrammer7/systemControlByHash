import tkinter as tk
from tkinter import filedialog
import os
import json
import hashlib

def hash_file(file_path, hash_algorithm='sha256', chunk_size=65536):
    """Calculate the hash of a file."""
    # Choose hash algorithm
    hasher = hashlib.new(hash_algorithm)

    # Open the file in binary mode
    with open(file_path, 'rb') as file:
        # Read the file chunk by chunk
        while chunk := file.read(chunk_size):
            hasher.update(chunk)

    # Return the hexadecimal representation of the digest
    return hasher.hexdigest()

def choose_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        print("Выбранный файл:", file_path)
        file_name, file_content = read_file_content(file_path)
        update_text_widget(file_name, file_content)
        # Активируем кнопку для вычисления хэша после выбора файла
        button_hash.config(state=tk.NORMAL)
        # Сохраняем путь к выбранному файлу для последующего использования
        root.file_path = file_path

def compute_hash():
    file_path = root.file_path  # Получаем путь к выбранному файлу
    if file_path:
        print("Выбранный файл для вычисления хэша:", file_path)
        file_hash = hash_file(file_path)
        save_to_json(os.path.basename(file_path), file_hash)  # Сохраняем информацию в JSON

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

def save_to_json(file_name, file_hash):
    data = {"file_name": file_name, "file_hash": file_hash}
    with open("file_info.json", "w") as json_file:
        json.dump(data, json_file)
        print("Информация о файле сохранена в file_info.json")

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

# Создание кнопки для вычисления хэша файла
button_hash = tk.Button(root, text="Хэш", command=compute_hash, state=tk.DISABLED)
button_hash.pack(pady=20, padx=20, side=tk.RIGHT)

# Запуск цикла обработки событий
root.mainloop()