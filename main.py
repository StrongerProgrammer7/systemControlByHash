import os
import tkinter as tk
from tkinter import filedialog, ttk

from backend.Hashs.WorkHash import WorkHash
# from ui.ui import *

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
        toggle_button_state(button_hash)
        toggle_button_state(button_check_integrity)
        toggle_button_state(algorithm_combobox)


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
    changeChecker(algorithm)
    success = checker.hashing_file(root.file_path)
    if success:
        tk.messagebox.showinfo("Хэш", "Успешно выполнен")
    else:
        tk.messagebox.showerror("Хэш", "Проблемы с хэшированием проверьте файл")

def generate_report():
    checker.generate_report()


def changeChecker(algorithm):
    if algorithm == "Stribog":
        checker.changeTypeHash("STRIBOG")
    elif algorithm == "SHA":
        checker.changeTypeHash("SHA")
    else:
        checker.changeTypeHash("SHAKE")

def check_integrity():
    algorithm = algorithm_combobox.get()
    data = checker.get_data_by_file_path(root.file_path)

    if data is None:
        tk.messagebox.showerror("Проверка целостности", "Файл не найден в базе данных.")
    type_hash_for_file = data[3]
    changeChecker(type_hash_for_file)
    diff = checker.check_file(root.file_path)
    print(diff)
    if diff is not None and len(diff) > 0:
        tk.messagebox.showerror("Проверка целостности", "Хэши не совпадают, см различия")
        display_difference(diff)
    else:
        tk.messagebox.showinfo("Проверка целостности", "Хэши совпадают.")

    changeChecker(algorithm)

def display_difference(record):
    diff_window = tk.Toplevel(root)
    diff_window.title("Различия в записи базы данных")

    diff_text_widget = tk.Text(diff_window, wrap="word", height=10)
    diff_text_widget.pack(fill="both", expand=True)

    for elem in record:
        diff_text_widget.insert(tk.END,elem)

    # diff_text_widget.insert(tk.END, "Абсолютный путь файла: {}\n".format(record[1]))
    # diff_text_widget.insert(tk.END, "Хэш в базе данных: {}\n".format(record[2]))
    # diff_text_widget.insert(tk.END, "Хэш, рассчитанный сейчас: {}\n".format(hash_value))
    # diff_text_widget.insert(tk.END, "Тип хэша: {}\n".format(record[4]))
    # if record[5]:
    #     diff_text_widget.insert(tk.END, "Тип шифрования: {}\n".format(record[5]))
    # if record[6]:
    #     diff_text_widget.insert(tk.END, "Дополнительная информация о шифровании: {}\n".format(", ".join(record[6])))
    # if record[7]:
    #     diff_text_widget.insert(tk.END, "Ключ для расшифровки хэша: {}\n".format(record[7]))

def checkbox_changed(event):
    if checkbox1["state"] != tk.DISABLED:
        if checkbox1_var.get() == 0:
            checker.set_encrypt_method("DES")
        else:
            checker.set_encrypt_method(None)

def pastKey():
    file_path = filedialog.askopenfilename()
    if file_path:
        print("Выбранный файл:", file_path)
        tk.messagebox.showinfo("Ключи", "ключи загружены")
        toggle_button_state(checkbox1)

def toggle_button_state(elem):
    state = elem['state']
    elem['state'] = tk.NORMAL
    # if state == tk.NORMAL:
    #     elem['state'] = tk.DISABLED  # Если кнопка активна, делаем ее неактивной
    # else:
    #     elem['state'] = tk.NORMAL  # Если кнопка неактивна, делаем ее активной

if __name__ == '__main__':
    global checker
    checker =WorkHash(256, "STRIBOG")
    # Создание главного окна
    root = tk.Tk()
    root.title("Выбор файла")

    # Установка размеров окна
    root.geometry("600x400")

    # Создание кнопки для выбора файла и установка положения
    button_choose = tk.Button(root, text="Выбрать файл", command=choose_file)
    button_hash = tk.Button(root, text="Захэшировать", command=compute_hash,state=tk.DISABLED)
    button_report = tk.Button(root, text="Сгенерировать отчет", command=generate_report)
    button_check_integrity = tk.Button(root, text="Проверить целостность", command=check_integrity,state=tk.DISABLED)
    btn_past_key = tk.Button(root, text="Считать ключи", command=pastKey)

    button_choose.grid(row=0, column=0, sticky="ew")
    button_hash.grid(row=1, column=0, sticky="ew")
    button_report.grid(row=2, column=0, sticky="ew")
    button_check_integrity.grid(row=3, column=0, sticky="ew")
    btn_past_key.grid(row=4, column=0, sticky="ew")

    text_widget = tk.Text(root, wrap="word", height=20, width=60)
    text_widget.grid(row=0, column=1, rowspan=3, sticky="nsew")
    text_widget.config(state=tk.DISABLED)  # Начальное состояние виджета - только для чтения


    algorithms = ["Stribog", "SHA", "SHAKE"]
    algorithm_combobox = ttk.Combobox(root, values=algorithms,state=tk.DISABLED)
    algorithm_combobox.grid(row=4,column=1,padx=25,sticky="w")
    algorithm_combobox.set("Stribog")

    checkbox1_var = tk.IntVar()
    checkbox1 = tk.Checkbutton(root, text="DES", variable=checkbox1_var,state=tk.DISABLED)
    checkbox1.grid(row=4, column=1, padx=25,sticky="e")
    checkbox1.bind("<Button-1>", checkbox_changed)
   # btn_past_key.bind("<Button-1>",lambda event: toggle_button_state())
    # Запуск цикла обработки событий
    root.mainloop()
