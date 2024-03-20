
import os.path

def add_text_to_file(file_path, text):
    if os.path.exists(file_path):
        with open(file_path, "a") as file:
            file.write(text)
        print(f"Text added to '{file_path}'.")
        return True
    else:
        print("Path doesn't exists!")
        return False