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

def clear_and_write(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()
    with open(output_file, 'w') as f:
        f.write(content)

def size512Or256(size):
    return size == 512 or size == 256

def _validate_type(value, expected_type, name):
    if not isinstance(value, expected_type):
        raise ValueError(f"Value {name} must be {expected_type.__name__}")

def get_tempFileIncludeContentFromDB(content_from_db, temp_file_path='test_files/temp.txt'):
    try:
        if content_from_db:
            # Записываем содержимое в новый файл
            with open(temp_file_path, 'wb') as file:
                file.write(content_from_db)

            print(f"File '{temp_file_path}' has been successfully retrieved from the database.".format("temp.txt"))
        else:
            print("File '{}' not found in the database.".format("temp.txt"))
        return temp_file_path
    except Exception as e:
        print("Error retrieving file from the database:", e)
        return None