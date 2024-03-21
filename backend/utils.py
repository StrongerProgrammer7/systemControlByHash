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

def retrieve_file_from_database(record,absolute_path):
    try:

        if record[8]:
            # Записываем содержимое в новый файл
            with open('retrieved_file.txt', 'wb') as file:
                file.write(record[8])

            print("File '{}' has been successfully retrieved from the database.".format("retrieved_file.txt"))
        else:
            print("File '{}' not found in the database.".format("retrieved_file.txt"))

    except Exception as e:
        print("Error retrieving file from the database:", e)