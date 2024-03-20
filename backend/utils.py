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


def size512Or256(size):
    return size == 512 or size == 256

def _validate_type(value, expected_type, name):
    if not isinstance(value, expected_type):
        raise ValueError(f"Value {name} must be {expected_type.__name__}")