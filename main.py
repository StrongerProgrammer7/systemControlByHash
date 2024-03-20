#from Crypto.Hash import SHA512
import _pystribog
import binascii
import os

class DataIntegrityChecker:
    def __init__(self,sizeHash=512):
        self.data = {}
        if sizeHash == 512:
            self.stribog = _pystribog.StribogHash(_pystribog.Hash512)
        else:
            self.stribog = _pystribog.StribogHash(_pystribog.Hash256)

    def add_file(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, "rb") as file:
                data = file.read()
                self.stribog.update(data)
                hash_value = self.stribog.hexdigest()
                self.data[file_path] = hash_value

                print(f"File '{file_path}' added with hash value: {hash_value}")
        else:
            print(f"File '{file_path}' not found.")

    def check_integrity(self, file_path):
        if file_path in self.data:
            with open(file_path, "rb") as file:
                data = file.read()

                self.stribog.clear()
                self.stribog.update(data)
                hash_value = self.stribog.hexdigest()

                if hash_value == self.data[file_path]:
                    print(f"Integrity of '{file_path}' verified.")
                else:
                    print(f"Integrity check failed for '{file_path}'.")
        else:
            print(f"File '{file_path}' not found in integrity records.")

# Пример использования
checker = DataIntegrityChecker()

# Добавляем файлы для контроля целостности
checker.add_file("example.txt")
def add_text_to_file(file_path, text):
    with open(file_path, "a") as file:
        file.write(text)
    print(f"Text added to '{file_path}'.")


add_text_to_file("example.txt", "This is some additional text.\n")
# Check file integrity
checker.check_integrity("example.txt")

'''
work with SHA
hash_object = SHA512.new(data)
hash_value = hash_object.hexdigest()
                
'''