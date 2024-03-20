from backend.DataIntegrityChecker import DataIntegrityChecker
from backend.enumHash import Hash
import logging

class SHA(DataIntegrityChecker):

    def __init__(self, sizeHash=512):
        super().__init__(sizeHash, Hash.SHA)

    def hashingFile(self, file_path):
        super().hashingFile(file_path)
        with open(file_path, "rb") as file:
            data = file.read()
            hash_object = self._systemHash.new(data)
            hash_value = hash_object.hexdigest()
            self._data[file_path] = hash_value
            print(f"File '{file_path}' added with hash value: {hash_value}")
            logging.info(f"File '{file_path}' added with hash value: {hash_value}")
            return True

    def check_integrity(self, file_path):
        super().check_integrity(file_path)
        with open(file_path, "rb") as file:
            data = file.read()

            hash_object = self._systemHash.new(data)
            hash_value = hash_object.hexdigest()

            if hash_value == self._data[file_path]:
                logging.info(f"Integrity {self.typeHash} of '{file_path}' verified.")
                print(f"Integrity of '{file_path}' verified.")
                return True
            else:
                logging.warning(f"Integrity check {self.typeHash} failed for '{file_path}'.")
                print(f"Integrity check failed for '{file_path}'.")
                return False
