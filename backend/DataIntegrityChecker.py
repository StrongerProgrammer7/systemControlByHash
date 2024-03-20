import _pystribog
import os


class DataIntegrityChecker:

    def __init__(self, sizeHash=512):
        self._data = {}
        if sizeHash == 512:
            self._stribog = _pystribog.StribogHash(_pystribog.Hash512)
        else:
            self._stribog = _pystribog.StribogHash(_pystribog.Hash256)

    def hashingFile(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, "rb") as file:
                data = file.read()
                self._stribog.update(data)
                hash_value = self._stribog.hexdigest()
                self._data[file_path] = hash_value
                print(f"File '{file_path}' added with hash value: {hash_value}")
        else:
            print(f"File '{file_path}' not found.")

    def check_integrity(self, file_path):
        if file_path in self._data:
            with open(file_path, "rb") as file:
                data = file.read()

                self._stribog.clear()
                self._stribog.update(data)
                hash_value = self._stribog.hexdigest()

                if hash_value == self._data[file_path]:
                    print(f"Integrity of '{file_path}' verified.")
                    return True
                else:
                    print(f"Integrity check failed for '{file_path}'.")
                    return False

        else:
            print(f"File '{file_path}' not found in integrity records.")

    def gethashFile(self, pathFile):
        return self._data[pathFile]

    def changeHashSize(self, size):
        if size != _pystribog.Hash256 and size != _pystribog.Hash512:
            print("Not correct size")
            return False
        self._stribog = _pystribog.StribogHash(size)
        print("Succes change")
        return True
