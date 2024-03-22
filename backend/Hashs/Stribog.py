import _pystribog

from backend.Hashs.DataIntegrityChecker import DataIntegrityChecker, Hashs,overrides
import logging


class Stribog(DataIntegrityChecker):
    def __init__(self, sizeHash=512, encryptMethod=None):
        super().__init__(sizeHash, Hashs.STRIBOG, encryptMethod)
        self._systemHash = _pystribog.StribogHash(sizeHash)

    @overrides
    def hashingFile(self, file_path):
        isAccess = super().hashingFile(file_path)
        if isAccess == False:
            return isAccess

        with open(file_path, "rb") as file:
            data = file.read()
            hash_value = self.get_hash(data)

            super()._record_to_db(hash_value, file_path, data)

            print(f"File '{file_path}' added with hash value: {hash_value}")
            logging.info(f"File '{file_path}' added with hash value: {hash_value}")
            return True

    @overrides
    def check_integrity(self, file_path):
        super().check_integrity(file_path)
        with open(file_path, "rb") as file:
            data = file.read()

            new_hash = self.get_hash(data)

            prev_hash = super()._get_prev_hash(file_path=file_path)#super()._getHash(super()._getDecryptHash, file_path)

            if new_hash == prev_hash:
                logging.info(f"Integrity {self.typeHash} of '{file_path}' verified.")
                print(f"Integrity of '{file_path}' verified.")
                return []
            else:
                logging.warning(f"Integrity check {self.typeHash} failed for '{file_path}'.")
                print(f"Integrity check failed for '{file_path}'.")

                return self._get_line_difference_file(file_path)

    @overrides
    def get_hash(self, data, callback=None):
        self._systemHash.update(data)
        hash_value = self._systemHash.hexdigest()
        self._systemHash.clear()

        return hash_value