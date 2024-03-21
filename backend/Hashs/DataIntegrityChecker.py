import os
import logging
from overrides import overrides

from backend.utils import size512Or256, _validate_type, get_tempFileIncludeContentFromDB
from backend.enums.enumHash import Hashs
from backend.enums.enumEncryptMethod import EncryptMethods
from backend.Encrypt.AES import EncryptAES
from backend.Encrypt.DES import EncryptDES
from backend.BD_system.work_with_db import CRUD
from backend.DifferenceFile import SearchDifferenceFile


class DataIntegrityChecker:

    def __init__(self, sizeHash, typeHash, encryptMethod):
        _validate_type(sizeHash, int, "sizeHash")
        _validate_type(typeHash, Hashs, "typeHash")

        if not size512Or256(sizeHash):
            raise ValueError("Size hash must be 512 or 256")

        self._data = {} # TODO Save too,
        self.typeHash = typeHash
        self.sizeHash = sizeHash
        self.typeEncrypt = None
        self._encryptMethod = None

        self._set_system_encrypt(encryptMethod)
        self._db = CRUD()
        self._searchDiff = SearchDifferenceFile()
        self._setup_logging()

    def hashingFile(self, file_path):
        if os.path.exists(file_path):
            pass  # "Overload methods")
        else:
            print(f"File '{file_path}' not found.")
            logging.error(f"File '{file_path}' not found.")
            return False

    def check_integrity(self, file_path):
        data = self._db.get_data(file_path)[1]
        if data == file_path:
            pass  # "Overload methods")
        else:
            print(f"File '{file_path}' not found in integrity records.")
            logging.error(f"File '{file_path}' not found in integrity records.")

    def get_hash(self, data, callback=None):
        pass  # overload

    def usingEncrypt(self, encryptMethod):
        if encryptMethod is None:
            self._encryptMethod = None
            self.typeEncrypt = None
        else:
            _validate_type(encryptMethod, str, "encryptMethod")
            self._set_system_encrypt(encryptMethod)

    def deleteHashByPath(self, file_path):
        self._db.delete_by_absolute_path(file_path)

    def get_data_all(self):
        return self._db.get_data()

    def get_data_by_file_path(self, file_path):
        return self._db.get_data(file_path)

    # private methods
    def _get_prev_hash(self, file_path):
        record = self.get_data_by_file_path(file_path)
        return record[2] if record is not None else ''

    def _record_to_db(self, hash_value, file_path, content):
        cipher = iv = tag = key = None
        if self.typeEncrypt is not None:
            cipher, iv, key = self._encryptMethod.encrypt_hash(content)
        self._data[file_path] = hash_value

        self._db.insert(absolute_path=file_path,
                        hash_value=hash_value,
                        type_hash=self.typeHash.value,
                        body_file=content if self.typeEncrypt is None else None,
                        encrypted_hash=cipher if self.typeEncrypt is not None else None,
                        type_encrypted=self.typeEncrypt.value if self.typeEncrypt is not None else None,
                        iv=iv if self.typeEncrypt is not None else None,
                        hash_key_encrypted=key if self.typeEncrypt is not None else None)

    def _get_line_difference_file(self, file_path):
        record = self._db.get_data(file_path)
        if record[8] is None:
            content = self._encryptMethod.decrypt_hash(record[3], record[6], record[7])
        else:
            content = record[8]

        path = get_tempFileIncludeContentFromDB(content)
        differences = self._searchDiff.getDifferenceFile(file_path, path)
        return differences

    def _set_system_encrypt(self, typeEncrypt):
        if typeEncrypt == EncryptMethods.AES.value:
            self.typeEncrypt = EncryptMethods.AES
            self._encryptMethod = EncryptAES(16)
        elif typeEncrypt == EncryptMethods.DES.value:
            self.typeEncrypt = EncryptMethods.DES
            self._encryptMethod = EncryptDES(8)
        else:
            self.typeEncrypt = None
            self._encryptMethod = None

    def _setup_logging(self):
        logging.basicConfig(filename='data_integrity.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
