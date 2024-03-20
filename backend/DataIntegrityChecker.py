from Crypto.Hash import SHA512
from Crypto.Hash import SHA256

from base64 import b64decode,b64encode
import os
import logging

import _pystribog
from backend.utils import size512Or256, _validate_type
from backend.enums.enumHash import Hashs
from backend.enums.enumEncryptMethod import EncryptMethods
from backend.Encrypt.AES import EncryptAES
from backend.Encrypt.DES import EncryptDES

class DataIntegrityChecker:

    def __init__(self, sizeHash, typeHash, keyEncrypt, encryptMethod):
        _validate_type(sizeHash, int, "sizeHash")
        _validate_type(keyEncrypt, int, "keyEncrypt")
        _validate_type(typeHash, Hashs, "typeHash")

        if not size512Or256(sizeHash):
            raise ValueError("Size hash must be 512 or 256")

        self._data = {}
        self.typeHash = typeHash
        self.sizeHash = sizeHash
        self.typeEncrypt = encryptMethod

        self._set_system_hash()
        self._set_system_encrypt(keyEncrypt)
        self._setup_logging()


    def hashingFile(self, file_path):
        if os.path.exists(file_path):
            print("")#"Overload methods")
        else:
            print(f"File '{file_path}' not found.")
            logging.error(f"File '{file_path}' not found.")
            return False

    def check_integrity(self, file_path):
        if file_path in self._data:
            print("")#"Overload methods")
        else:
            print(f"File '{file_path}' not found in integrity records.")
            logging.error(f"File '{file_path}' not found in integrity records.")

    def getEncryptDataFile(self, file_path):
        return {
            self._data[file_path]['encrypted_hash'],
            self._data[file_path]['nonce'],
            self._data[file_path]['tag'],
        }

    def changeHashSize(self, size):
        if size != _pystribog.Hash256 and size != _pystribog.Hash512:
            print("Not correct size")
            return False
        self.sizeHash = size
        self._set_system_hash()

    def changeTypeHash(self, typeHash):
        _validate_type(typeHash, str, "typeHash")

        self.typeHash = typeHash
        self._set_system_hash()

    def generate_report(self, report_file="data_integrity_report.txt"):
        with open(report_file, "w") as report:
            report.write("Data Integrity Report\n\n")
            for file_path, hash_info in self._data.items():
                report.write(f"File: {file_path}\n")
                report.write(f"Hash type: {self.typeHash.value}\n")
                report.write(f"Type encrypt: {self.typeEncrypt.value}\n")
                report.write(f"Hash Encrypted: {hash_info['encrypted_hash']}\n")
                report.write(f"Size hash = {512 if len(hash_info) == 128 else 256}\n")
                report.write(f"Hash Value: ")

                if os.path.exists(file_path):
                    with open(file_path, "rb") as file:
                        data = file.read()
                        newHash = self._get_hash(data,self._systemHash)
                        decrypted_hash = self._getDecryptHash(file_path)
                        report.write(f"{decrypted_hash} \n")
                        report.write(f"New hash {newHash}\n")
                        report.write("Status: ")
                        if newHash == decrypted_hash:
                            report.write("Integrity verified\n")
                        else:
                            report.write("Integrity check failed\n")
                else:
                    report.write("File not found\n")
                report.write("\n")
        print(f"Report generated: {report_file}")


    def _get_hash(self, data, hash_function):
        if self.typeHash != Hashs.STRIBOG:
            hash_function = hash_function.new(data)
        else:
            hash_function.clear()
            hash_function.update(data)

        return hash_function.hexdigest()

    def _recordEncryptHash(self,hash_value,file_path):
        encryptHash, nonce, tag, key = self._encryptMethod.encrypt_hash(hash_value)

        self._data[file_path] = {
            'encrypted_hash': encryptHash,
            'nonce': nonce,
            'tag': tag,
            'key': b64encode(key).decode('utf-8')
        }

    def _getDecryptHash(self,file_path):
        return self._encryptMethod.decrypt_hash(self._data[file_path]['encrypted_hash'],
                           self._data[file_path]['nonce'],
                           self._data[file_path]['tag'],
                           b64decode(self._data[file_path]['key']))

    def _set_system_hash(self):
        if self.typeHash == Hashs.STRIBOG:
            self._systemHash = _pystribog.StribogHash(self.sizeHash)
        elif self.typeHash == Hashs.SHA:
            self._systemHash = SHA256 if self.sizeHash == 256 else SHA512

    def _set_system_encrypt(self,key):
        if self.typeEncrypt == EncryptMethods.AES:
            self._encryptMethod = EncryptAES(key)
        elif self.typeEncrypt == EncryptMethods.DES:
            self._encryptMethod = EncryptDES(8)


    def _setup_logging(self):
        logging.basicConfig(filename='data_integrity.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')