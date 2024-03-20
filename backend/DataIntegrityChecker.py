from Crypto.Hash import SHA512
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode,b64encode
import os
import logging

import _pystribog
from backend.utils import size512Or256, _validate_type
from backend.enumHash import Hash

class DataIntegrityChecker:

    def __init__(self, sizeHash=512, typeHash=Hash.STRIBOG,keyEncrypt=16):
        _validate_type(sizeHash, int, "sizeHash")
        _validate_type(keyEncrypt, int, "keyEncrypt")
        _validate_type(typeHash, Hash, "typeHash")

        if not size512Or256(sizeHash):
            raise ValueError("Size hash must be 512 or 256")

        self._data = {}
        self.typeHash = typeHash
        self.sizeHash = sizeHash
        self.keyEncrypt = keyEncrypt
        self._set_system_hash()
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
                report.write(f"Hash type: {self.typeHash}\n")
                report.write("Type encrypt: AES\n")
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
        if self.typeHash != Hash.STRIBOG:
            hash_function = hash_function.new(data)
        else:
            hash_function.clear()
            hash_function.update(data)

        return hash_function.hexdigest()

    def _recordEncryptHash(self,hash_value,file_path):
        key = get_random_bytes(self.keyEncrypt)

        encryptHash, nonce, tag = self._encrypt_hash(hash_value, key)

        self._data[file_path] = {
            'encrypted_hash': encryptHash,
            'nonce': nonce,
            'tag': tag,
            'key': b64encode(key).decode('utf-8')
        }
    def _getDecryptHash(self,file_path):
        return self._decrypt_hash(self._data[file_path]['encrypted_hash'],
                           self._data[file_path]['nonce'],
                           self._data[file_path]['tag'],
                           b64decode(self._data[file_path]['key']))

    def _set_system_hash(self):
        if self.typeHash == Hash.STRIBOG:
            self._systemHash = _pystribog.StribogHash(self.sizeHash)
        elif self.typeHash == Hash.SHA:
            self._systemHash = SHA256 if self.sizeHash == 256 else SHA512

    def _encrypt_hash(self, hash_value, key):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(hash_value.encode())
        return b64encode(ciphertext).decode('utf-8'), b64encode(cipher.nonce).decode('utf-8'), b64encode(tag).decode(
            'utf-8')

    def _decrypt_hash(self, encrypted_hash, nonce, tag, key):
        cipher = AES.new(key, AES.MODE_GCM, b64decode(nonce))
        plaintext = cipher.decrypt_and_verify(b64decode(encrypted_hash), b64decode(tag))
        return plaintext.decode('utf-8')

    def _setup_logging(self):
        logging.basicConfig(filename='data_integrity.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')