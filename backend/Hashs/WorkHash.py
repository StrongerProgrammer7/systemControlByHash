import os

from backend.Hashs.SHA import SHA, EncryptMethods
from backend.Hashs.Stribog import Stribog
from backend.Hashs.SHAKE import SHAKE
from backend.enums.enumHash import Hashs
from backend.utils import _validate_type, size512Or256


class WorkHash():
    def __init__(self, sizeHash, typeHash, encryptMethod=None):
        _validate_type(sizeHash, int, "sizeHash")
        _validate_type(typeHash, str, "typeHash")
        if encryptMethod is not None:
            _validate_type(encryptMethod, str, "encryptMethod")

        if not size512Or256(sizeHash):
            raise ValueError("Size hash must be 512 or 256")

        self._set_type_hash(typeHash)
        self.sizeHash = sizeHash
        self._set_type_encrypt(encryptMethod)
        self._set_system_hash(encryptMethod)

    def hashing_file(self, file_path):
        self.methodHash.hashingFile(file_path)

    def check_file(self, file_path):
        self.methodHash.check_integrity(file_path)

    def delete_hash_file(self, file_path):
        self.methodHash.deleteHashByPath(file_path)

    def generate_report(self, report_file="data_integrity_report.txt"):
        with open(report_file, "w") as report:
            report.write("Data Integrity Report\n\n")
            self._generateReportFromDatabase(report)

    def changeTypeHash(self, typeHash):
        _validate_type(typeHash, str, "typeHash")
        self._set_type_hash(typeHash)
        self._set_system_hash(self.methodHash.typeEncrypt)

    def changeSizeHash(self, sizeHash):
        _validate_type(sizeHash, int, "sizeHash")
        if sizeHash != 256 or sizeHash != 512:
            print("Error: only 256 or 512")
            return False
        self.sizeHash = sizeHash
        self._set_system_hash(self.methodHash.typeEncrypt)

    def get_data_by_file_path(self,file_path):
        record = self.methodHash.get_data_by_file_path(file_path)
        data = [record[1],record[2],record[3],record[4],record[5],record[8]]
        return data

    def set_encrypt_method(self,encryptMethod):
        self.methodHash.usingEncrypt(encryptMethod)

    def _set_system_hash(self, encryptMethod):
        if self.typeHash == Hashs.STRIBOG:
            self.methodHash = Stribog(self.sizeHash, encryptMethod)
        elif self.typeHash == Hashs.SHA:
            self.methodHash = SHA(self.sizeHash, encryptMethod)
        elif self.typeHash == Hashs.SHAKE128:
            self.methodHash = SHAKE(self.sizeHash, encryptMethod)

    def _set_type_hash(self, typeHash: str) -> None:
        if typeHash == Hashs.STRIBOG.value:
            self.typeHash = Hashs.STRIBOG
        elif typeHash == Hashs.SHA.value:
            self.typeHash = Hashs.SHA
        elif typeHash == Hashs.SHAKE128.value:
            self.typeHash = Hashs.SHAKE128
        else:
            print("type hash not exists!")

    def _set_type_encrypt(self, encryptType: str) -> None:
        if encryptType == EncryptMethods.AES.value:
            self.encryptMethod = EncryptMethods.DES
        elif encryptType == EncryptMethods.DES.value:
            self.encryptMethod = EncryptMethods.AES

    def _generateReportFromDatabase(self, report):
        record = self.methodHash.get_data_all()
        tempTypeHash = self.typeHash
        for elem in record:
            report.write(f"File: {elem[1]}\n")
            report.write(f"Hash type: {elem[4]}\n")
            if elem[5] is not None:
                report.write(f"Type encrypt: {elem[5]}\n")
                report.write(f"Hash Encrypted: {elem[3]}\n")
            report.write(f"Size hash = {512 if len(elem[2]) == 128 else 256}\n")
            report.write(f"Hash Value: ")
            file_path = elem[1]
            if os.path.exists(file_path):
                with open(file_path, "rb") as file:
                    data = file.read()
                    # absolute_path, hash_value, encrypted_hash, type_hash, type_encrypted, extra_info_encryption,
                    #hash_key_encrypted, body_file
                    hash = self.methodHash.get_hash(data)
                    prev_hash = elem[2]
                    report.write(f"{prev_hash} \n")
                    report.write(f"New hash {hash}\n")
                    report.write("Status: ")
                    if prev_hash == hash:
                        report.write("Integrity verified\n")
                    else:
                        report.write("Integrity check failed\n")
            else:
                report.write("File not found\n")
            report.write("\n")

        self.changeTypeHash(tempTypeHash.value)
