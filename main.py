
from backend.SHA import SHA
from backend.Stribog import Stribog,EncryptMethods
from backend.utils import add_text_to_file

def workHash(hash):
    hash.hashingFile("test_files/example2.txt")
    # hash.changeHashSize(256)
    hash.hashingFile("test_files/example.txt")

    add_text_to_file("test_files/example2.txt", "This is some additional text.\n")
    hash.check_integrity("test_files/example.txt")
    # hash.changeHashSize(512)
    hash.check_integrity("test_files/example2.txt")


def generateReport(hash):
    hash.generate_report()

if __name__ == '__main__':
    checker = Stribog(256,encryptMethod=EncryptMethods.DES)
    workHash(checker)
    #generateReport(checker)
