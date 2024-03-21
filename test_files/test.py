from backend.utils import clear_and_write
from backend.Hashs.WorkHash import WorkHash

PATH_EXAMPLE2 = "example2.txt"
PATH_EXAMPLE = "example.txt"
#STRIBOG
def test1():
    checker = WorkHash(256, "STRIBOG")
    checker.hashing_file(PATH_EXAMPLE2)
    checker.check_file(PATH_EXAMPLE2)

#SHA + DES
def test2():
    checker = WorkHash(256,"SHA",encryptMethod="DES")
    checker.hashing_file(PATH_EXAMPLE)
    checker.check_file(PATH_EXAMPLE)

#SHA
def test3():
    checker = WorkHash(256, "SHA", encryptMethod="DES")
    checker.hashing_file(PATH_EXAMPLE2)

    input("Измени файл example2: ")

    clear_and_write(PATH_EXAMPLE2, "test_files/ex3.txt")

    checker.check_file(PATH_EXAMPLE2)

# SHAKE128
def test4():
    checker = WorkHash(256, "SHAKE128", encryptMethod="DES")
    checker.hashing_file(PATH_EXAMPLE2)
    print(checker.get_data_by_file_path(PATH_EXAMPLE2))
    checker.check_file(PATH_EXAMPLE2)

# generate report
def test5():
    checker = WorkHash(256, "STRIBOG",)
    checker.hashing_file(PATH_EXAMPLE2)
    checker.changeTypeHash("SHA")
    checker.hashing_file(PATH_EXAMPLE2)
    checker.generate_report()
def test6():
    checker = WorkHash(256, "STRIBOG", encryptMethod="DES")
    checker.hashing_file(PATH_EXAMPLE2)
    checker.set_encrypt_method(None)
    checker.check_file(PATH_EXAMPLE2)
if __name__ == '__main__':
    test1()
    test2()
    test3()
    test4()
    test5()



