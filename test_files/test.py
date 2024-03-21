from backend.utils import clear_and_write
from backend.Hashs.WorkHash import WorkHash

#STRIBOG
def test1():
    checker = WorkHash(256, "STRIBOG")
    checker.hashing_file("test_files/example2.txt")
    checker.check_file("test_files/example2.txt")

#SHA + DES
def test2():
    checker = WorkHash(256,"SHA",encryptMethod="DES")
    checker.hashing_file("test_files/example.txt")
    checker.check_file("test_files/example.txt")

#SHA
def test3():
    checker = WorkHash(256, "SHA", encryptMethod="DES")
    checker.hashing_file("test_files/example2.txt")

    input("Измени файл example2: ")

    clear_and_write("test_files/example2.txt", "test_files/ex3.txt")

    checker.check_file("test_files/example2.txt")

# SHAKE128
def test4():
    checker = WorkHash(256, "SHAKE128", encryptMethod="DES")
    checker.hashing_file("test_files/example2.txt")
    print(checker.get_data_by_file_path("test_files/example2.txt"))
    checker.check_file("test_files/example2.txt")

# generate report
def test5():
    checker = WorkHash(256, "STRIBOG",)
    checker.hashing_file("test_files/example2.txt")
    checker.changeTypeHash("SHA")
    checker.hashing_file("test_files/example.txt")
    checker.generate_report()


if __name__ == '__main__':
    test1()
    test2()
    test3()
    test4()
    test5()



