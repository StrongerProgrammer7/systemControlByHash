import sqlite3
import db_system
class CRUD:
    def __init__(self, db_name='mydatabase.db'):
        self._db = db_system.MyDatabase()
        self._db.create_table()
        self.cursor = self._db.cursor

    def insert_record(self, absolute_path, hash_value, encrypted_hash=None, type_hash=None, type_encrypted=None,
                      extra_info_encryption=None, hash_key_encrypted=None, body_file=None):
        existing_record = self.get_record_by_absolute_path(absolute_path)
        if existing_record:
            self.update_record_by_absolute_path(absolute_path, hash=hash_value, encrypted_hash=encrypted_hash,
                                                type_hash=type_hash, type_encrypted=type_encrypted,
                                                extra_info_encryption=extra_info_encryption,
                                                hash_key_encrypted=hash_key_encrypted, body_file=body_file)
            return False  # Запись уже существовала и была обновлена
        else:
            try:
                self.cursor.execute('''
                    INSERT INTO mytable (absolute_path, hash, encrypted_hash, type_hash, type_encrypted, extra_info_encryption, hash_key_encrypted, body_file) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (absolute_path, hash_value, encrypted_hash, type_hash, type_encrypted, extra_info_encryption,
                      hash_key_encrypted, body_file))
                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                print("Record with absolute path '{}' already exists.".format(absolute_path))
                return False

    def get_record_by_absolute_path(self, absolute_path):
        self.cursor.execute('''
            SELECT * FROM mytable WHERE absolute_path = ?
        ''', (absolute_path,))
        record = self.cursor.fetchone()

        # Разбиваем поле extra_info_encryption на части, если оно есть
        if record and record[6]:
            record_extra_info_encryption = record[6].split(',')
            record = list(record)
            record[6] = record_extra_info_encryption
            record = tuple(record)

        return record

    def update_record_by_absolute_path(self, absolute_path, **kwargs):
        update_query = "UPDATE mytable SET "
        update_query += ", ".join([f"{key} = ?" for key in kwargs.keys()])
        update_query += " WHERE absolute_path = ?"

        values = list(kwargs.values())
        values.append(absolute_path)

        self.cursor.execute(update_query, tuple(values))
        db_system.MyDatabase.conn.commit()

    def delete_record_by_absolute_path(self, absolute_path):
        self.cursor.execute('''
            DELETE FROM mytable WHERE absolute_path = ?
        ''', (absolute_path,))
        db_system.MyDatabase.conn.commit()



if __name__ == "__main__":
    db = CRUD()
    with open("../../test_files/ex3.txt", "rb") as file:
        data = file.read()
        # Пример использования операций CRUD
        db.insert_record('example_path', 'example_hash', encrypted_hash='example_encrypted_hash', type_hash='example_type_hash',extra_info_encryption = "aaa,aasd,assad",body_file=data,type_encrypted="DES",hash_key_encrypted="0xkey")
        record = db.get_record_by_absolute_path('example_path')
        print("Retrieved Record:", record[0])
        db.update_record_by_absolute_path('example_path', hash='updated_hash')
        record = db.get_record_by_absolute_path('example_path')
        print("Updated Record:", record)
        db.delete_record_by_absolute_path('example_path')
