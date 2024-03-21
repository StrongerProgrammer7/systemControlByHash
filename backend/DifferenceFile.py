

class SearchDifferenceFile():

    def getDifferenceFile(self, file_path,file_from_db):
        original_lines = self._read_file_lines(file_from_db)
        current_lines = self._read_file_lines(file_path)
        differences = self._compare_lines(original_lines, current_lines)
        print(differences)
        return differences


    def _read_file_lines(self, file_path):
        with open(file_path, "r") as file:
            return file.readlines()

    def _compare_lines(self, original_lines, current_lines):
        differences = []
        for i, (original_line, current_line) in enumerate(zip(original_lines, current_lines), start=1):
            differences.extend(self._compare_words_in_lines(original_line, current_line, i))
        return differences

    def _compare_words_in_lines(self, original_line, current_line, line_number):
        differences = []
        original_words = original_line.split()
        current_words = current_line.split()
        column_line = 0
        for j, (original_word, current_word) in enumerate(zip(original_words, current_words), start=1):
            if original_word != current_word:
                message, column_line = self._create_difference_message(original_word, current_word, line_number, j,
                                                                       column_line)
                differences.append(message)
            else:
                column_line += len(current_word) + 1
        return differences

    def _create_difference_message(self, original_word, current_word, line_number, word_number, column_line):
        if len(original_word) > len(current_word):
            return f"Difference found at Line {line_number}, column {column_line}, Word {word_number}: 'len1{len(original_word)}' > 'len2{len(current_word)}' word: '{original_word}' vs '{current_word}'", column_line + len(
                current_word) + 1
        elif len(original_word) < len(current_word):
            return f"Difference found at Line {line_number}, column {column_line}, Word {word_number}: 'len1{len(original_word)}' < 'len2{len(current_word)}' word: '{original_word}' vs '{current_word}'", column_line + len(
                current_word) + 1
        else:
            for k, (original_char, current_char) in enumerate(zip(original_word, current_word), start=1):
                column_line += 1
                if original_char != current_char:
                    return f"Difference found at Line {line_number}, column {column_line}, Word {word_number}, num symbol {k} : '{original_char}' vs '{current_char}' word: '{original_word}' vs '{current_word}'", column_line + min(
                        len(original_word), len(current_word)) - k + word_number - 1
            return ""  # Возвращаем пустую строку, если слова одинаковы
