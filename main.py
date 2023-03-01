
# Урок 12 (обязательное)
# 0. Познакомится с описанием систем
# https://docs.google.com/document/d/1I1Q2Mqg7PsYrkMNOdogLBoGKeyoq34-dfJQrUtbBOEM/edit?usp=sharing - github api
# https://docs.google.com/document/d/1jpVzAey3YjtcPI_ujMkVRvC-JKxJAo8bsHyixpfqRnE/edit?usp=sharing - hh api
# 1. Выбрать одну из 2-х система какая более интересна, скорее всего с hh будет проще.
#    В hh больше аналитики, в github больше работы с текстом;
# 2. Реализовать систему. Результатом будет код парсера + файл или несколько файлов
#    с полученными данными;
# 3. Сдать проект в виде ссылки на репозиторий + приложить итоговые файлы".
#

from xparser import *

def DoIt():

    # вызов парсера с файлами на вход и на выход ========================================

    # исходный файл с кодировкой utf8. encode = utf8
    # p = xParser("C:\\PythonDrom\\Texts_2022\\~~~\\origin_utf8.txt", "C:\\PythonDrom\\Texts_2022\\~~~\\result.txt")

    # исходный файл с кодировкой utf8bom. encode = utf8
    # p = xParser("C:\\PythonDrom\\Texts_2022\\~~~\\origin_utf18bom.txt", "C:\\PythonDrom\\Texts_2022\\~~~\\result.txt")

    # исходный файл с кодировкой utf16lebom. encode = utf16
    #p = xParser("C:\\PythonDrom\\Texts_2022\\~~~\\origin_utf16lebom.txt", "C:\\PythonDrom\\Texts_2022\\~~~\\result.txt")


    # исходный файл с кодировкой utf16bebom. encode = utf16
    p = xParser("C:\\PythonDrom\\Texts_2022\\~~~\\origin_utf16bebom.txt",
                "C:\\PythonDrom\\Texts_2022\\~~~\\result.txt",
                "C:\\PythonDrom\\Texts_2022\\~~~\\final.txt")

    # ===================================================================================

    p.parser_0()

    p.fileIn.close()
    p.fileOut.close()
    p.fileFinal.close()

# =======================================================================================

def main():
    DoIt()

if __name__ == '__main__':
    main()
