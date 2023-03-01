

from __future__ import unicode_literals
import string
import copy

# ??? what is the difference  between utf-8 and utf-8 bom ???
# utf-8          # + ...utf8.txt       encoding='utf8'
# utf-8     bom  # + ...utf8bom.txt    encoding='utf8'

# ??? what is the difference between utf-16 le bom and utf-16 be bom ???
# utf-16 be bom  # + ...utf16lebom.txt encoding='utf16'
# utf-16 le bom  # + ...utf16bebom.txt encoding='utf16'

class xParser:

    # константы парсера для приведения кода к стандартному
    # виду и поиска уязвимостей ==========================================

    parserPoints = ['#', '\t', '\n', ' ', '', '"""']
    # ==============================================
    # контексты уязвимостей ========================
    substrings_0 = ['email', '=', '@']
    substrings_1 = ['password', '=']
    substrings_2 = ['open(']
    substrings_3 = ['open (']
    substrings_4 = ['read']
    substrings_5 = ['eval']
    substrings_6 = ['pickle',
                    'pickle.load']
    substrings_7 = [ 'django.middleware.security.SecurityMiddleware',
                     'django.contrib.sessions.middleware.SessionMiddleware',
                     'django.middleware.common.CommonMiddleware',
                     'django.middleware.csrf.CsrfViewMiddleware',
                     'django.contrib.auth.middleware.AuthenticationMiddleware',
                     'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
                     'django.contrib.messages.middleware.MessageMiddleware',
                     'django.middleware.clickjacking.XFrameOptionsMiddleware',
                     'django.middleware.locale.LocaleMiddleware']
    substrings_8 = ['query',
                    'SELECT',
                    'from',
                    'where']

    DescriptionsDict = dict()   # словарь для определений опасного кода
    BodiesDict = dict()         # словарь для сбора всего опасного кода
    # размеры этих словарей могут НЕ совпадать.
    # Может быть безопасный код, который не соответствует ни одному
    # определению опасного кода
    DangerousContextDict = dict()  # словарь для фрагментов, которые делают
                                   # код уязвимым
    # ====================================================================

    # создать объект - открыть файлы
    # (возможно, с предварительной перекодировкой под utf)
    def __init__(self, fnameIn, fnameOut, fnameFinal):

        self.fileIn = None
        self.fileOut = None
        self.fileFinal = None

        # варианты операторов открытия файлов ============================
        ##text = open(fnameIn, 'r', encoding='utf16').read()

        # with open(fnameIn, 'r', encoding='utf16') as file:
        #     text = file.read()
        # ================================================================

        self.fileFinal = open(fnameFinal, 'w', encoding='utf16')
        self.fileOut = open(fnameOut, 'w', encoding='utf16')
        self.fileIn = open(fnameIn, 'r', encoding='utf16')

    # поиск и удаление закоммеченных фрагментов текста. =================================
    # Задаются константой xParser.parserPoints[0] и удаляются, т.к. не содержат полезной
    # информации и в дальнейшем не понадобятся. =========================================
    def parser_0(self):

        retStrings = []
        workList = []   # Это список. Из него надо лепить строку после его заполнения .

        # чтение из открытого исходника
        for line in self.fileIn:
            # print(line.strip())

            workList.clear()

            for symbol in line:
                if symbol == xParser.parserPoints[0]:
                    # коммент найден - переход к следующей строке
                    break
                elif symbol == xParser.parserPoints[1]:
                    pass
                elif symbol == xParser.parserPoints[2]:
                    pass
                else:
                    workList.append(symbol)

            workList.append(xParser.parserPoints[2])  # строка прочитана, список слов
                                                      # сформирован, на конец списка
                                                      # вешается "конец_строки".

            workStr = ''.join(workList)  # из списка формируется строка с '' (пустым)
            retStrings.append(workStr)   # разделителем и она добавляется в retStrings

        retStrings = self.parser_01(retStrings)

        # Это всего лишь запись в отладочный файл, чтобы было видно, как отработал
        # препроцессор.
        for s in retStrings:
            self.fileOut.write(s)


        bodyDiction = self.parser_02(retStrings)

        self.threatDetector(bodyDiction)

        print(f'=====BodiesDict===========================================')

        nb = 0
        for keyBody in xParser.BodiesDict:
            print(f'{nb} -> {keyBody}: {xParser.BodiesDict[keyBody]}')
            nb += 1

        print(f'=====DangerousContextDict=================================')

        nb = 0
        for keyBody in xParser.DangerousContextDict:
            print(f'{nb} -> {keyBody}: {xParser.DangerousContextDict[keyBody]}')
            nb += 1

        print(f'=====DescriptionsDict=================================')

        nb = 0
        for keyBody in xParser.DescriptionsDict:

            print(f'{nb} -> {keyBody}: ')
            for txt in xParser.DescriptionsDict[keyBody]:
                txt = txt.rstrip('\n')
                print(txt)
            nb += 1
       # =================================================================

        for keyBody in xParser.BodiesDict:
            for txt in xParser.BodiesDict[keyBody]:
                txt = txt.rstrip('\n')
                self.fileFinal.write(f'{txt}\n')
            self.fileFinal.write(f'\n')

            self.fileFinal.write(f'\t{xParser.DangerousContextDict[keyBody]}\n')
            self.fileFinal.write(f'\n')

            for txt in xParser.DescriptionsDict[keyBody]:
                txt = txt.rstrip('\n')
                self.fileFinal.write(f'\t\t{txt}\n')
            self.fileFinal.write(f'\n')

            # ===================================================================================
    # выкинуть \n , если он стоит ПЕРВЫМ в строке, за исключением пробелов.
    # то есть строка, состоящая из n (n >= 0) пробелов полностью удаляется ==============
    def parser_01(self, workStrings):

        retStrings = []

        for str in workStrings:
            workList = list(str)
            lwn = len(workList)

            for n in range(0, lwn):
                if workList[n] == xParser.parserPoints[3] or workList[n] == xParser.parserPoints[2]:
                    workList[n] = xParser.parserPoints[4]
                else:
                    retStrings.append(''.join(workList))
                    break

        return retStrings

# =======================================================================================

    def parser_02(self, workStrings):

        doBody = False
        fullBodyes= []    # общий список для сохранения всех примеров

        exampleBody = []
        exampleNumber = -1
        bodyDiction = dict()

        descriptionBuffer = []
        descriptionNumber = 0

        theFirst = True

        for str in workStrings:

            if xParser.parserPoints[5] in str and theFirst == True:

                if doBody == True:
                    ###print(f'<<- {exampleBody} ->>')     # !!!!!
                    fullBodyes.append(exampleBody.copy())

                    bodyDiction[exampleNumber] = exampleBody.copy()
                    ###print(bodyDiction)

                xxxIndex = str.find(xParser.parserPoints[5])
                ###print(f'\nthe First {xParser.parserPoints[5]} in {descriptionNumber}')
                doBody = False
                theFirst = False

                exampleBody.clear()

            elif xParser.parserPoints[5] in str and theFirst == False:
                ###print(descriptionBuffer)


                xxxIndex = str.find(xParser.parserPoints[5])
                ###print(f'the Last {xParser.parserPoints[5]} in {descriptionNumber}')
                doBody = True

                theFirst = True

                # сформированное описание возможной уязвимости из локального списка
                # переносится в общий глобальный словарь.
                # Ключом элемента в словаре является номер его описания.
                xParser.DescriptionsDict[descriptionNumber] = descriptionBuffer.copy()


                # локальный список (множество предложений, описыващих угрозу) очищается.
                # Номер описания угрозы увеличивается на 1.
                descriptionBuffer.clear()
                descriptionNumber += 1

                exampleBody.clear()
                exampleNumber += 1

            else:
                if theFirst == False:
                    descriptionBuffer.append(str)
                elif doBody == True:
                    #print(f'{exampleNumber}...{str}')
                    exampleBody.append(str)

        #print(f'<<= {exampleBody} =>>')     # !!!!!
        fullBodyes.append(exampleBody.copy())

        bodyDiction[exampleNumber] = exampleBody.copy()
        ###print(bodyDiction)

        print(f'==============================================')

        return bodyDiction

    # детектор уязвимостей ==============================================================
    def threatDetector(self, bodyDiction):
        f0 = -1
        f1 = -1
        f2 = -1
        f3 = -1

        oldBody = None

        # MIDDLEWARE_CLASSES_counter_plus
        mdwCounterPlus = -1
        # MIDDLEWARE_CLASSES_counter_minus
        mdwCounterMinus = -1

        for n in range(0, len(bodyDiction)):
            body = bodyDiction[n]
        #  body - это единица компиляции. Она разбирается на фрагменты.
        #  На фрагментах определяется уязвимость кода.
        #  Замена целочисленного значения ключа на строку означает
        #  "предположительно" безопасный код. В случае определения
        #  его уязвимости производится обратное преобразование.
        #  Таким образом, ключ опасного кода является числом,
        #                 ключ безопасного кода является строкой.
            del(bodyDiction[n])
            bodyDiction[str(n)] = body

    # ==== этот код позволяет определить некоторые уязвимости в коде django проекта =====
    # ==== по соотношению значений переменных mdwCounterPlus и mdwCounterMinus ==========
            if mdwCounterPlus > -1 and mdwCounterPlus < mdwCounterMinus:
                m = n-1
                print(f'{m} >>> {oldBody} was dangerous code\n')

                # обратное преобразование ключа
                del (bodyDiction[str(m)])
                bodyDiction[int(m)] = oldBody.copy()

                xParser.BodiesDict[m] = oldBody.copy()
                # здесь нет формального признака уязвимости.
                # Признаком уязвимости является соотношение значений переменных
                # mdwCounterPlus и mdwCounterPlus
                xParser.DangerousContextDict[m] = f'variables mdwCounterPlus, mdwCounterMinus:' \
                                                  f' mdwCounterPlus > -1 and ' \
                                                  f'mdwCounterPlus < mdwCounterPlus'

            mdwCounterPlus = -1
            mdwCounterMinus = -1

            oldBody = body

    # ===================================================================================

            # Разбор единицы компиляции на фрагменты.
            for b in body:

                mdwCounterMinus = -1

                # ========================================================
                # substrings_0 = ['email',
                #                 '=',
                #                 '@']
                
                f0 = b.find(xParser.substrings_0[0])
                f1 = b.find(xParser.substrings_0[1])
                f2 = b.find(xParser.substrings_0[2])
                if f0 >= 0 and f1 > f0 and f2 > f1:
                    print(f'{n} >>> {b} : {xParser.substrings_0[0]}, '
                          f'{xParser.substrings_0[1]}, '
                          f'{xParser.substrings_0[2]} is dangerous code\n')

                    # обратное преобразование ключа
                    del(bodyDiction[str(n)])
                    bodyDiction[n] = body

                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_0[0]}, ' \
                                                      f'{xParser.substrings_0[1]}, ' \
                                                      f'{xParser.substrings_0[2]}'

                    break   # !!!!!


                # ========================================================
                # substrings_1 = ['password',
                #                 '=' ]

                f0 = b.find(xParser.substrings_1[0])
                f1 = b.find(xParser.substrings_1[1])
                if f0 >= 0 and f1 > f0:
                    print(f'{n} >>> {b} : {xParser.substrings_1[0]}, '
                          f'{xParser.substrings_1[1]} is dangerous code\n')

                    # обратное преобразование ключа
                    del (bodyDiction[str(n)])
                    bodyDiction[n] = body

                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_1[0]}, ' \
                                                      f'{xParser.substrings_1[1]}'

                    break   # !!!!!

                # ========================================================
                # substrings_2 = ['open(']

                f0 = b.find(xParser.substrings_2[0])
                if f0 >= 0:
                    print(f'{n} >>> {b} : {xParser.substrings_2[0]} is dangerous code\n')
                    del (bodyDiction[str(n)])
                    bodyDiction[n] = body

                    # обратное преобразование ключа
                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_2[0]}'

                    break   # !!!!!

                # ========================================================
                # substrings_3 = ['open (']
                # в этом пробеле ______^
                # разница между substrings_2 и substrings_3

                f0 = b.find(xParser.substrings_3[0])
                if f0 >= 0:
                    print(f'{n} >>> {b} : {xParser.substrings_3[0]} is dangerous code\n')
                    del (bodyDiction[str(n)])
                    bodyDiction[n] = body

                    # обратное преобразование ключа
                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_3[0]}'

                    break  # !!!!!

                # ========================================================
                # substrings_4 = ['read']

                f0 = b.find(xParser.substrings_4[0])
                if f0 >= 0:
                    print(f'{n} >>> {b} : {xParser.substrings_4[0]} is dangerous code\n')
                    del (bodyDiction[str(n)])
                    bodyDiction[n] = body

                    # обратное преобразование ключа
                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_4[0]}'

                    break  # !!!!!

                # ========================================================
                # substrings_5 = ['eval']

                f0 = b.find(xParser.substrings_5[0])
                if f0 >= 0:
                    print(f'{n} >>> {b} : {xParser.substrings_5[0]} is dangerous code\n')
                    del (bodyDiction[str(n)])
                    bodyDiction[n] = body

                    # обратное преобразование ключа
                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_5[0]}'

                    break  # !!!!!

                # ========================================================
                # substrings_6 = ['pickle', 'pickle.load']

                f0 = b.find(xParser.substrings_6[0])
                if f0 == -1:
                    f0 = b.find(xParser.substrings_6[1])
                if f0 >= 0:
                    print(f'{n} >>> {b} : {xParser.substrings_6[0]} '
                          f'or {xParser.substrings_6[1]} is dangerous code\n')

                    # обратное преобразование ключа
                    del (bodyDiction[str(n)])
                    bodyDiction[n] = body

                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_6[0]} or ' \
                                                      f'{xParser.substrings_6[1]}'

                    break  # !!!!!

                # ========================================================
                # В django проекте список MIDDLEWARE_CLASSES должен
                # содержать ВСЕ первоначально заданные элементы (9 штук).
                # Удаления и комментирования элементов из этого списка делает
                # код небезопасным. =====================================================
                #  ======== поиски потенциальной уязвимости в коде jango проекта ========
                # substrings_7 = [ 'django.middleware.security.SecurityMiddleware',
                #                  'django.contrib.sessions.middleware.SessionMiddleware',
                #                  'django.middleware.common.CommonMiddleware',
                #                  'django.middleware.csrf.CsrfViewMiddleware',
                #                  'django.contrib.auth.middleware.AuthenticationMiddleware',
                #                  'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
                #                  'django.contrib.messages.middleware.MessageMiddleware',
                #                  'django.middleware.clickjacking.XFrameOptionsMiddleware',
                #                  'django.middleware.locale.LocaleMiddleware']

                # Попытка поиска уязвимости в django ====================================

                xIndex = 0
                for xIndex in range(0, 9):
                    f0 = b.find(xParser.substrings_7[xIndex])
                    if f0 == -1:
                        mdwCounterMinus += 1
                    else:
                        break

                # print(f'~~~~~{mdwCounterPlus} === {mdwCounterMinus}~~~~~')

                if f0 >= 0:
                    # print(f'Ok, {b} :  {xParser.substrings_7[xIndex]}')
                    mdwCounterPlus += 1
                    mdwCounterMinus = -1
                    continue
                elif f0 == -1:
                    # print(f'--- {b} --- {mdwCounterMinus} ---')
                    if mdwCounterPlus > -1 and mdwCounterPlus < 8:
                        mdwCounterMinus += 1

                # ========================================================
                # substrings_8 = ['query'
                #                 'SELECT',
                #                 'from',
                #                 'where']

                f0 = b.find(xParser.substrings_8[0])
                f1 = b.find(xParser.substrings_8[1])
                f2 = b.find(xParser.substrings_8[2])
                f3 = b.find(xParser.substrings_8[3])
                if f0 >= 0 and f1 > f0 and f2 > f1 and f3 > f2:
                    print(f'{n} >>> {b} : {xParser.substrings_8[0]},'
                          f'{xParser.substrings_8[1]},'
                          f'{xParser.substrings_8[2]},'
                          f'{xParser.substrings_8[3]} is dangerous code\n')

                    # обратное преобразование ключа
                    del (bodyDiction[str(n)])
                    bodyDiction[n] = body

                    xParser.BodiesDict[n] = body.copy()
                    xParser.DangerousContextDict[n] = f'{xParser.substrings_8[0]}, ' \
                                                      f'{xParser.substrings_8[1]}, ' \
                                                      f'{xParser.substrings_8[2]}, ' \
                                                      f'{xParser.substrings_8[3]}'

                    break   # !!!!!