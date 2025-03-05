

from typing import *
from gw_sys_core.gwis import IDConverter


q = IDConverter()


# print(q.convert('', "n"))

# print(q.convert(56765765, "s"))
# print(q.convert(56765765, "s"))




# print('0 -> ' + str(q.convert('0', "n")))
# print('01 -> ' + str(q.convert('01', "n")))
# print('10 -> ' + str(q.convert('10', "n")))
# print('00000 -> ' + str(q.convert('00000', "n")))
print('A0000 -> ' + str(q.convert('A0000', "n")))
print('AAAAA  -> ' + str(q.convert('AAAAA', "n")))

dbase = {
    'usr1': 1,
    'usr2': 8
}

base = {
    1: 123,
    8: 123
}


def login(username_or_id, password, _type: Literal['nickcname', 'strid']):
    # теперь используется только intid


    # пересылаем его серверу аутентификации
    # send {"value": username_or_id, type: _type}

    # Сервер аутентификации
    
    if _type == 'nickcname':
        # получаем id
        username_or_id = dbase['usr1']

    intid = q.convert(username_or_id, "n")

    # проверяем по id
    if intid not in base:
        return False
    if base[intid] == password:
        return f'аутентифицирован как id: {intid}'
    
    return False


# print(login('8', 123, 'strid'))
# print(login('-8', 123, 'strid'))
# print(login('user1', 123, 'nickcname'))

#аутентифицирован как id: 8
#аутентифицирован как id: 8
#аутентифицирован как id: 1