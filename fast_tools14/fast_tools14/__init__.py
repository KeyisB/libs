
from itertools import product


b = [k for k in enumerate([x for x in product('АВИКЛ', repeat=6)], 1)]
print(b[:50])

for n, i in b:
    if i.count('А') <= 2 and i.count('В') == 2 and 'И' not in i:
        print(f'{n}: {i}')
        break



def game(first,second,move):
    if first+second>=122: return move%2==0
    if move==0: return 0
    actions = ([
        game(first+2,second, move-1),
        game(first,second+2, move-1),
        game(first*2,second, move-1),
        game(first,second*2, move-1)
                ])
    return any(actions) if (move-1)%2==0 else all(actions) # на any() если в 1 вопросе говорится после неудачного хода Пети
first_ = 3
second_ = 118
print('19)', [second for second in range(first_,second_) if game(first_,second,2)])
print('20)', [second for second in range(first_,second_) if not game(first_,second,1) and game(first_,second,3)])
print('21)', [second for second in range(first_,second_) if not game(first_,second,2) and game(first_,second,4)])




def game(summ, move):
    # условие победы (наш move с каждым вложенным запуском будет уменьшаться и при этом игра должна закончиться 0, 
    # но игра может закончится на ходе того же игрока, когда, поэтому)
    if summ >= 223: return move%2==0
    if move == 0: return 0 # чтобы функция не ушла в глубь
    actions = [game(summ+1, move-1), game(summ+4, move-1), game(summ*3, move-1)] #действия наших игроков
    #выиграшная стратегия должна существовать в одном из ходов завершающего игрока и во всех ходах другого игрока
    return any(actions) if (move-1)%2==0 else all(actions)

print('19)', [summ for summ in range(1,222) if not game(summ,1) and game(summ, 2)])
"""
not game(summ, 1): Петя не может выиграть первым ходом.
game(summ, 2): Ваня выигрывает первым ходом.
"""


print('20)', [summ for summ in range(1,222) if not game(summ,1) and game(summ, 3)])
"""
not game(summ, 1): Петя не может выиграть за один ход.
game(summ, 3): Петя выигрывает на своём втором ходу, т.е.
    после двух ходов (его и Вани) у Пети есть выигрышная
    стратегия независимо от действий Вани.
"""

print('21)', [summ for summ in range(1,222) if game(summ,2) and not game(summ, 1)])
"""
game(summ, 2): У Вани есть выигрышная стратегия, позволяющая ему выиграть вторым ходом.
not game(summ, 1): У Вани нет гарантированной стратегии выигрыша первым ходом.
"""




#print('20)', [summ for summ in range(1,2021) if not game(summ,1) and game(summ, 3)])
#print('21)', [summ for summ in range(1,2021) if not game(summ,2) and game(summ, 4)])
'''
1 ход - это ход победа Пети гарантированна
2 ход - это ход победы Вани гарантированная
3 ход - это ход победа Пети гарантированная
4 ход - это ход победы Вани своим 1 или 2 ходом
'''