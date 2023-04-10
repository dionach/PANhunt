import re


class CardPatternSingleton:

    pattern: dict[str, re.Pattern[str]]

    def __init__(self) -> None:
        self.pattern = {'Mastercard': re.compile(r'(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
                        'Visa': re.compile(r'(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
                        'AMEX': re.compile(r'(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)')}
        self.pattern['AMEX'].findall('')

    def __new__(cls) -> 'CardPatternSingleton':
        if not hasattr(cls, 'instance'):
            cls.instance = super(CardPatternSingleton, cls).__new__(cls)
        return cls.instance

    def brands(self):
        return list(self.pattern.items())
