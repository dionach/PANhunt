import re


class PAN:
    """PAN: A class for recording PANs, their brand and where they were found"""

    pan: str
    path: str
    sub_path: str
    brand: str

    def __init__(self, path: str, sub_path: str, brand: str, pan: str) -> None:

        self.path, self.sub_path, self.brand, self.pan = path, sub_path, brand, pan

    def get_masked_pan(self) -> str:
        """The first six and last four digits are the maximum number of digits that may be displayed"""
        pan_out: str = self.pan[0:6] + \
            re.sub(r'\d', '*', self.pan[6:-4]) + self.pan[-4:]
        return f'{self.sub_path} {self.brand}:{pan_out}'

    @staticmethod
    def is_excluded(pan: str, excluded_pans: list[str]) -> bool:
        for excluded_pan in excluded_pans:
            if pan == excluded_pan:
                return True
        return False

    @staticmethod
    def is_valid_luhn_checksum(pan: str) -> bool:
        """ from wikipedia: https://en.wikipedia.org/wiki/Luhn_algorithm"""

        safe_pan: str = re.sub(r'[^\d]', '', pan)

        def digits_of(n) -> list[int]:
            return [int(d) for d in str(n)]

        digits: list[int] = digits_of(safe_pan)
        odd_digits: list[int] = digits[-1::-2]
        even_digits: list[int] = digits[-2::-2]
        checksum: int = 0
        checksum += sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))

        return checksum % 10 == 0
