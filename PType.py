from datetime import datetime, timedelta
from typing import Literal, Optional, Union

import panutils
from exceptions import PANHuntException
from PTypeEnum import PTypeEnum

_ValueType = Optional[Union[int, float, datetime, bool, str,
                            bytes, list[int], list[float], list[datetime], list[bytes], list[str]]]


class PType:

    ptype: PTypeEnum
    byte_count: int
    is_variable: bool
    is_multi: bool

    def __init__(self, ptype: PTypeEnum, byte_count: int, is_variable: bool, is_multi: bool) -> None:

        self.ptype, self.byte_count, self.is_variable, self.is_multi = ptype, byte_count, is_variable, is_multi

    def value(self, value_bytes: bytes) -> _ValueType:
        """value_bytes is normally a string of bytes, but if multi and variable, bytes is a list of bytes"""

        if self.ptype == PTypeEnum.PtypInteger16:
            return panutils.unpack_integer('h', value_bytes)
        if self.ptype == PTypeEnum.PtypInteger32:
            return panutils.unpack_integer('i', value_bytes)
        if self.ptype == PTypeEnum.PtypFloating32:
            return panutils.unpack_float('f', value_bytes)
        if self.ptype == PTypeEnum.PtypFloating64:
            return panutils.unpack_float('d', value_bytes)
        if self.ptype == PTypeEnum.PtypCurrency:
            raise NotImplementedError('PtypCurrency')
        if self.ptype == PTypeEnum.PtypFloatingTime:
            return self.get_floating_time(value_bytes)
        if self.ptype == PTypeEnum.PtypErrorCode:
            return panutils.unpack_integer('I', value_bytes)
        if self.ptype == PTypeEnum.PtypBoolean:
            return panutils.unpack_integer('B', value_bytes) != 0
        if self.ptype == PTypeEnum.PtypInteger64:
            return panutils.unpack_integer('q', value_bytes)
        if self.ptype == PTypeEnum.PtypString:
            return value_bytes.decode('utf-16-le')  # unicode
        if self.ptype == PTypeEnum.PtypString8:
            if value_bytes[-1:] == b'\x00':
                return value_bytes[:-1]
            else:
                return value_bytes
        if self.ptype == PTypeEnum.PtypTime:
            return self.get_time(value_bytes)
        if self.ptype == PTypeEnum.PtypGuid:
            return value_bytes
        if self.ptype == PTypeEnum.PtypServerId:
            raise NotImplementedError('PtypServerId')
        if self.ptype == PTypeEnum.PtypRestriction:
            raise NotImplementedError('PtypRestriction')
        if self.ptype == PTypeEnum.PtypRuleAction:
            raise NotImplementedError('PtypRuleAction')
        if self.ptype == PTypeEnum.PtypBinary:
            return value_bytes
        if self.ptype == PTypeEnum.PtypMultipleInteger16:
            return self.unpack_list_int(value_bytes, 16)
        if self.ptype == PTypeEnum.PtypMultipleInteger32:
            return self.unpack_list_int(value_bytes, 32)
        if self.ptype == PTypeEnum.PtypMultipleFloating32:
            return self.unpack_list_float(value_bytes, 32)
        if self.ptype == PTypeEnum.PtypMultipleFloating64:
            return self.unpack_list_float(value_bytes, 64)
        if self.ptype == PTypeEnum.PtypMultipleCurrency:
            raise NotImplementedError('PtypMultipleCurrency')
        if self.ptype == PTypeEnum.PtypMultipleFloatingTime:
            count: int = len(value_bytes) // 8
            return [self.get_floating_time(value_bytes[i * 8:(i + 1) * 8]) for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleInteger64:
            self.unpack_list_int(value_bytes=value_bytes, bit_size=64)
        if self.ptype == PTypeEnum.PtypMultipleString:
            return ''.join([item_bytes.to_bytes(2, 'little').decode('utf-16-le') for item_bytes in value_bytes])
        if self.ptype == PTypeEnum.PtypMultipleString8:
            return value_bytes  # list
        if self.ptype == PTypeEnum.PtypMultipleTime:
            count = len(value_bytes) // 8
            return [self.get_time(value_bytes[i * 8:(i + 1) * 8]) for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleGuid:
            count = len(value_bytes) // 16
            return [value_bytes[i * 16:(i + 1) * 16] for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleBinary:
            return value_bytes
        if self.ptype == PTypeEnum.PtypUnspecified:
            return value_bytes
        if self.ptype == PTypeEnum.PtypNull:
            return None
        if self.ptype == PTypeEnum.PtypObject:
            return value_bytes
        raise PANHuntException(f"Invalid PTypeEnum for value {self.ptype}")

    def unpack_list_int(self, value_bytes: bytes, bit_size: Literal[16, 32, 64]) -> list[int]:
        format_dict: dict[int, str] = {16: 'h', 32: 'i', 64: 'q'}
        buffer_size = (bit_size // 8)
        count: int = len(value_bytes) // buffer_size
        return [panutils.unpack_integer(
            format_dict[bit_size], value_bytes[i * buffer_size:(i + 1) * buffer_size]) for i in range(count)]

    def unpack_list_float(self, value_bytes: bytes, bit_size: Literal[32, 64]) -> list[float]:
        format_dict: dict[int, str] = {32: 'f', 64: 'd'}
        buffer_size = (bit_size // 8)
        count: int = len(value_bytes) // buffer_size
        return [panutils.unpack_float(
            format_dict[bit_size], value_bytes[i * buffer_size:(i + 1) * buffer_size]) for i in range(count)]

    def get_floating_time(self, time_bytes: bytes) -> datetime:

        return datetime(year=1899, month=12, day=30) + timedelta(days=panutils.unpack_float('d', time_bytes))

    def get_time(self, time_bytes: bytes) -> datetime:

        return datetime(year=1601, month=1, day=1) + timedelta(microseconds=panutils.unpack_integer('q', time_bytes) / 10.0)

    def get_multi_value_offsets(self, value_bytes: bytes) -> tuple[int, list[int]]:

        ulCount: int = panutils.unpack_integer('I', value_bytes[:4])
        if ulCount == 1:
            # not documented, but seems as if a single length multi only has a 4 byte ULONG with the offset. Boo!
            rgulDataOffsets: list[int] = [8]
        else:
            rgulDataOffsets = [panutils.unpack_integer(
                'Q', value_bytes[4 + i * 8:4 + (i + 1) * 8]) for i in range(ulCount)]
        rgulDataOffsets.append(len(value_bytes))
        return ulCount, rgulDataOffsets
