import datetime as dt
import struct
from typing import Any

from msmsg import MSGException
from PTypeEnum import PTypeEnum


class PType:

    def __init__(self, ptype: PTypeEnum, byte_count: int, is_variable: bool, is_multi: bool) -> None:

        self.ptype, self.byte_count, self.is_variable, self.is_multi = ptype, byte_count, is_variable, is_multi

    # TODO: Define each possible return type
    def value(self, value_bytes) -> Any:
        """value_bytes is normally a string of bytes, but if multi and variable, bytes is a list of bytes"""

        if self.ptype == PTypeEnum.PtypInteger16:
            return struct.unpack('h', value_bytes)[0]  # int
        if self.ptype == PTypeEnum.PtypInteger32:
            return struct.unpack('i', value_bytes)[0]  # int
        if self.ptype == PTypeEnum.PtypFloating32:
            return struct.unpack('f', value_bytes)[0]  # float
        if self.ptype == PTypeEnum.PtypFloating64:
            return struct.unpack('d', value_bytes)[0]
        if self.ptype == PTypeEnum.PtypCurrency:
            raise NotImplementedError('PtypCurrency')
        if self.ptype == PTypeEnum.PtypFloatingTime:
            return self.get_floating_time(value_bytes)
        if self.ptype == PTypeEnum.PtypErrorCode:
            return struct.unpack('I', value_bytes)[0]
        if self.ptype == PTypeEnum.PtypBoolean:
            return struct.unpack('B', value_bytes)[0] != 0
        if self.ptype == PTypeEnum.PtypInteger64:
            return struct.unpack('q', value_bytes)[0]
        if self.ptype == PTypeEnum.PtypString:
            return value_bytes.decode('utf-16-le')  # unicode
        if self.ptype == PTypeEnum.PtypString8:
            if value_bytes[-1:] == '\x00':
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
            count: int = len(value_bytes) // 2
            return [struct.unpack('h', value_bytes[i * 2:(i + 1) * 2])[0] for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleInteger32:
            count = len(value_bytes) // 4
            return [struct.unpack('i', value_bytes[i * 4:(i + 1) * 4])[0] for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleFloating32:
            count = len(value_bytes) // 4
            return [struct.unpack('f', value_bytes[i * 4:(i + 1) * 4])[0] for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleFloating64:
            count = len(value_bytes) // 8
            return [struct.unpack('d', value_bytes[i * 8:(i + 1) * 8])[0] for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleCurrency:
            raise NotImplementedError('PtypMultipleCurrency')
        if self.ptype == PTypeEnum.PtypMultipleFloatingTime:
            count = len(value_bytes) // 8
            return [self.get_floating_time(value_bytes[i * 8:(i + 1) * 8]) for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleInteger64:
            count = len(value_bytes) // 8
            return [struct.unpack('q', value_bytes[i * 8:(i + 1) * 8])[0] for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleString:
            return ''.join([item_bytes.decode('utf-16-le') for item_bytes in value_bytes])
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
        raise MSGException(f"Invalid PTypeEnum for value {self.ptype}")

    def get_floating_time(self, time_bytes: bytes) -> dt.datetime:

        return dt.datetime(year=1899, month=12, day=30) + dt.timedelta(days=struct.unpack('d', time_bytes)[0])

    def get_time(self, time_bytes: bytes) -> dt.datetime:

        return dt.datetime(year=1601, month=1, day=1) + dt.timedelta(microseconds=struct.unpack('q', time_bytes)[0] / 10.0)

    def get_multi_value_offsets(self, value_bytes) -> tuple[int, list[int]]:

        ulCount: int = struct.unpack('I', value_bytes[:4])[0]
        if ulCount == 1:
            # not documented, but seems as if a single length multi only has a 4 byte ULONG with the offset. Boo!
            rgulDataOffsets: list[int] = [8]
        else:
            rgulDataOffsets = [struct.unpack(
                'Q', value_bytes[4 + i * 8:4 + (i + 1) * 8])[0] for i in range(ulCount)]
        rgulDataOffsets.append(len(value_bytes))
        return ulCount, rgulDataOffsets
