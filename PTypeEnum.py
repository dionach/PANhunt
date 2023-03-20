from enum import Enum


class PTypeEnum(Enum):

    PtypInteger16 = 0x02
    PtypInteger32 = 0x03
    PtypFloating32 = 0x04
    PtypFloating64 = 0x05
    PtypCurrency = 0x06
    PtypFloatingTime = 0x07
    PtypErrorCode = 0x0A
    PtypBoolean = 0x0B
    PtypInteger64 = 0x14
    PtypString = 0x1F
    PtypString8 = 0x1E
    PtypTime = 0x40
    PtypGuid = 0x48
    PtypServerId = 0xFB
    PtypRestriction = 0xFD
    PtypRuleAction = 0xFE
    PtypBinary = 0x102
    PtypMultipleInteger16 = 0x1002
    PtypMultipleInteger32 = 0x1003
    PtypMultipleFloating32 = 0x1004
    PtypMultipleFloating64 = 0x1005
    PtypMultipleCurrency = 0x1006
    PtypMultipleFloatingTime = 0x1007
    PtypMultipleInteger64 = 0x1014
    PtypMultipleString = 0x101F
    PtypMultipleString8 = 0x101E
    PtypMultipleTime = 0x1040
    PtypMultipleGuid = 0x1048
    PtypMultipleBinary = 0x1102
    PtypUnspecified = 0x0
    PtypNull = 0x01
    PtypObject = 0x0D
