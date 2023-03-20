from enum import Enum


class CryptMethodEnum(Enum):
    Unsupported = -1
    Unencoded = 0
    NDB_CRYPT_PERMUTE = 1
