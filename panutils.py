import codecs
import datetime as dt
import os
import pickle
import re
import struct
import unicodedata
from ctypes import ArgumentError
from typing import Any, Optional, Union

_ValueType = Optional[Union[int, float, dt.datetime, bool, str,
                            bytes, list[int], list[float], list[dt.datetime], list[bytes], list[str]]]


def read_unicode_file(filename: str) -> str:
    with codecs.open(filename, encoding='utf-8', mode='r') as f:
        s: str = f.read()
    return s


def write_unicode_file(filename: str, data_to_write: str) -> None:
    with codecs.open(filename, encoding='utf-8', mode='w') as f:
        f.write(data_to_write)


def read_ascii_file(fn, open_mode="r") -> Any:
    with open(fn, open_mode, encoding='ascii') as f:
        data_read = f.read()
    return data_read


def write_ascii_file(filename: str, data_to_write: Any, write_mode='w') -> None:
    with open(filename, write_mode, encoding='ascii') as f:
        f.write(data_to_write)


def unicode2ascii(unicode_str: str) -> str:
    return unicodedata.normalize('NFKD', unicode_str).encode('ascii', 'ignore').decode("ascii")


def bytes_to_time(datetime_bytes: bytes) -> dt.datetime:
    return dt.datetime(year=1601, month=1, day=1) + dt.timedelta(microseconds=unpack_integer('q', datetime_bytes) / 10.0)


def to_zeropaddedhex(value, fixed_length: int) -> str:
    return f"{value:0{fixed_length}x}"


def decode_zip_filename(filename: str | bytes) -> Any:

    if isinstance(filename, str):
        return filename
    return filename.decode('cp437')


def decode_zip_text(instr: str | bytes) -> str:

    if isinstance(instr, str):
        return instr
    elif isinstance(instr, bytes):
        return instr.decode('utf-8')
    else:
        raise ValueError()


def get_ext(file_name: str) -> str:

    return os.path.splitext(file_name)[1].lower()


def get_safe_filename(filename: str) -> str:

    return re.sub(r'[/\\;,><&\*:%=\+@!#\^\(\)|\?]', '', filename)


def size_friendly(size: int) -> str:
    if size < 1024:
        return f"{size}B"
    if size < 1024 * 1024:
        return f"{(size / 1024)}KB"
    if size < 1024 * 1024 * 1024:
        return f"{(size / (1024 * 1024))}MB"
    return f"{(size / (1024 * 1024 * 1024))}GB"


def datetime_from_filetime(timestamp: int) -> dt.datetime:
    # timestamp: a 64-bit integer representing the number of 100-nanosecond intervals since January 1, 1601
    return dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=timestamp // 10)


def datetime_from_filetime_bytes(timestamp: bytes) -> dt.datetime:
    return datetime_from_filetime(int.from_bytes(timestamp, 'little'))

# TODO: Write a typed wrapper for struct.unpack with ENUM for format: https://docs.python.org/3/library/struct.html#format-characters


def unpack_integer(format: str, buffer: bytes) -> int:
    if format in ['b', 'B', 'h', 'H', 'i', 'I', 'l', 'L', 'q', 'Q', 'n', 'N', 'P']:
        return int(struct.unpack(format, buffer)[0])
    else:
        raise ArgumentError(format, buffer)


def unpack_float(format: str, buffer: bytes) -> float:
    if format in ['e', 'f', 'd']:
        return float(struct.unpack(format, buffer)[0])
    else:
        raise ArgumentError(format, buffer)


def to_binary(value: _ValueType) -> bytes:
    if isinstance(value, bytes):
        return value
    raise TypeError()


def to_str(value: _ValueType) -> str:
    if isinstance(value, str):
        return value
    raise TypeError()


def to_int(value: _ValueType) -> int:
    if isinstance(value, int):
        return value
    raise TypeError()


def to_datetime(value: _ValueType) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value
    raise TypeError()
