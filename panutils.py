import codecs
import datetime as dt
import os
import pickle
import re
import struct
import unicodedata
from typing import Any


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
    return dt.datetime(year=1601, month=1, day=1) + dt.timedelta(microseconds=struct.unpack('q', datetime_bytes)[0] / 10.0)


def to_zeropaddedhex(value, fixed_length: int) -> str:
    return f"{value:0{fixed_length}x}"


def to_hex(value: bytes) -> str:
    return value.hex()


def load_object(filename: str) -> Any:

    with open(filename, 'rb') as pkl_file:
        obj = pickle.load(pkl_file)
    return obj


def save_object(filename: str, obj) -> None:

    with open(filename, 'wb') as pkl_file:
        pickle.dump(obj, pkl_file, -1)


def write_csv(filename: str, dlines) -> None:

    with open(filename, "w", encoding='ascii') as f:
        for d in dlines:
            s: str = ','.join(['"%s"' % str(i).replace('"', "'") for i in d])
            f.write('%s\n' % s)


def decode_zip_filename(filename: str | bytes) -> Any:

    if isinstance(filename, str):
        return filename
    return filename.decode('cp437')


def get_ext(file_name) -> Any:

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


# TODO: Write a typed wrapper for stuct.unpack with ENUM for format: https://docs.python.org/3/library/struct.html#format-characters
# unpack(bytes, type1, type2=None,type3=None)
