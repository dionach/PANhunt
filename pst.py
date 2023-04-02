#! /usr/bin/env python
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# By BB
# based on MS-PST Microsoft specification for PST file format [MS-PST].pdf v2.1
#

import argparse
import datetime as dt
import itertools
import math
import os
import string
import struct
import sys
from calendar import c
from enum import Enum
from io import BufferedReader, BytesIO
from typing import Any, Literal, Optional, Type, Union

import progressbar
from exceptions import PSTException

import panutils
from CryptMethodEnum import CryptMethodEnum
from PTypeEnum import PTypeEnum

_ValueType = Optional[Union[int, float, dt.datetime, bool, str,
                            bytes, list[int], list[float], list[dt.datetime], list[bytes], list[str]]]



# error_log_list = []

##############################################################################################################################
#  _   _           _        ____        _        _                       ___   _ ____  ______    _
# | \ | | ___   __| | ___  |  _ \  __ _| |_ __ _| |__   __ _ ___  ___   / / \ | |  _ \| __ ) \  | |    __ _ _   _  ___ _ __
# |  \| |/ _ \ / _` |/ _ \ | | | |/ _` | __/ _` | '_ \ / _` / __|/ _ \ | ||  \| | | | |  _ \| | | |   / _` | | | |/ _ \ '__|
# | |\  | (_) | (_| |  __/ | |_| | (_| | || (_| | |_) | (_| \__ \  __/ | || |\  | |_| | |_) | | | |__| (_| | |_| |  __/ |
# |_| \_|\___/ \__,_|\___| |____/ \__,_|\__\__,_|_.__/ \__,_|___/\___| | ||_| \_|____/|____/| | |_____\__,_|\__, |\___|_|
#                                                                       \_\                /_/              |___/
##############################################################################################################################


class NID:
    NID_TYPE_HID = 0x00
    NID_TYPE_INTERNAL = 0x01
    NID_TYPE_NORMAL_FOLDER = 0x02
    NID_TYPE_SEARCH_FOLDER = 0x03
    NID_TYPE_NORMAL_MESSAGE = 0x04
    NID_TYPE_ATTACHMENT = 0x05
    NID_TYPE_SEARCH_UPDATE_QUEUE = 0x06
    NID_TYPE_SEARCH_CRITERIA_OBJECT = 0x07
    NID_TYPE_ASSOC_MESSAGE = 0x08
    NID_TYPE_CONTENTS_TABLE_INDEX = 0x0a
    NID_TYPE_RECEIVE_FOLDER_TABLE = 0x0b
    NID_TYPE_OUTGOING_QUEUE_TABLE = 0x0c
    NID_TYPE_HIERARCHY_TABLE = 0x0d
    NID_TYPE_CONTENTS_TABLE = 0x0e
    NID_TYPE_ASSOC_CONTENTS_TABLE = 0x0f
    NID_TYPE_SEARCH_CONTENTS_TABLE = 0x10
    NID_TYPE_ATTACHMENT_TABLE = 0x11
    NID_TYPE_RECIPIENT_TABLE = 0x12
    NID_TYPE_SEARCH_TABLE_INDEX = 0x13
    NID_TYPE_LTP = 0x1f

    NID_MESSAGE_STORE = 0x21
    NID_NAME_TO_ID_MAP = 0x61
    NID_NORMAL_FOLDER_TEMPLATE = 0xA1
    NID_SEARCH_FOLDER_TEMPLATE = 0xC1
    NID_ROOT_FOLDER = 0x122
    NID_SEARCH_MANAGEMENT_QUEUE = 0x1E1
    NID_SEARCH_ACTIVITY_LIST = 0x201
    NID_RESERVED1 = 0x241
    NID_SEARCH_DOMAIN_OBJECT = 0x261
    NID_SEARCH_GATHERER_QUEUE = 0x281
    NID_SEARCH_GATHERER_DESCRIPTOR = 0x2A1
    NID_RESERVED2 = 0x2E1
    NID_RESERVED3 = 0x301
    NID_SEARCH_GATHERER_FOLDER_QUEUE = 0x321

    nid: int
    nidType: int
    nidIndex: int
    is_hid: bool
    is_nid: bool

    def __init__(self, bytes_or_nid: bytes | int) -> None:

        if isinstance(bytes_or_nid, int):
            self.nid = bytes_or_nid
        else:
            self.nid = panutils.unpack_integer('I', bytes_or_nid)
        self.nidType = self.nid & 0x1f
        self.nidIndex = self.nid & 0xffffffe0
        self.is_hid = False
        self.is_nid = True

    def __repr__(self) -> str:

        return 'nid: %s, %s' % (hex(self.nid), hex(self.nidType))


class BID:
    bid: int
    is_internal: bool

    def __init__(self, value_bytes: bytes) -> None:

        if len(value_bytes) == 4:  # ansi
            self.bid = panutils.unpack_integer('I', value_bytes)
        else:  # unicode (8)
            self.bid = panutils.unpack_integer('Q', value_bytes)
        if self.bid % 2 == 1:  # A
            self.bid -= 1
        self.is_internal = (self.bid & 2 == 2)  # B

    def __repr__(self) -> str:
        if self.is_internal:
            int_ext = 'I'
        else:
            int_ext = 'E'
        return 'bid: %s %s' % (self.bid, int_ext)


class BREF:
    bid: BID
    ib: int

    def __init__(self, value_bytes) -> None:
        bid: bytes
        ib: int
        if len(value_bytes) == 8:  # ansi
            bid, ib = struct.unpack('4sI', value_bytes)
        else:  # unicode (16)
            bid, ib = struct.unpack('8sQ', value_bytes)
        self.bid = BID(bid)
        self.ib = ib

    def __repr__(self) -> str:
        return '%s, ib: %s' % (self.bid, hex(self.ib))


class Page:

    PAGE_SIZE = 512
    ptypeBBT = 0x80
    ptypeNBT = 0x81
    ptypeFMap = 0x82
    ptypePMap = 0x83
    ptypeAMap = 0x84
    ptypeFPMap = 0x85
    ptypeDL = 0x86

    ptype: int
    ptypeRepeat: int
    wSig: int
    bid: int
    dwCRC: int
    cEnt: int
    cEntMax: int
    cbEnt: int
    cLevel: int

    def __init__(self, value_bytes: bytes, is_ansi: bool) -> None:

        # fixed 512 bytes
        if len(value_bytes) != Page.PAGE_SIZE:
            raise PSTException('Invalid Page size')

        ptype: int
        ptypeRepeat: int
        wSig: int
        bid: int
        dwCRC: int

        if is_ansi:
            ptype, ptypeRepeat, wSig, bid, dwCRC = struct.unpack(
                'BBHII', value_bytes[-12:])

        else:  # unicode
            ptype, ptypeRepeat, wSig, dwCRC, bid = struct.unpack(
                'BBHIQ', value_bytes[-16:])

        self.ptype = ptype
        self.ptypeRepeat = ptypeRepeat
        self.wSig = wSig
        self.bid = bid
        self.dwCRC = dwCRC

        if self.ptype < Page.ptypeBBT or self.ptype > Page.ptypeDL:
            raise PSTException('Invalid Page Type %s ' %
                               hex(self.ptype))
        if self.ptype != self.ptypeRepeat:
            raise PSTException('Page Type does not match Page Type Repeat %s!=%s ' % (
                hex(self.ptype), hex(self.ptypeRepeat)))

        entry_type: Type[BBTENTRY] | Type[NBTENTRY] | Type[BTENTRY]
        if self.ptype in (Page.ptypeBBT, Page.ptypeNBT):
            cEnt: int
            cEntMax: int
            cbEnt: int
            cLevel: int

            if is_ansi:
                cEnt, cEntMax, cbEnt, cLevel = struct.unpack(
                    'BBBB', value_bytes[-16:-12])
                # rgEntries 492 (cLevel>0) or 496 bytes (cLevel=0)
                entry_size = 12
            else:  # unicode
                cEnt, cEntMax, cbEnt, cLevel = struct.unpack(
                    'BBBB', value_bytes[-24:-20])
                # rgEntries 488 bytes
                entry_size = 24

            self.cEnt = cEnt
            self.cEntMax = cEntMax
            self.cbEnt = cbEnt
            self.cLevel = cLevel

            if self.cLevel == 0:
                if self.ptype == Page.ptypeBBT:
                    entry_type = BBTENTRY
                else:  # ptypeNBT
                    entry_type = NBTENTRY
                    entry_size = entry_size + entry_size // 3
            else:  # BTENTRY
                entry_type = BTENTRY

            self.rgEntries = []
            # self.cbEnt is size of each entry which may be different to entry_size
            for i in range(self.cEnt):
                self.rgEntries.append(entry_type(
                    value_bytes[i * self.cbEnt:i * self.cbEnt + entry_size]))

    def __repr__(self) -> str:

        return 'PageType: %s, Entries: %s, Level: %s' % (hex(self.ptype), self.cEnt, self.cLevel)


class BTENTRY:
    BREF: 'BREF'
    key: int

    def __init__(self, bytedata: bytes
                 ) -> None:

        if len(bytedata) == 12:  # ansi
            self.key = panutils.unpack_integer('I', bytedata[:4])
            self.BREF = BREF(bytedata[4:])
        else:  # unicode 24
            self.key = panutils.unpack_integer('Q', bytedata[:8])
            self.BREF = BREF(bytedata[8:])

    def __repr__(self) -> str:

        return '%s' % (self.BREF)


class BBTENTRY:
    BREF: 'BREF'
    cb: int
    cRef: int
    key: int

    def __init__(self, value_bytes: bytes) -> None:

        if len(value_bytes) == 12:  # ansi
            self.BREF = BREF(value_bytes[:8])
            self.cb, self.cRef = struct.unpack('HH', value_bytes[8:12])
        else:  # unicode (24)
            self.BREF = BREF(value_bytes[:16])
            self.cb, self.cRef = struct.unpack('HH', value_bytes[16:20])
        self.key = self.BREF.bid.bid

    def __repr__(self) -> str:

        return '%s, data size: %s' % (self.BREF, self.cb)


class NBTENTRY:
    nid: NID
    bidData: BID
    bidSub: BID
    nidParent: NID
    key: int

    def __init__(self, value_bytes: bytes) -> None:

        if len(value_bytes) == 16:  # ansi
            nid, bidData, bidSub, nidParent = struct.unpack(
                '4s4s4s4s', value_bytes)
        else:  # unicode (32)
            nid, padding, bidData, bidSub, nidParent = struct.unpack(
                '4s4s8s8s4s', value_bytes[:-4])
        self.nid = NID(nid)
        self.bidData = BID(bidData)
        self.bidSub = BID(bidSub)
        self.nidParent = NID(nidParent)
        self.key = self.nid.nid

    def __repr__(self) -> str:

        return '%s, bidData: %s, bidSub: %s' % (self.nid, self.bidData, self.bidSub)


class SLENTRY:
    nid: NID
    bidData: BID
    bidSub: BID

    def __init__(self, value_bytes: bytes) -> None:

        if len(value_bytes) == 12:  # ansi
            nid, bidData, bidSub = struct.unpack(
                '4s4s4s', value_bytes)
        else:  # unicode 24
            nid, padding, bidData, bidSub = struct.unpack(
                '4s4s8s8s', value_bytes)
        self.nid = NID(nid)
        self.bidData = BID(bidData)
        self.bidSub = BID(bidSub)

    def __repr__(self) -> str:

        return '%s %s sub%s' % (self.nid, self.bidData, self.bidSub)


class SIENTRY:

    nid: NID
    bid: BID

    def __init__(self, value_bytes: bytes) -> None:
        nid: bytes
        bid: bytes

        if len(value_bytes) == 8:  # ansi
            nid, bid = struct.unpack('4s4s', value_bytes)
        else:  # unicode 16
            nid, padding, bid = struct.unpack('4s4s8s', value_bytes)
        self.nid = NID(nid)
        self.bid = BID(bid)


class Block:

    # this has the first 512 entries removed, as decoding only uses from 512 onwards
    mpbbCryptFrom512 = (71, 241, 180, 230, 11, 106, 114, 72, 133, 78, 158, 235, 226, 248, 148, 83, 224, 187, 160, 2, 232, 90, 9, 171, 219, 227, 186, 198, 124, 195, 16, 221,
                        57, 5, 150, 48, 245, 55, 96, 130, 140, 201, 19, 74, 107, 29, 243, 251, 143, 38, 151, 202, 145, 23, 1, 196, 50, 45, 110, 49, 149, 255, 217, 35,
                        209, 0, 94, 121, 220, 68, 59, 26, 40, 197, 97, 87, 32, 144, 61, 131, 185, 67, 190, 103, 210, 70, 66, 118, 192, 109, 91, 126, 178, 15, 22, 41,
                        60, 169, 3, 84, 13, 218, 93, 223, 246, 183, 199, 98, 205, 141, 6, 211, 105, 92, 134, 214, 20, 247, 165, 102, 117, 172, 177, 233, 69, 33, 112, 12,
                        135, 159, 116, 164, 34, 76, 111, 191, 31, 86, 170, 46, 179, 120, 51, 80, 176, 163, 146, 188, 207, 25, 28, 167, 99, 203, 30, 77, 62, 75, 27, 155,
                        79, 231, 240, 238, 173, 58, 181, 89, 4, 234, 64, 85, 37, 81, 229, 122, 137, 56, 104, 82, 123, 252, 39, 174, 215, 189, 250, 7, 244, 204, 142, 95,
                        239, 53, 156, 132, 43, 21, 213, 119, 52, 73, 182, 18, 10, 127, 113, 136, 253, 157, 24, 65, 125, 147, 216, 88, 44, 206, 254, 36, 175, 222, 184, 54,
                        200, 161, 128, 166, 153, 152, 168, 47, 14, 129, 101, 115, 228, 194, 162, 138, 212, 225, 17, 208, 8, 139, 42, 242, 237, 154, 100, 63, 193, 108, 249, 236)

    decrypt_table: bytes = bytes.maketrans(
        bytearray(list(range(256))), bytearray(mpbbCryptFrom512))

    # TODO: Use Enum
    btypeData = 0
    btypeXBLOCK = 1
    btypeXXBLOCK = 2
    btypeSLBLOCK = 3
    btypeSIBLOCK = 4

    is_ansi: bool
    block_type: int
    btype: int
    cLevel: int
    cEnt: int
    bid: BID
    bid_size: int
    slentry_size: int
    sientry_size: int
    offset: int
    cb: int
    wSig: int
    dwCRC: int
    data_block: bytes

    def __init__(self, value_bytes: bytes, offset: int, data_size: int, is_ansi: bool, bid_check, bCryptMethod: CryptMethodEnum) -> None:

        self.is_ansi = is_ansi
        self.offset = offset  # for debugging

        cb: int
        wSig: int
        bid: bytes
        dwCRC: int

        if self.is_ansi:  # 12
            cb, wSig, bid, dwCRC = struct.unpack(
                'HH4sI', value_bytes[-12:])
            bid_size = 4
            slentry_size = 12
            sientry_size = 8
            # [MS-PST] WRONG for SLBLOCK and SIBLOCK for ANSI: there is no 4 byte padding
            sl_si_entries_offset = 4
        else:  # unicode 16
            cb, wSig, dwCRC, bid = struct.unpack(
                'HHI8s', value_bytes[-16:])
            bid_size = 8
            slentry_size = 24
            sientry_size = 16
            sl_si_entries_offset = 8

        self.cb = cb
        self.wSig = wSig
        self.dwCRC = dwCRC
        self.bid = BID(bid)

        if self.bid.bid != bid_check.bid:
            raise PSTException('Block bid %s != ref bid %s' %
                               (self.bid, bid_check))
        if data_size != self.cb:
            raise PSTException(
                'BBT Entry data size %s != Block data size %s' % (data_size, self.cb))

        if not self.bid.is_internal:

            self.block_type = Block.btypeData
            self.btype = 0
            self.cLevel = 0
            if bCryptMethod == CryptMethodEnum.NDB_CRYPT_PERMUTE:  # NDB_CRYPT_PERMUTE
                self.data_block = value_bytes[:data_size].translate(
                    BytesIO(Block.decrypt_table).read())
            if bCryptMethod == CryptMethodEnum.Unencoded:
                self.data_block = value_bytes[:data_size]  # data block
            else:
                raise RuntimeError("Unsupported encryption method.")

        else:  # XBLOCK, XXBLOCK, SLBLOCK or SIBLOCK

            self.btype, self.cLevel, self.cEnt = struct.unpack(
                'BBH', value_bytes[:4])

            if self.btype == 1:  # XBLOCK, XXBLOCK
                self.lcbTotal = panutils.unpack_integer('I', value_bytes[4:8])
                if self.cLevel == 1:  # XBLOCK
                    self.block_type = Block.btypeXBLOCK
                elif self.cLevel == 2:  # XXBLOCK
                    self.block_type = Block.btypeXXBLOCK
                else:
                    raise PSTException('Invalid Block Level %s' % self.cLevel)
                self.rgbid = []
                for i in range(self.cEnt):
                    self.rgbid.append(
                        BID(value_bytes[8 + i * bid_size:8 + (i + 1) * bid_size]))

            elif self.btype == 2:  # SLBLOCK, SIBLOCK

                self.rgentries: list[SIENTRY | SLENTRY] = []
                if self.cLevel == 0:  # SLBLOCK
                    self.block_type = Block.btypeSLBLOCK
                    for i in range(self.cEnt):
                        self.rgentries.append(SLENTRY(
                            value_bytes[sl_si_entries_offset + i * slentry_size:sl_si_entries_offset + (i + 1) * slentry_size]))
                elif self.cLevel == 1:  # SIBLOCK
                    self.block_type = Block.btypeSIBLOCK
                    for i in range(self.cEnt):
                        self.rgentries.append(SIENTRY(
                            value_bytes[sl_si_entries_offset + i * sientry_size:sl_si_entries_offset + (i + 1) * sientry_size]))
                else:
                    raise PSTException('Invalid Block Level %s' % self.cLevel)

            else:
                raise PSTException('Invalid Block Type %s' % self.btype)

    def __repr__(self) -> str:

        return 'Block %s %s %s' % (self.bid, self.btype, self.cLevel)


class NBD:
    """Node Database Layer"""

    fd: BufferedReader
    header: 'Header'
    nbt_entries: dict[int, NBTENTRY]
    bbt_entries: dict[int, BBTENTRY]

    def __init__(self, fd: BufferedReader, header: 'Header') -> None:

        self.fd = fd
        self.header = header
        self.nbt_entries = self.get_page_leaf_entries(
            NBTENTRY, self.header.root.BREFNBT.ib)  # type: ignore
        self.bbt_entries = self.get_page_leaf_entries(
            BBTENTRY, self.header.root.BREFBBT.ib)  # type: ignore

    def fetch_page(self, offset: int) -> Page:

        self.fd.seek(offset)
        return Page(self.fd.read(Page.PAGE_SIZE), self.header.is_ansi)

    def fetch_block(self, bid: BID) -> Block:

        try:
            bbt_entry: BBTENTRY = self.bbt_entries[bid.bid]
        except KeyError:
            raise PSTException('Invalid BBTEntry: %s' % bid)

        offset: int = bbt_entry.BREF.ib
        data_size: int = bbt_entry.cb

        block_trailer_size: int
        block_size: int
        size_diff: int
        if self.header.is_ansi:
            block_trailer_size = 12
        else:  # unicode
            block_trailer_size = 16
        # block size must align on 64 bytes
        size_diff = (data_size + block_trailer_size) % 64
        if size_diff == 0:
            block_size = data_size + block_trailer_size
        else:
            block_size = data_size + block_trailer_size + 64 - size_diff
        self.fd.seek(offset)
        return Block(self.fd.read(block_size), offset, data_size, self.header.is_ansi, bid, self.header.bCryptMethod)

    def fetch_all_block_data(self, bid: BID) -> list[bytes]:
        """returns list of block datas"""

        data_list: list[bytes] = []
        block: Block = self.fetch_block(bid)
        if block.block_type == Block.btypeData:
            data_list.append(block.data_block)
        elif block.block_type == Block.btypeXBLOCK:
            for xbid in block.rgbid:
                xblock: Block = self.fetch_block(xbid)
                if xblock.block_type != Block.btypeData:
                    raise PSTException(
                        'Expecting data block, got block type %s' % xblock.block_type)
                data_list.append(xblock.data_block)
        elif block.block_type == Block.btypeXXBLOCK:
            for xxbid in block.rgbid:
                xxblock: Block = self.fetch_block(xxbid)
                if xxblock.block_type != Block.btypeXBLOCK:
                    raise PSTException(
                        'Expecting XBLOCK, got block type %s' % xxblock.block_type)
                data_list.extend(self.fetch_all_block_data(xxbid))
        else:
            raise PSTException(
                'Invalid block type (not data/XBLOCK/XXBLOCK), got %s' % block.block_type)
        return data_list

    def fetch_subnodes(self, bid: BID) -> dict[int, SLENTRY]:
        """ get dictionary of subnode SLENTRYs for subnode bid"""

        subnodes: dict[int, SLENTRY] = {}
        block: Block = self.fetch_block(bid)
        if block.block_type == Block.btypeSLBLOCK:
            for entry in block.rgentries:
                if isinstance(entry, SLENTRY):
                    slentry: SLENTRY = entry
                    if slentry.nid.nid in list(subnodes.keys()):
                        raise PSTException(
                            'Duplicate subnode %s' % slentry.nid)
                    subnodes[slentry.nid.nid] = slentry
        elif block.block_type == Block.btypeSIBLOCK:
            for entry in block.rgentries:
                if isinstance(entry, SIENTRY):
                    subnodes.update(self.fetch_subnodes(entry.bid))
        else:
            raise PSTException(
                'Invalid block type (not SLBLOCK/SIBLOCK), got %s' % block.block_type)
        return subnodes

    def get_page_leaf_entries(self, entry_type: Type[NBTENTRY] | Type[BBTENTRY], page_offset: int) -> dict[int, NBTENTRY | BBTENTRY]:
        """ entry type is NBTENTRY or BBTENTRY"""

        leaf_entries: dict[int, NBTENTRY | BBTENTRY] = {}
        page: Page = self.fetch_page(page_offset)
        for entry in page.rgEntries:
            if isinstance(entry, entry_type):
                if entry.key in leaf_entries.keys():
                    raise PSTException('Invalid Leaf Key %s' % entry)
                leaf_entries[entry.key] = entry
            elif isinstance(entry, BTENTRY):
                leaf_entries.update(self.get_page_leaf_entries(
                    entry_type, entry.BREF.ib))
            else:
                raise PSTException('Invalid Entry Type')
        return leaf_entries


################################################################################################################################################################################
#  _     _     _           _____     _     _                               _   ____                            _   _              ___   _____ ______    _
# | |   (_)___| |_ ___    |_   _|_ _| |__ | | ___  ___      __ _ _ __   __| | |  _ \ _ __ ___  _ __   ___ _ __| |_(_) ___  ___   / / | |_   _|  _ \ \  | |    __ _ _   _  ___ _ __
# | |   | / __| __/ __|     | |/ _` | '_ \| |/ _ \/ __|    / _` | '_ \ / _` | | |_) | '__/ _ \| '_ \ / _ \ '__| __| |/ _ \/ __| | || |   | | | |_) | | | |   / _` | | | |/ _ \ '__|
# | |___| \__ \ |_\__ \_    | | (_| | |_) | |  __/\__ \_  | (_| | | | | (_| | |  __/| | | (_) | |_) |  __/ |  | |_| |  __/\__ \ | || |___| | |  __/| | | |__| (_| | |_| |  __/ |
# |_____|_|___/\__|___( )   |_|\__,_|_.__/|_|\___||___( )  \__,_|_| |_|\__,_| |_|   |_|  \___/| .__/ \___|_|   \__|_|\___||___/ | ||_____|_| |_|   | | |_____\__,_|\__, |\___|_|
#                     |/                              |/                                      |_|                                \_\              /_/              |___/
################################################################################################################################################################################


class HID:

    hidIndex: int
    hidBlockIndex: int

    def __init__(self, value_bytes) -> None:

        # hidIndex cannot be zero, first 5 bits must be zero (hidType)
        self.hidIndex, self.hidBlockIndex = struct.unpack('HH', value_bytes)
        self.hidType: int = self.hidIndex & 0x1F
        self.hidIndex = (self.hidIndex >> 5) & 0x7FF
        self.is_hid: bool = True
        self.is_nid: bool = False


class HNPAGEMAP:
    cAlloc: int
    cFree: int

    def __init__(self, value_bytes: bytes) -> None:

        self.cAlloc, self.cFree = struct.unpack('HH', value_bytes[:4])
        self.rgibAlloc: list[int] = []
        for i in range(self.cAlloc + 1):  # cAlloc+1 is next free
            self.rgibAlloc.append(struct.unpack(
                'H', value_bytes[4 + i * 2:4 + (i + 1) * 2])[0])


class HN:

    # TODO: Use Enum
    bTypeTC: int = 0x7C
    bTypeBTH: int = 0xB5
    bTypePC: int = 0xBC

    nbt_entry: NBTENTRY
    data_sections: list[bytes]
    ltp: 'LTP'
    hnpagemaps: list[HNPAGEMAP]
    subnodes: Optional[dict[int, SLENTRY]] = None
    bSig: int
    bClientSig: int
    hidUserRoot: HID
    rgbFillLevel: int

    def __init__(self, nbt_entry: NBTENTRY, ltp: 'LTP', data_sections: list[bytes]) -> None:
        """data_sections = list of data sections from blocks"""

        self.nbt_entry = nbt_entry
        self.data_sections = data_sections
        self.ltp = ltp
        self.hnpagemaps = []

        for i, section_bytes in enumerate(data_sections):
            ibHnpm: int
            bSig: int
            bClientSig: int
            hidUserRootBytes: bytes
            rgbFillLevel: int

            if i == 0:  # HNHDR
                ibHnpm, bSig, bClientSig, hidUserRootBytes, rgbFillLevel = struct.unpack(
                    'HBB4sI', section_bytes[:12])
                self.bSig = bSig
                self.bClientSig = bClientSig
                self.rgbFillLevel = rgbFillLevel

                self.hidUserRoot = HID(hidUserRootBytes)
                if self.bSig != 0xEC:
                    raise PSTException('Invalid HN Signature %s' % self.bSig)
            else:  # HNPAGEHDR or HNBITMAPHDR
                ibHnpm = panutils.unpack_integer('H', section_bytes[:2])
            self.hnpagemaps.append(HNPAGEMAP(section_bytes[ibHnpm:]))

        # subnode SLENTRYs
        self.subnodes = None
        if self.nbt_entry.bidSub.bid != 0:
            self.subnodes = self.ltp.nbd.fetch_subnodes(self.nbt_entry.bidSub)

    def get_hid_data(self, hid: HID) -> bytes:

        start_offset: int = self.hnpagemaps[hid.hidBlockIndex].rgibAlloc[hid.hidIndex - 1]
        end_offset: int = self.hnpagemaps[hid.hidBlockIndex].rgibAlloc[hid.hidIndex]
        block: bytes = self.data_sections[hid.hidBlockIndex]
        return block[start_offset:end_offset]

    def __repr__(self) -> str:

        return 'HN: %s, Blocks: %s' % (self.nbt_entry, len(self.data_sections))


class BTHData:
    key: bytes
    data: bytes

    def __init__(self, key: bytes, data: bytes) -> None:

        self.key = key
        self.data = data


class BTHIntermediate:

    key: bytes
    hidNextLevel: HID
    bIdxLevel: int

    def __init__(self, key: bytes, hidNextLevel: HID, bIdxLevel: int) -> None:

        self.key = key
        self.hidNextLevel = hidNextLevel
        self.bIdxLevel = bIdxLevel


class BTH:
    bType: int
    cbKey: int
    cbEnt: int
    bIdxLevels: int
    hidRoot: HID
    bth_data_list: list[BTHData]

    def __init__(self, hn: HN, bth_hid: HID) -> None:
        """ hn = HN heapnode, bth_hid is hid of BTH header"""

        # BTHHEADER
        bth_header_bytes: bytes = hn.get_hid_data(bth_hid)
        hidRootBytes: bytes
        self.bType, self.cbKey, self.cbEnt, self.bIdxLevels, hidRootBytes = struct.unpack(
            'BBBB4s', bth_header_bytes)
        self.hidRoot: HID = HID(hidRootBytes)
        if self.bType != HN.bTypeBTH:
            raise PSTException('Invalid BTH Type %s' % self.bType)
        self.bth_data_list = []
        bth_working_stack: list[BTHIntermediate] = []
        if self.hidRoot.hidIndex != 0:
            value_bytes: bytes = hn.get_hid_data(self.hidRoot)
            bth_record_list: list[BTHData | BTHIntermediate] = self.get_bth_records(
                value_bytes, self.bIdxLevels)
            bth_data_list: list[BTHData] = [
                bthdata for bthdata in bth_record_list if isinstance(bthdata, BTHData)]
            bth_intermediate_list: list[BTHIntermediate] = [
                bthim for bthim in bth_record_list if isinstance(bthim, BTHIntermediate)]

            if self.bIdxLevels == 0:  # no intermediate levels
                self.bth_data_list = bth_data_list
            else:
                bth_working_stack = bth_intermediate_list
                while bth_working_stack:
                    bth_intermediate: BTHIntermediate = bth_working_stack.pop()
                    value_bytes = hn.get_hid_data(
                        bth_intermediate.hidNextLevel)
                    bth_record_list = self.get_bth_records(
                        value_bytes, bth_intermediate.bIdxLevel - 1)
                    if bth_intermediate.bIdxLevel - 1 == 0:  # leafs
                        self.bth_data_list.extend(bth_data_list)
                    else:
                        bth_working_stack.extend(bth_intermediate_list)

    def get_bth_records(self, value_bytes: bytes, bIdxLevel: int) -> list[BTHData | BTHIntermediate]:

        bth_record_list: list[BTHData | BTHIntermediate] = []
        if bIdxLevel == 0:  # leaf
            record_size: int = self.cbKey + self.cbEnt
            records: int = len(value_bytes) // record_size
            for i in range(records):
                key, data = struct.unpack('%ss%ss' % (
                    self.cbKey, self.cbEnt), value_bytes[i * record_size:(i + 1) * record_size])
                bth_record_list.append(BTHData(key, data))
        else:  # intermediate
            record_size = self.cbKey + 4
            records = len(value_bytes) // record_size
            for i in range(records):
                key, hidNextLevel = struct.unpack(
                    '%ss4s' % self.cbKey, value_bytes[i * record_size:(i + 1) * record_size])
                hidNextLevel = HID(hidNextLevel)
                bth_record_list.append(BTHIntermediate(
                    key, hidNextLevel, bIdxLevel))
        return bth_record_list


class PCBTHData:
    wPropId: 'PropIdEnum'
    wPropType: int
    dwValueHnid: bytes
    value: _ValueType
    hid: HID
    subnode_nid: NID

    def __init__(self, bth_data: BTHData, hn: HN) -> None:

        self.wPropId = PropIdEnum(panutils.unpack_integer('H', bth_data.key))
        wPropType: int
        dwValueHnid: bytes
        wPropType, dwValueHnid = struct.unpack('H4s', bth_data.data)

        self.wPropType = wPropType
        self.dwValueHnid: bytes = dwValueHnid

        ptype: PType = hn.ltp.ptypes[PTypeEnum(self.wPropType)]

        if not ptype.is_variable and not ptype.is_multi:
            if ptype.byte_count <= 4:
                self.value = ptype.value(self.dwValueHnid[:ptype.byte_count])
            else:
                self.hid = HID(self.dwValueHnid)
                self.value = ptype.value(hn.get_hid_data(self.hid))
        else:
            if NID(self.dwValueHnid).nidType == NID.NID_TYPE_HID:
                self.hid = HID(self.dwValueHnid)
                self.value = ptype.value(hn.get_hid_data(self.hid))
            else:
                self.subnode_nid = NID(self.dwValueHnid)
                if hn.subnodes and self.subnode_nid.nid in list(hn.subnodes.keys()):
                    subnode_nid_bid: BID = hn.subnodes[self.subnode_nid.nid].bidData
                else:
                    raise PSTException(
                        'Invalid NID subnode reference %s' % self.subnode_nid)
                data_list: list[bytes] = hn.ltp.nbd.fetch_all_block_data(
                    subnode_nid_bid)
                self.value = ptype.value(b''.join(data_list))

    def __repr__(self) -> str:

        return '%s (%s) = %s' % (hex(self.wPropId.value), hex(self.wPropType), repr(self.value))


class PType:

    ptype: PTypeEnum
    byte_count: int
    is_variable: bool
    is_multi: bool

    def __init__(self, ptype: PTypeEnum, byte_count: int, is_variable: bool, is_multi: bool) -> None:

        self.ptype, self.byte_count, self.is_variable, self.is_multi = ptype, byte_count, is_variable, is_multi

    def value(self, value_bytes: bytes) -> _ValueType:
        """value_bytes is normally a string of bytes, but if multi and variable, bytes is a list of bytes"""

        ulCount: int
        rgulDataOffsets: list[int]
        data_list: list[bytes]

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
            ulCount, rgulDataOffsets = self.get_multi_value_offsets(
                value_bytes)
            s: list[str] = []
            for i in range(ulCount):
                s.append(value_bytes[rgulDataOffsets[i]                         :rgulDataOffsets[i + 1]].decode('utf-16-le'))
            return s
        if self.ptype == PTypeEnum.PtypMultipleString8:
            ulCount, rgulDataOffsets = self.get_multi_value_offsets(
                value_bytes)
            data_list = []
            for i in range(ulCount):
                data_list.append(
                    value_bytes[rgulDataOffsets[i]:rgulDataOffsets[i + 1]])
            return data_list
        if self.ptype == PTypeEnum.PtypMultipleTime:
            count = len(value_bytes) // 8
            return [self.get_time(value_bytes[i * 8:(i + 1) * 8]) for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleGuid:
            count = len(value_bytes) // 16
            return [value_bytes[i * 16:(i + 1) * 16] for i in range(count)]
        if self.ptype == PTypeEnum.PtypMultipleBinary:
            ulCount, rgulDataOffsets = self.get_multi_value_offsets(
                value_bytes)
            data_list = []
            for i in range(ulCount):
                data_list.append(
                    value_bytes[rgulDataOffsets[i]:rgulDataOffsets[i + 1]])
            return data_list
        if self.ptype == PTypeEnum.PtypUnspecified:
            return value_bytes
        if self.ptype == PTypeEnum.PtypNull:
            return None
        if self.ptype == PTypeEnum.PtypObject:
            return value_bytes[:4]
        raise PSTException(f"Invalid PTypeEnum for value {self.ptype}")

    def unpack_list_int(self, value_bytes: bytes, bit_size: Literal[16, 32, 64]) -> list[int]:
        format_dict: dict[int, str] = {16: 'h', 32: 'i', 64: 'q'}
        count: int = len(value_bytes) // (bit_size // 8)
        return [panutils.unpack_integer(
            format_dict[bit_size], value_bytes[i * count:(i + 1) * count]) for i in range(count)]

    def unpack_list_float(self, value_bytes: bytes, bit_size: Literal[32, 64]) -> list[float]:
        format_dict: dict[int, str] = {32: 'f', 64: 'd'}
        count: int = len(value_bytes) // (bit_size // 8)
        return [panutils.unpack_float(
            format_dict[bit_size], value_bytes[i * count:(i + 1) * count]) for i in range(count)]

    def get_floating_time(self, time_bytes: bytes) -> dt.datetime:

        return dt.datetime(year=1899, month=12, day=30) + dt.timedelta(days=panutils.unpack_float('d', time_bytes))

    def get_time(self, time_bytes: bytes) -> dt.datetime:

        return dt.datetime(year=1601, month=1, day=1) + dt.timedelta(microseconds=panutils.unpack_integer('q', time_bytes) / 10.0)

    def get_multi_value_offsets(self, value_bytes: bytes) -> tuple[int, list[int]]:

        ulCount: int = panutils.unpack_integer('I', value_bytes[:4])
        rgulDataOffsets: list[int] = [struct.unpack(
            'I', value_bytes[(i + 1) * 4:(i + 2) * 4])[0] for i in range(ulCount)]
        rgulDataOffsets.append(len(value_bytes))
        return ulCount, rgulDataOffsets


class PropIdEnum(Enum):

    PidTagNameidBucketCount = 0x0001
    PidTagNameidStreamGuid = 0x0002
    PidTagNameidStreamEntry = 0x0003
    PidTagNameidStreamString = 0x0004
    PidTagNameidBucketBase = 0x1000
    PidTagItemTemporaryFlags = 0x1097
    PidTagPstBestBodyProptag = 0x661D
    PidTagPstIpmsubTreeDescendant = 0x6705
    PidTagPstSubTreeContainer = 0x6772
    PidTagLtpParentNid = 0x67F1
    PidTagLtpRowId = 0x67F2
    PidTagLtpRowVer = 0x67F3
    PidTagPstPassword = 0x67FF
    PidTagMapiFormComposeCommand = 0x682F
    PidTagRecordKey = 0x0FF9
    PidTagDisplayName = 0x3001
    PidTagIpmSubTreeEntryId = 0x35E0
    PidTagIpmWastebasketEntryId = 0x35E3
    PidTagFinderEntryId = 0x35E7
    PidTagContentCount = 0x3602
    PidTagContentUnreadCount = 0x3603
    PidTagSubfolders = 0x360A
    PidTagReplItemid = 0x0E30
    PidTagReplChangenum = 0x0E33
    PidTagReplVersionHistory = 0x0E34
    PidTagReplFlags = 0x0E38
    PidTagContainerClass = 0x3613
    PidTagPstHiddenCount = 0x6635
    PidTagPstHiddenUnread = 0x6636
    PidTagImportance = 0x0017
    PidTagMessageClassW = 0x001A
    PidTagSensitivity = 0x0036
    PidTagSubjectW = 0x0037
    PidTagClientSubmitTime = 0x0039
    PidTagSentRepresentingSearchKey = 0x003B
    PidTagSentRepresentingNameW = 0x0042
    PidTagMessageToMe = 0x0057
    PidTagMessageCcMe = 0x0058
    PidTagConversationTopicW = 0x0070
    PidTagConversationIndex = 0x0071
    PidTagDisplayCcW = 0x0E03
    PidTagDisplayToW = 0x0E04
    PidTagMessageDeliveryTime = 0x0E06
    PidTagMessageFlags = 0x0E07
    PidTagMessageSize = 0x0E08
    PidTagMessageStatus = 0x0E17
    PidTagReplCopiedfromVersionhistory = 0x0E3C
    PidTagReplCopiedfromItemid = 0x0E3D
    PidTagLastModificationTime = 0x3008
    PidTagSmtpAddress = 0x39FE
    PidTagSecureSubmitFlags = 0x65C6
    PidTagOfflineAddressBookName = 0x6800
    PidTagSendOutlookRecallReport = 0x6803
    PidTagOfflineAddressBookTruncatedProperties = 0x6805
    PidTagViewDescriptorFlags = 0x7003
    PidTagViewDescriptorLinkTo = 0x7004
    PidTagViewDescriptorViewFolder = 0x7005
    PidTagViewDescriptorName = 0x7006
    PidTagViewDescriptorVersion = 0x7007
    PidTagCreationTime = 0x3007
    PidTagSearchKey = 0x300B
    PidTagRecipientType = 0x0c15
    PidTagResponsibility = 0x0E0F
    PidTagObjectType = 0x0FFE
    PidTagEntryID = 0x0FFF
    PidTagAddressType = 0x3002
    PidTagEmailAddress = 0x3003
    PidTagDisplayType = 0x3900
    PidTag7BitDisplayName = 0x39FF
    PidTagSendRichInfo = 0x3A40
    PidTagAttachmentSize = 0x0E20
    PidTagAttachFilename = 0x3704
    PidTagAttachMethod = 0x3705
    PidTagRenderingPosition = 0x370B
    PidTagSenderEntryId = 0x0C19
    PidTagSenderName = 0x0C1A
    PidTagSenderSearchKey = 0x0C1D
    PidTagSenderAddressType = 0x0C1E
    PidTagRead = 0x0E69
    PidTagHasAttachments = 0x0E1B
    PidTagBody = 0x1000
    PidTagRtfCompressed = 0x1009
    PidTagAttachDataBinary = 0x3701
    PidTagAttachDataObject = 0x3701
    PidTagOriginalDisplayTo = 0x0074
    PidTagTransportMessageHeaders = 0x007D
    PidTagSenderSmtpAddress = 0x5D01
    PidTagSentRepresentingSmtpAddress = 0x5D02
    PidTagReceivedBySmtpAddress = 0x5D07
    PidTagReceivedRepresentingSmtpAddress = 0x5D08
    PidTagAttachMimeTag = 0x370E
    PidTagAttachExtension = 0x3703
    PidTagAttachLongFilename = 0x3707


class PC:  # Property Context

    hn: HN
    bth: BTH
    properties: dict[PropIdEnum, PCBTHData]

    def __init__(self, hn: HN) -> None:

        self.hn = hn
        if hn.bClientSig != HN.bTypePC:
            raise PSTException(
                'Invalid HN bClientSig, not bTypePC, is %s' % hn.bClientSig)
        self.bth = BTH(hn, hn.hidUserRoot)
        if self.bth.cbKey != 2:
            raise PSTException('Invalid PC BTH key size: %s' % self.bth.cbKey)
        if self.bth.cbEnt != 6:
            raise PSTException('Invalid PC BTH data size: %s' % self.bth.cbEnt)
        self.properties = {}
        for bth_data in self.bth.bth_data_list:
            if isinstance(bth_data, BTHData):
                pc_property: PCBTHData = PCBTHData(bth_data, hn)
                if pc_property.wPropId in (PropIdEnum.PidTagFinderEntryId, PropIdEnum.PidTagIpmSubTreeEntryId, PropIdEnum.PidTagIpmWastebasketEntryId, PropIdEnum.PidTagEntryID):
                    # TODO: Solve EntryID issue
                    entryId = EntryID(
                        panutils.to_binary(pc_property.value))
                    pc_property.value = entryId
                self.properties[pc_property.wPropId] = pc_property

    def getval(self, propid: PropIdEnum) -> PCBTHData:

        if propid in self.properties:
            return self.properties[propid]

        raise IndexError("Invalid propid %s" % propid)

    def __repr__(self) -> str:

        s: str = f'PC {self.hn}\n'
        s += '\n'.join([f'Property {self.properties[wPropId]}'
                       for wPropId in self.properties])
        return s


class TCOLDESC:

    wPropType: int
    wPropId: int
    ibData: int
    cbData: int
    iBit: int

    def __init__(self, value_bytes: bytes) -> None:

        # self.tag is 4 byte (self.wPropId, self.wPropType): where is documentation MS?
        self.wPropType, self.wPropId, self.ibData, self.cbData, self.iBit = struct.unpack(
            'HHHBB', value_bytes)

    def __repr__(self) -> str:

        return 'Tag: %s/%s, Offset+Size: %s+%s' % (hex(self.wPropId), hex(self.wPropType), self.ibData, self.cbData)


class TCROWID:

    dwRowIndex: int
    dwRowID: int
    nid: NID

    def __init__(self, bth_data: BTHData) -> None:

        self.dwRowID = panutils.unpack_integer('I', bth_data.key)  # dwRowID
        self.nid = NID(bth_data.key)  # for hierarchy TCs
        if len(bth_data.data) == 2:  # ansi
            self.dwRowIndex = panutils.unpack_integer('H', bth_data.data)
        else:  # unicode (4)
            self.dwRowIndex = panutils.unpack_integer('I', bth_data.data)


class TC:  # Table Context

    TCI_4b: int = 0
    TCI_2b: int = 1
    TCI_1b: int = 2
    TCI_bm: int = 3

    hn: HN
    bType: int
    cCols: int
    hnidRows: HID | NID
    hidRowIndex: HID
    rgib: tuple[int, int, int, int]
    rgTCOLDESC: list[TCOLDESC]
    hidIndex: bytes
    RowIndex: dict[int, TCROWID]
    RowMatrix: dict[PropIdEnum, dict[int, _ValueType]]

    def __init__(self, hn: HN) -> None:

        self.hn = hn
        if hn.bClientSig != HN.bTypeTC:
            raise PSTException(
                'Invalid HN bClientSig, not bTypeTC, is %s' % hn.bClientSig)
        tcinfo_bytes: bytes = hn.get_hid_data(hn.hidUserRoot)
        self.bType, self.cCols = struct.unpack('BB', tcinfo_bytes[:2])
        if self.bType != HN.bTypeTC:
            raise PSTException(
                'Invalid TCINFO bType, not bTypeTC, is %s' % self.bType)
        self.rgib = struct.unpack('HHHH', tcinfo_bytes[2:10])    # type: ignore
        hidRowIndexBytes, hnidRowsBytes, hidIndexBytes = struct.unpack(
            '4s4s4s', tcinfo_bytes[10:22])
        self.hidRowIndex = HID(hidRowIndexBytes)
        self.hidIndex = hidIndexBytes
        if NID(hnidRowsBytes).nidType == NID.NID_TYPE_HID:
            self.hnidRows = HID(hnidRowsBytes)
        else:
            self.hnidRows = NID(hnidRowsBytes)
        self.rgTCOLDESC = []
        for i in range(self.cCols):
            self.rgTCOLDESC.append(
                TCOLDESC(tcinfo_bytes[22 + i * 8:22 + (i + 1) * 8]))

        self.setup_row_index()
        self.setup_row_matrix()

    def setup_row_index(self) -> None:

        # key is dwRowID, value is dwRowIndex
        self.RowIndex: dict[int, TCROWID] = {}
        if not (self.hnidRows.is_hid and self.hnidRows.hidIndex == 0):  # type: ignore
            row_index_bth: BTH = BTH(self.hn, self.hidRowIndex)
            if row_index_bth.cbKey != 4:
                raise PSTException(
                    'Invalid TC RowIndex key size %s' % row_index_bth.cbKey)
            for bth_data in row_index_bth.bth_data_list:
                tcrowid: TCROWID = TCROWID(bth_data)
                self.RowIndex[tcrowid.dwRowIndex] = tcrowid

    def setup_row_matrix(self) -> None:

        self.RowMatrix = {}
        row_matrix_data: list[bytes]

        if self.RowIndex:
            if self.hn.ltp.nbd.header.is_ansi:
                size_BlockTrailer: int = 12
            else:  # unicode
                size_BlockTrailer = 16

            row_size: int = self.rgib[TC.TCI_bm]
            RowsPerBlock: int = int(math.floor(
                (8192.0 - size_BlockTrailer) / row_size))

            if self.hnidRows.is_hid:
                if isinstance(self.hnidRows, HID):
                    row_matrix_data = [self.hn.get_hid_data(
                        self.hnidRows)]  # block data list
                raise TypeError()
            else:
                if isinstance(self.hnidRows, NID):
                    if self.hn.subnodes and self.hnidRows.nid in list(self.hn.subnodes.keys()):
                        subnode_nid_bid: BID = self.hn.subnodes[self.hnidRows.nid].bidData
                        row_matrix_data = self.hn.ltp.nbd.fetch_all_block_data(
                            subnode_nid_bid)
                    else:
                        raise PSTException(
                            'Row Matrix HNID not in Subnodes: %s' % self.hnidRows.nid)
                else:
                    raise TypeError()

            for irow in range(len(self.RowIndex)):
                BlockIndex: int = irow // RowsPerBlock
                RowIndex: int = irow % RowsPerBlock
                row_bytes: bytes = row_matrix_data[BlockIndex][RowIndex *
                                                               row_size:(RowIndex + 1) * row_size]
                dwRowID: int = panutils.unpack_integer('I', row_bytes[:4])
                rgbCEB: bytes = row_bytes[self.rgib[TC.TCI_1b]:]

                rowvals: dict[int, _ValueType] = {}
                for tcoldesc in self.rgTCOLDESC:
                    is_fCEB: bool = (
                        (rgbCEB[tcoldesc.iBit // 8] & (1 << (7 - (tcoldesc.iBit % 8)))) != 0)
                    if is_fCEB:
                        data_bytes: Optional[bytes] = row_bytes[tcoldesc.ibData:
                                                                tcoldesc.ibData + tcoldesc.cbData]
                    else:
                        data_bytes = None

                    if tcoldesc.wPropId in rowvals:
                        raise PSTException(
                            'Property ID %s already in row data' % hex(tcoldesc.wPropId))
                    rowvals[tcoldesc.wPropId] = self.get_row_cell_value(
                        data_bytes, tcoldesc)
                self.RowMatrix[PropIdEnum(dwRowID)] = rowvals  # row_datas

    def get_row_cell_value(self, data_bytes: Optional[bytes], tcoldesc: TCOLDESC) -> _ValueType:

        if data_bytes is None:
            return None

        ptype: PType = self.hn.ltp.ptypes[PTypeEnum(tcoldesc.wPropType)]
        hid: HID

        if not ptype.is_variable and not ptype.is_multi:
            if ptype.byte_count <= 8:
                return ptype.value(data_bytes)

            hid = HID(data_bytes)
            return ptype.value(self.hn.get_hid_data(hid))

        if NID(data_bytes).nidType == NID.NID_TYPE_HID:
            hid = HID(data_bytes)
            return ptype.value(self.hn.get_hid_data(hid))

        subnode_nid: NID = NID(data_bytes)
        if self.hn.subnodes and subnode_nid.nid in list(self.hn.subnodes.keys()):
            subnode_nid_bid: BID = self.hn.subnodes[subnode_nid.nid].bidData
        else:
            raise PSTException(
                'Row Matrix Value HNID Subnode invalid: %s' % subnode_nid)

        data_sectors: list[bytes] = self.hn.ltp.nbd.fetch_all_block_data(
            subnode_nid_bid)
        return ptype.value(b''.join(data_sectors))

    def get_row_ID(self, RowIndex) -> int:

        return self.RowIndex[RowIndex].dwRowID

    def getval(self, RowIndex: int, wPropId: PropIdEnum) -> _ValueType:

        dwRowID: int = self.get_row_ID(RowIndex)
        rowvals: dict[int,
                      _ValueType] = self.RowMatrix[PropIdEnum(dwRowID)]
        if wPropId.value in rowvals.keys():
            return rowvals[wPropId.value]
        return None

    def __repr__(self) -> str:

        s: str = 'TC Rows: %s, %s\n' % (len(self.RowIndex), self.hn)
        s += 'Columns: ' + \
            ''.join([' %s' % tcoldesc for tcoldesc in self.rgTCOLDESC])
        s += '\nData:\n' + '\n'.join(['%s: %s' % (hex(dwRowID.value), rowvals)
                                     for dwRowID, rowvals in list(self.RowMatrix.items())])
        return s


class LTP:
    """LTP layer"""

    def __init__(self, nbd: NBD) -> None:

        self.nbd: NBD = nbd

        self.ptypes: dict[PTypeEnum, PType] = {
            PTypeEnum.PtypInteger16: PType(PTypeEnum.PtypInteger16, 2, False, False),
            PTypeEnum.PtypInteger32: PType(PTypeEnum.PtypInteger32, 4, False, False),
            PTypeEnum.PtypFloating32: PType(PTypeEnum.PtypFloating32, 4, False, False),
            PTypeEnum.PtypFloating64: PType(PTypeEnum.PtypFloating64, 8, False, False),
            PTypeEnum.PtypCurrency: PType(PTypeEnum.PtypCurrency, 8, False, False),
            PTypeEnum.PtypFloatingTime: PType(PTypeEnum.PtypFloatingTime, 8, False, False),
            PTypeEnum.PtypErrorCode: PType(PTypeEnum.PtypErrorCode, 4, False, False),
            PTypeEnum.PtypBoolean: PType(PTypeEnum.PtypBoolean, 1, False, False),
            PTypeEnum.PtypInteger64: PType(PTypeEnum.PtypInteger64, 8, False, False),
            PTypeEnum.PtypString: PType(PTypeEnum.PtypString, 0, True, False),
            PTypeEnum.PtypString8: PType(PTypeEnum.PtypString8, 0, True, False),
            PTypeEnum.PtypTime: PType(PTypeEnum.PtypTime, 8, False, False),
            PTypeEnum.PtypGuid: PType(PTypeEnum.PtypGuid, 16, False, False),
            PTypeEnum.PtypServerId: PType(PTypeEnum.PtypServerId, 2, False, True),
            PTypeEnum.PtypRestriction: PType(PTypeEnum.PtypRestriction, 0, True, False),
            PTypeEnum.PtypRuleAction: PType(PTypeEnum.PtypRuleAction, 2, False, True),
            PTypeEnum.PtypBinary: PType(PTypeEnum.PtypBinary, 2, False, True),
            PTypeEnum.PtypMultipleInteger16: PType(PTypeEnum.PtypMultipleInteger16, 2, False, True),
            PTypeEnum.PtypMultipleInteger32: PType(PTypeEnum.PtypMultipleInteger32, 2, False, True),
            PTypeEnum.PtypMultipleFloating32: PType(PTypeEnum.PtypMultipleFloating32, 2, False, True),
            PTypeEnum.PtypMultipleFloating64: PType(PTypeEnum.PtypMultipleFloating64, 2, False, True),
            PTypeEnum.PtypMultipleCurrency: PType(PTypeEnum.PtypMultipleCurrency, 2, False, True),
            PTypeEnum.PtypMultipleFloatingTime: PType(PTypeEnum.PtypMultipleFloatingTime, 2, False, True),
            PTypeEnum.PtypMultipleInteger64: PType(PTypeEnum.PtypMultipleInteger64, 2, False, True),
            PTypeEnum.PtypMultipleString: PType(PTypeEnum.PtypMultipleString, 2, True, True),
            PTypeEnum.PtypMultipleString8: PType(PTypeEnum.PtypMultipleString8, 2, True, True),
            PTypeEnum.PtypMultipleTime: PType(PTypeEnum.PtypMultipleTime, 2, False, True),
            PTypeEnum.PtypMultipleGuid: PType(PTypeEnum.PtypMultipleGuid, 2, False, True),
            PTypeEnum.PtypMultipleBinary: PType(PTypeEnum.PtypMultipleBinary, 2, False, True),
            PTypeEnum.PtypUnspecified: PType(PTypeEnum.PtypUnspecified, 0, False, False),
            PTypeEnum.PtypNull: PType(PTypeEnum.PtypNull, 0, False, False),
            PTypeEnum.PtypObject: PType(PTypeEnum.PtypObject, 4, False, True)
        }

    def get_pc_by_nid(self, nid: NID) -> PC:

        nbt_entry: NBTENTRY = self.nbd.nbt_entries[nid.nid]
        datas: list[bytes] = self.nbd.fetch_all_block_data(nbt_entry.bidData)
        hn: HN = HN(nbt_entry, self, datas)
        return PC(hn)

    def get_pc_by_slentry(self, slentry: SLENTRY) -> PC:

        datas: list[bytes] = self.nbd.fetch_all_block_data(slentry.bidData)
        # TODO: Solve HN with SLENTRY parameter
        hn: HN = HN(slentry, self, datas)

        return PC(hn)

    def get_tc_by_nid(self, nid: NID) -> TC:

        nbt_entry: NBTENTRY = self.nbd.nbt_entries[nid.nid]
        datas: list[bytes] = self.nbd.fetch_all_block_data(nbt_entry.bidData)
        hn: HN = HN(nbt_entry, self, datas)
        return TC(hn)

    def get_tc_by_slentry(self, slentry: SLENTRY) -> TC:

        datas: list[bytes] = self.nbd.fetch_all_block_data(slentry.bidData)
        # TODO: Solve HN with SLENTRY parameter
        hn: HN = HN(slentry, self, datas)

        return TC(hn)

    def strip_SubjectPrefix(self, Subject: str) -> str:
        if Subject and ord(Subject[:1]) == 0x01:
            # prefix_length = ord(Subject[1:2])
            # return Subject[prefix_length+1:]
            return Subject[2:]
        else:
            return Subject


#############################################################################################################################
#  __  __                           _               _
# |  \/  | ___  ___ ___  __ _  __ _(_)_ __   __ _  | |    __ _ _   _  ___ _ __
# | |\/| |/ _ \/ __/ __|/ _` |/ _` | | '_ \ / _` | | |   / _` | | | |/ _ \ '__|
# | |  | |  __/\__ \__ \ (_| | (_| | | | | | (_| | | |__| (_| | |_| |  __/ |
# |_|  |_|\___||___/___/\__,_|\__, |_|_| |_|\__, | |_____\__,_|\__, |\___|_|
#                             |___/         |___/              |___/
#############################################################################################################################


class EntryID:

    rgbFlags: bytes
    uid: bytes
    nid: NID

    def __init__(self, value_bytes: bytes) -> None:

        nid_bytes: bytes
        self.rgbFlags, self.uid, nid_bytes = struct.unpack(
            '4s16s4s', value_bytes)
        self.nid = NID(nid_bytes)

    def __repr__(self) -> str:

        return f'EntryID {self.nid}'


class SubFolder:

    nid: NID
    name: str
    parent_path: str

    def __init__(self, nid: NID, name: str, parent_path: str) -> None:

        self.nid = nid
        self.name = name
        self.parent_path = parent_path

    def __repr__(self) -> str:

        return f'{self.name} ({self.nid})'


class SubMessage:

    def __init__(self, nid: NID, SentRepresentingName: str, Subject: str, ClientSubmitTime: dt.datetime) -> None:

        self.nid: NID = nid
        self.SentRepresentingName: str = SentRepresentingName
        self.Subject: str = Subject
        self.ClientSubmitTime: dt.datetime = ClientSubmitTime

    def __repr__(self) -> str:

        return f'{self.Subject} ({self.nid})'


class Folder:

    pc: PC
    nidType: int
    DisplayName: str
    path: str
    EntryId: bytes
    ContentCount: int
    ContainerClass: str
    HasSubfolders: bool
    tc_contents: Optional[TC]
    tc_hierarchy: Optional[TC]
    tc_fai: Optional[TC]
    subfolders: list[SubFolder]
    submessages: list[SubMessage]

    def __init__(self, nid: NID, ltp: LTP, parent_path='', messaging: Optional['Messaging'] = None) -> None:

        if nid.nidType != NID.NID_TYPE_NORMAL_FOLDER:
            raise PSTException('Invalid Folder NID Type: %s' % nid.nidType)
        self.pc = ltp.get_pc_by_nid(nid)
        self.DisplayName = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagDisplayName).value)
        self.path = parent_path + '\\' + self.DisplayName

        # print('FOLDER DEBUG', self.DisplayName, self.pc)

        # entryids in PST are stored as nids
        if messaging:
            self.EntryId = 4 * b'\x00' + \
                messaging.store_record_key + struct.pack('I', nid.nid)

        self.ContentCount = panutils.to_int(self.pc.getval(
            PropIdEnum.PidTagContentCount).value)
        self.ContainerClass = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagContainerClass).value)
        self.HasSubfolders = panutils.to_int(self.pc.getval(
            PropIdEnum.PidTagSubfolders).value) == 1

        nid_hierarchy: NID = NID(nid.nidIndex | NID.NID_TYPE_HIERARCHY_TABLE)
        nid_contents: NID = NID(nid.nidIndex | NID.NID_TYPE_CONTENTS_TABLE)
        # FAI = Folder Associated Information
        nid_fai: NID = NID(nid.nidIndex | NID.NID_TYPE_ASSOC_CONTENTS_TABLE)

        try:
            self.tc_hierarchy = None
            self.subfolders = []
            self.tc_hierarchy = ltp.get_tc_by_nid(nid_hierarchy)
            self.subfolders = [SubFolder(self.tc_hierarchy.RowIndex[RowIndex].nid, panutils.to_str(self.tc_hierarchy.getval(
                RowIndex, PropIdEnum.PidTagDisplayName)), self.path) for RowIndex in range(len(self.tc_hierarchy.RowIndex))]
        except PSTException as e:
            log_error(e)

        try:
            self.tc_contents = None
            self.submessages = []
            self.tc_contents = ltp.get_tc_by_nid(nid_contents)
            self.submessages = [SubMessage(self.tc_contents.RowIndex[RowIndex].nid,
                                           panutils.to_str(self.tc_contents.getval(
                                               RowIndex, PropIdEnum.PidTagSentRepresentingNameW)),
                                           ltp.strip_SubjectPrefix(
                                               panutils.to_str(self.tc_contents.getval(RowIndex, PropIdEnum.PidTagSubjectW))),
                                           panutils.datetime_from_filetime_bytes(panutils.to_binary(self.tc_contents.getval(RowIndex, PropIdEnum.PidTagClientSubmitTime))))
                                for RowIndex in range(len(self.tc_contents.RowIndex)) if RowIndex in list(self.tc_contents.RowIndex.keys())]
        except PSTException as e:
            log_error(e)

        try:
            self.tc_fai = None
            self.tc_fai = ltp.get_tc_by_nid(nid_fai)
        except PSTException as e:
            log_error(e)

    def __repr__(self) -> str:

        return 'Folder: %s, submessages: %s, subfolders: %s' % (self.DisplayName, len(self.submessages), self.subfolders)


class SubAttachment:
    nid: NID
    AttachmentSize: int
    AttachFilename: str
    AttachLongFilename: Optional[str]
    Filename: Optional[str]

    def __init__(self, nid: NID, AttachmentSize: int, AttachFilename: str, AttachLongFilename: Optional[str]) -> None:

        self.nid, self.AttachmentSize, self.AttachFilename, self.AttachLongFilename = nid, AttachmentSize, AttachFilename, AttachLongFilename
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = '[None]'

    def __repr__(self) -> str:

        return f'{self.Filename} ({panutils.size_friendly(self.AttachmentSize)})'


class SubRecipient:
    RecipientType: int
    DisplayName: str
    ObjectType: int
    AddressType: int
    EmailAddress: str
    DisplayType: int
    EntryId: 'EntryID'

    def __init__(self, RecipientType: int, DisplayName: str, ObjectType: int, AddressType: int, EmailAddress: str, DisplayType: int, EntryId: 'EntryID') -> None:

        self.RecipientType, self.DisplayName, self.ObjectType, self.AddressType, self.EmailAddress, self.DisplayType, self.EntryId = RecipientType, DisplayName, ObjectType, AddressType, EmailAddress, DisplayType, EntryId

    def __repr__(self) -> str:

        return f'{self.DisplayName} ({self.EmailAddress})'


class Message:

    mfRead = 0x01
    mfUnsent = 0x08
    mfUnmodified = 0x02
    mfHasAttach = 0x10
    mfFromMe = 0x20
    mfFAI = 0x40
    mfNotifyRead = 0x100
    mfNotifyUnread = 0x200
    mfInternet = 0x2000

    afByValue = 0x01
    afEmbeddedMessage = 0x05
    afStorage = 0x06

    hn: HN
    pc: PC
    ltp: LTP
    EntryId: bytes
    tc_attachments: Optional[TC]
    tc_recipients: Optional[TC]
    subrecipients: list[SubRecipient]
    subattachments: list[SubAttachment]

    def __init__(self, nid: NID, ltp: LTP, nbd: Optional[NBD] = None, parent_message: Optional['Message'] = None, messaging: Optional['Messaging'] = None) -> None:

        self.ltp = ltp

        if parent_message and parent_message.pc.hn.subnodes and nbd:
            subnode: SLENTRY = parent_message.pc.hn.subnodes[nid.nid]
            block_data_list: list[bytes] = nbd.fetch_all_block_data(
                subnode.bidData)
            # TODO: Solve HN with SLENTRY parameter
            hn: HN = HN(subnode, ltp, block_data_list)
            self.pc = PC(hn)
        else:
            if nid.nidType != NID.NID_TYPE_NORMAL_MESSAGE:
                raise PSTException(
                    'Invalid Message NID Type: %s' % nid.nidType)
            self.pc = ltp.get_pc_by_nid(nid)

        # entryids in PST are stored as nids
        if messaging:
            self.EntryId = 4 * b'\x00' + \
                messaging.store_record_key + struct.pack('I', nid.nid)

        self.MessageClass: str = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagMessageClassW).value)
        self.Subject: str = ltp.strip_SubjectPrefix(
            panutils.to_str(self.pc.getval(PropIdEnum.PidTagSubjectW).value))
        self.ClientSubmitTime: dt.datetime = panutils.datetime_from_filetime_bytes(panutils.to_binary(self.pc.getval(
            PropIdEnum.PidTagClientSubmitTime).value))
        self.SentRepresentingName: str = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagSentRepresentingNameW).value)
        self.SenderName: str = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagSenderName).value)
        self.SenderSmtpAddress: str = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagSenderSmtpAddress).value)
        self.MessageDeliveryTime: dt.datetime = panutils.datetime_from_filetime_bytes(panutils.to_binary(self.pc.getval(
            PropIdEnum.PidTagMessageDeliveryTime).value))
        self.MessageFlags: int = panutils.to_int(self.pc.getval(
            PropIdEnum.PidTagMessageFlags).value)
        self.MessageStatus: int = panutils.to_int(self.pc.getval(
            PropIdEnum.PidTagMessageStatus).value)
        self.HasAttachments: bool = (
            self.MessageFlags & Message.mfHasAttach == Message.mfHasAttach)
        self.MessageSize: int = panutils.to_int(self.pc.getval(
            PropIdEnum.PidTagMessageSize).value)
        self.Body = panutils.to_str(
            self.pc.getval(PropIdEnum.PidTagBody).value)
        self.Read = (self.MessageFlags & Message.mfRead == Message.mfRead)
        self.TransportMessageHeaders = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagTransportMessageHeaders).value)
        self.DisplayTo = panutils.to_str(
            self.pc.getval(PropIdEnum.PidTagDisplayToW).value)
        self.XOriginatingIP = panutils.to_str(self.pc.getval(
            PropIdEnum(0x8028)).value)  # x-originating-ip

        self.tc_attachments = None
        self.tc_recipients = None
        if self.pc.hn.subnodes:
            for subnode in list(self.pc.hn.subnodes.values()):  # SLENTRYs
                if subnode.nid.nidType == NID.NID_TYPE_ATTACHMENT_TABLE:
                    self.tc_attachments = self.ltp.get_tc_by_slentry(subnode)
                elif subnode.nid.nidType == NID.NID_TYPE_RECIPIENT_TABLE:
                    self.tc_recipients = ltp.get_tc_by_slentry(subnode)

        self.subattachments = []
        if self.tc_attachments:
            self.subattachments = [SubAttachment(self.tc_attachments.RowIndex[RowIndex].nid, panutils.to_int(self.tc_attachments.getval(RowIndex, PropIdEnum.PidTagAttachmentSize)),
                                                 panutils.to_str(self.tc_attachments.getval(RowIndex, PropIdEnum.PidTagAttachFilename)), panutils.to_str(self.tc_attachments.getval(RowIndex, PropIdEnum.PidTagAttachLongFilename))) for RowIndex in range(len(self.tc_attachments.RowIndex))]

        self.subrecipients = []
        if self.tc_recipients:
            self.subrecipients = [SubRecipient(
                panutils.to_int(self.tc_recipients.getval(
                    RowIndex, PropIdEnum.PidTagRecipientType)),
                panutils.to_str(self.tc_recipients.getval(
                    RowIndex, PropIdEnum.PidTagDisplayName)),
                panutils.to_int(self.tc_recipients.getval(
                    RowIndex, PropIdEnum.PidTagObjectType)),
                panutils.to_int(self.tc_recipients.getval(
                    RowIndex, PropIdEnum.PidTagAddressType)),
                panutils.to_str(self.tc_recipients.getval(
                    RowIndex, PropIdEnum.PidTagEmailAddress)),
                panutils.to_int(self.tc_recipients.getval(
                    RowIndex, PropIdEnum.PidTagDisplayType)),
                EntryID(panutils.to_binary(self.tc_recipients.getval(
                    RowIndex, PropIdEnum.PidTagEntryID)))
            ) for RowIndex in range(len(self.tc_recipients.RowIndex))]

    def get_attachment(self, subattachment: SubAttachment) -> Optional['Attachment']:
        """ fetch attachment on demand, not when Message instanced"""
        if self.pc.hn.subnodes:
            return Attachment(self.ltp, self.pc.hn.subnodes[subattachment.nid.nid])
        return None

    def get_all_properties(self) -> str:

        return self.pc.__repr__()

    def __repr__(self) -> str:

        attachments: str = ', '.join(
            ['%s' % subattachment for subattachment in self.subattachments])
        return 'Message: %s, From: %s, %s, Size: %s, Attachments: %s' % (repr(self.Subject), repr(self.SentRepresentingName), self.ClientSubmitTime, panutils.size_friendly(self.MessageSize), attachments)


class Attachment:

    def __init__(self, ltp: LTP, slentry: SLENTRY) -> None:

        self.ltp = ltp
        self.slentry = slentry
        self.pc = self.ltp.get_pc_by_slentry(slentry)

        self.DisplayName = panutils.to_str(
            self.pc.getval(PropIdEnum.PidTagDisplayName).value)
        self.AttachMethod = self.pc.getval(PropIdEnum.PidTagAttachMethod)
        self.AttachmentSize = self.pc.getval(PropIdEnum.PidTagAttachmentSize)
        self.AttachFilename = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagAttachFilename).value)  # 8.3 short name
        self.AttachLongFilename = panutils.to_str(self.pc.getval(
            PropIdEnum.PidTagAttachLongFilename).value)
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = '[NoFilename_Method%s]' % self.AttachMethod

        if self.AttachMethod == Message.afByValue:
            self.data = panutils.to_binary(self.pc.getval(
                PropIdEnum.PidTagAttachDataBinary).value)
        else:
            self.data = panutils.to_binary(self.pc.getval(
                PropIdEnum.PidTagAttachDataObject).value)
            # raise PSTException('Unsupported Attachment Method %s' % self.AttachMethod)
        self.AttachMimeTag = self.pc.getval(PropIdEnum.PidTagAttachMimeTag)
        self.AttachExtension = self.pc.getval(PropIdEnum.PidTagAttachExtension)

    def get_all_properties(self) -> str:

        return self.pc.__repr__()


class NAMEID:

    name: Optional[str]
    guid: Optional[bytes]
    dwPropertyID: int
    wGuid: int
    wPropIdx: int
    N: int
    NPID: int

    def __init__(self, value_bytes: bytes) -> None:

        property_id, guid, prop_idx = struct.unpack(
            'IHH', value_bytes)

        if not isinstance(property_id, int):
            raise TypeError(property_id)
        if not isinstance(guid, int):
            raise TypeError(guid)
        if not isinstance(prop_idx, int):
            raise TypeError(prop_idx)

        self.dwPropertyID = property_id
        self.N = guid & 0x01
        self.wGuid = guid >> 1
        self.wPropIdx = prop_idx
        self.NPID = prop_idx + 0x8000


class Messaging:
    """Messaging Layer"""

    PasswordCRC32Hash: Optional[int]
    nameid_entries: list[NAMEID]
    ltp: LTP
    message_store: PC
    store_record_key: bytes

    def __init__(self, ltp: LTP) -> None:

        self.ltp = ltp
        self.set_message_store()
        try:
            self.set_name_to_id_map()
        except PSTException as e:
            log_error(e)

    def set_message_store(self) -> None:

        self.message_store = self.ltp.get_pc_by_nid(NID(NID.NID_MESSAGE_STORE))
        self.store_record_key = panutils.to_binary(self.message_store.getval(
            PropIdEnum.PidTagRecordKey).value)  # binary

        if PropIdEnum.PidTagPstPassword in self.message_store.properties.keys():
            self.PasswordCRC32Hash = struct.unpack('I', struct.pack(
                'i', panutils.to_str(self.message_store.getval(PropIdEnum.PidTagPstPassword).value)))[0]
        else:
            self.PasswordCRC32Hash = None
        self.root_entryid: bytes = panutils.to_binary(self.message_store.getval(
            PropIdEnum.PidTagIpmSubTreeEntryId).value)
        self.deleted_items_entryid: bytes = panutils.to_binary(self.message_store.getval(
            PropIdEnum.PidTagIpmWastebasketEntryId).value)

    def set_name_to_id_map(self) -> None:

        self.nameid_entries = []
        self.pc_name_to_id_map: PC = self.ltp.get_pc_by_nid(
            NID(NID.NID_NAME_TO_ID_MAP))

        nameid_entrystream: bytes = panutils.to_binary(self.pc_name_to_id_map.getval(
            PropIdEnum.PidTagNameidStreamEntry).value)
        if nameid_entrystream:
            self.nameid_entries = [NAMEID(nameid_entrystream[i * 8:(i + 1) * 8])
                                   for i in range(len(nameid_entrystream) // 8)]
            nameid_stringstream: bytes = panutils.to_binary(self.pc_name_to_id_map.getval(
                PropIdEnum.PidTagNameidStreamString).value)
            nameid_guidstream: bytes = panutils.to_binary(self.pc_name_to_id_map.getval(
                PropIdEnum.PidTagNameidStreamGuid).value)
            if nameid_stringstream and nameid_guidstream:

                for nameid in self.nameid_entries:
                    if nameid.N == 1:
                        name_len: int = panutils.unpack_integer(
                            'I', nameid_stringstream[nameid.dwPropertyID:nameid.dwPropertyID + 4])
                        name_bytes: bytes = nameid_stringstream[nameid.dwPropertyID +
                                                                4: nameid.dwPropertyID + 4 + name_len]
                        name_str: str = name_bytes.decode(
                            'utf-16-le')  # unicode
                        nameid.name = name_str
                    if nameid.wGuid == 0:
                        nameid.guid = None
                    elif nameid.wGuid == 1:  # PS_MAPI
                        nameid.guid = b'(\x03\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F'
                    elif nameid.wGuid == 2:  # PS_PUBLIC_STRINGS
                        nameid.guid = b')\x03\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F'
                    else:
                        nameid.guid = nameid_guidstream[16 *
                                                        (nameid.wGuid - 3):16 * (nameid.wGuid - 2)]

    def get_folder(self, entryid, parent_path='') -> Folder:

        return Folder(entryid.nid, self.ltp, parent_path, self)

    def get_named_properties(self) -> str:

        return '\n'.join(['%s = %s' % (hex(nameid.NPID), repr(nameid.name)) for nameid in self.nameid_entries if nameid.N == 1])


#############################################################################################################################
#  ____  ____ _____   _
# |  _ \/ ___|_   _| | |    __ _ _   _  ___ _ __
# | |_) \___ \ | |   | |   / _` | | | |/ _ \ '__|
# |  __/ ___) || |   | |__| (_| | |_| |  __/ |
# |_|   |____/ |_|   |_____\__,_|\__, |\___|_|
#                                |___/
#############################################################################################################################


class CRC:

    CrcTableOffset32 = (0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
                        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
                        0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
                        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
                        0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
                        0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
                        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
                        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
                        0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
                        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
                        0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
                        0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
                        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
                        0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
                        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
                        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
                        0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
                        0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
                        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
                        0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
                        0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
                        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
                        0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
                        0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
                        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
                        0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
                        0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
                        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
                        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
                        0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
                        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
                        0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D)

    CrcTableOffset40 = (0x00000000, 0x191B3141, 0x32366282, 0x2B2D53C3, 0x646CC504, 0x7D77F445, 0x565AA786, 0x4F4196C7,
                        0xC8D98A08, 0xD1C2BB49, 0xFAEFE88A, 0xE3F4D9CB, 0xACB54F0C, 0xB5AE7E4D, 0x9E832D8E, 0x87981CCF,
                        0x4AC21251, 0x53D92310, 0x78F470D3, 0x61EF4192, 0x2EAED755, 0x37B5E614, 0x1C98B5D7, 0x05838496,
                        0x821B9859, 0x9B00A918, 0xB02DFADB, 0xA936CB9A, 0xE6775D5D, 0xFF6C6C1C, 0xD4413FDF, 0xCD5A0E9E,
                        0x958424A2, 0x8C9F15E3, 0xA7B24620, 0xBEA97761, 0xF1E8E1A6, 0xE8F3D0E7, 0xC3DE8324, 0xDAC5B265,
                        0x5D5DAEAA, 0x44469FEB, 0x6F6BCC28, 0x7670FD69, 0x39316BAE, 0x202A5AEF, 0x0B07092C, 0x121C386D,
                        0xDF4636F3, 0xC65D07B2, 0xED705471, 0xF46B6530, 0xBB2AF3F7, 0xA231C2B6, 0x891C9175, 0x9007A034,
                        0x179FBCFB, 0x0E848DBA, 0x25A9DE79, 0x3CB2EF38, 0x73F379FF, 0x6AE848BE, 0x41C51B7D, 0x58DE2A3C,
                        0xF0794F05, 0xE9627E44, 0xC24F2D87, 0xDB541CC6, 0x94158A01, 0x8D0EBB40, 0xA623E883, 0xBF38D9C2,
                        0x38A0C50D, 0x21BBF44C, 0x0A96A78F, 0x138D96CE, 0x5CCC0009, 0x45D73148, 0x6EFA628B, 0x77E153CA,
                        0xBABB5D54, 0xA3A06C15, 0x888D3FD6, 0x91960E97, 0xDED79850, 0xC7CCA911, 0xECE1FAD2, 0xF5FACB93,
                        0x7262D75C, 0x6B79E61D, 0x4054B5DE, 0x594F849F, 0x160E1258, 0x0F152319, 0x243870DA, 0x3D23419B,
                        0x65FD6BA7, 0x7CE65AE6, 0x57CB0925, 0x4ED03864, 0x0191AEA3, 0x188A9FE2, 0x33A7CC21, 0x2ABCFD60,
                        0xAD24E1AF, 0xB43FD0EE, 0x9F12832D, 0x8609B26C, 0xC94824AB, 0xD05315EA, 0xFB7E4629, 0xE2657768,
                        0x2F3F79F6, 0x362448B7, 0x1D091B74, 0x04122A35, 0x4B53BCF2, 0x52488DB3, 0x7965DE70, 0x607EEF31,
                        0xE7E6F3FE, 0xFEFDC2BF, 0xD5D0917C, 0xCCCBA03D, 0x838A36FA, 0x9A9107BB, 0xB1BC5478, 0xA8A76539,
                        0x3B83984B, 0x2298A90A, 0x09B5FAC9, 0x10AECB88, 0x5FEF5D4F, 0x46F46C0E, 0x6DD93FCD, 0x74C20E8C,
                        0xF35A1243, 0xEA412302, 0xC16C70C1, 0xD8774180, 0x9736D747, 0x8E2DE606, 0xA500B5C5, 0xBC1B8484,
                        0x71418A1A, 0x685ABB5B, 0x4377E898, 0x5A6CD9D9, 0x152D4F1E, 0x0C367E5F, 0x271B2D9C, 0x3E001CDD,
                        0xB9980012, 0xA0833153, 0x8BAE6290, 0x92B553D1, 0xDDF4C516, 0xC4EFF457, 0xEFC2A794, 0xF6D996D5,
                        0xAE07BCE9, 0xB71C8DA8, 0x9C31DE6B, 0x852AEF2A, 0xCA6B79ED, 0xD37048AC, 0xF85D1B6F, 0xE1462A2E,
                        0x66DE36E1, 0x7FC507A0, 0x54E85463, 0x4DF36522, 0x02B2F3E5, 0x1BA9C2A4, 0x30849167, 0x299FA026,
                        0xE4C5AEB8, 0xFDDE9FF9, 0xD6F3CC3A, 0xCFE8FD7B, 0x80A96BBC, 0x99B25AFD, 0xB29F093E, 0xAB84387F,
                        0x2C1C24B0, 0x350715F1, 0x1E2A4632, 0x07317773, 0x4870E1B4, 0x516BD0F5, 0x7A468336, 0x635DB277,
                        0xCBFAD74E, 0xD2E1E60F, 0xF9CCB5CC, 0xE0D7848D, 0xAF96124A, 0xB68D230B, 0x9DA070C8, 0x84BB4189,
                        0x03235D46, 0x1A386C07, 0x31153FC4, 0x280E0E85, 0x674F9842, 0x7E54A903, 0x5579FAC0, 0x4C62CB81,
                        0x8138C51F, 0x9823F45E, 0xB30EA79D, 0xAA1596DC, 0xE554001B, 0xFC4F315A, 0xD7626299, 0xCE7953D8,
                        0x49E14F17, 0x50FA7E56, 0x7BD72D95, 0x62CC1CD4, 0x2D8D8A13, 0x3496BB52, 0x1FBBE891, 0x06A0D9D0,
                        0x5E7EF3EC, 0x4765C2AD, 0x6C48916E, 0x7553A02F, 0x3A1236E8, 0x230907A9, 0x0824546A, 0x113F652B,
                        0x96A779E4, 0x8FBC48A5, 0xA4911B66, 0xBD8A2A27, 0xF2CBBCE0, 0xEBD08DA1, 0xC0FDDE62, 0xD9E6EF23,
                        0x14BCE1BD, 0x0DA7D0FC, 0x268A833F, 0x3F91B27E, 0x70D024B9, 0x69CB15F8, 0x42E6463B, 0x5BFD777A,
                        0xDC656BB5, 0xC57E5AF4, 0xEE530937, 0xF7483876, 0xB809AEB1, 0xA1129FF0, 0x8A3FCC33, 0x9324FD72)

    CrcTableOffset48 = (0x00000000, 0x01C26A37, 0x0384D46E, 0x0246BE59, 0x0709A8DC, 0x06CBC2EB, 0x048D7CB2, 0x054F1685,
                        0x0E1351B8, 0x0FD13B8F, 0x0D9785D6, 0x0C55EFE1, 0x091AF964, 0x08D89353, 0x0A9E2D0A, 0x0B5C473D,
                        0x1C26A370, 0x1DE4C947, 0x1FA2771E, 0x1E601D29, 0x1B2F0BAC, 0x1AED619B, 0x18ABDFC2, 0x1969B5F5,
                        0x1235F2C8, 0x13F798FF, 0x11B126A6, 0x10734C91, 0x153C5A14, 0x14FE3023, 0x16B88E7A, 0x177AE44D,
                        0x384D46E0, 0x398F2CD7, 0x3BC9928E, 0x3A0BF8B9, 0x3F44EE3C, 0x3E86840B, 0x3CC03A52, 0x3D025065,
                        0x365E1758, 0x379C7D6F, 0x35DAC336, 0x3418A901, 0x3157BF84, 0x3095D5B3, 0x32D36BEA, 0x331101DD,
                        0x246BE590, 0x25A98FA7, 0x27EF31FE, 0x262D5BC9, 0x23624D4C, 0x22A0277B, 0x20E69922, 0x2124F315,
                        0x2A78B428, 0x2BBADE1F, 0x29FC6046, 0x283E0A71, 0x2D711CF4, 0x2CB376C3, 0x2EF5C89A, 0x2F37A2AD,
                        0x709A8DC0, 0x7158E7F7, 0x731E59AE, 0x72DC3399, 0x7793251C, 0x76514F2B, 0x7417F172, 0x75D59B45,
                        0x7E89DC78, 0x7F4BB64F, 0x7D0D0816, 0x7CCF6221, 0x798074A4, 0x78421E93, 0x7A04A0CA, 0x7BC6CAFD,
                        0x6CBC2EB0, 0x6D7E4487, 0x6F38FADE, 0x6EFA90E9, 0x6BB5866C, 0x6A77EC5B, 0x68315202, 0x69F33835,
                        0x62AF7F08, 0x636D153F, 0x612BAB66, 0x60E9C151, 0x65A6D7D4, 0x6464BDE3, 0x662203BA, 0x67E0698D,
                        0x48D7CB20, 0x4915A117, 0x4B531F4E, 0x4A917579, 0x4FDE63FC, 0x4E1C09CB, 0x4C5AB792, 0x4D98DDA5,
                        0x46C49A98, 0x4706F0AF, 0x45404EF6, 0x448224C1, 0x41CD3244, 0x400F5873, 0x4249E62A, 0x438B8C1D,
                        0x54F16850, 0x55330267, 0x5775BC3E, 0x56B7D609, 0x53F8C08C, 0x523AAABB, 0x507C14E2, 0x51BE7ED5,
                        0x5AE239E8, 0x5B2053DF, 0x5966ED86, 0x58A487B1, 0x5DEB9134, 0x5C29FB03, 0x5E6F455A, 0x5FAD2F6D,
                        0xE1351B80, 0xE0F771B7, 0xE2B1CFEE, 0xE373A5D9, 0xE63CB35C, 0xE7FED96B, 0xE5B86732, 0xE47A0D05,
                        0xEF264A38, 0xEEE4200F, 0xECA29E56, 0xED60F461, 0xE82FE2E4, 0xE9ED88D3, 0xEBAB368A, 0xEA695CBD,
                        0xFD13B8F0, 0xFCD1D2C7, 0xFE976C9E, 0xFF5506A9, 0xFA1A102C, 0xFBD87A1B, 0xF99EC442, 0xF85CAE75,
                        0xF300E948, 0xF2C2837F, 0xF0843D26, 0xF1465711, 0xF4094194, 0xF5CB2BA3, 0xF78D95FA, 0xF64FFFCD,
                        0xD9785D60, 0xD8BA3757, 0xDAFC890E, 0xDB3EE339, 0xDE71F5BC, 0xDFB39F8B, 0xDDF521D2, 0xDC374BE5,
                        0xD76B0CD8, 0xD6A966EF, 0xD4EFD8B6, 0xD52DB281, 0xD062A404, 0xD1A0CE33, 0xD3E6706A, 0xD2241A5D,
                        0xC55EFE10, 0xC49C9427, 0xC6DA2A7E, 0xC7184049, 0xC25756CC, 0xC3953CFB, 0xC1D382A2, 0xC011E895,
                        0xCB4DAFA8, 0xCA8FC59F, 0xC8C97BC6, 0xC90B11F1, 0xCC440774, 0xCD866D43, 0xCFC0D31A, 0xCE02B92D,
                        0x91AF9640, 0x906DFC77, 0x922B422E, 0x93E92819, 0x96A63E9C, 0x976454AB, 0x9522EAF2, 0x94E080C5,
                        0x9FBCC7F8, 0x9E7EADCF, 0x9C381396, 0x9DFA79A1, 0x98B56F24, 0x99770513, 0x9B31BB4A, 0x9AF3D17D,
                        0x8D893530, 0x8C4B5F07, 0x8E0DE15E, 0x8FCF8B69, 0x8A809DEC, 0x8B42F7DB, 0x89044982, 0x88C623B5,
                        0x839A6488, 0x82580EBF, 0x801EB0E6, 0x81DCDAD1, 0x8493CC54, 0x8551A663, 0x8717183A, 0x86D5720D,
                        0xA9E2D0A0, 0xA820BA97, 0xAA6604CE, 0xABA46EF9, 0xAEEB787C, 0xAF29124B, 0xAD6FAC12, 0xACADC625,
                        0xA7F18118, 0xA633EB2F, 0xA4755576, 0xA5B73F41, 0xA0F829C4, 0xA13A43F3, 0xA37CFDAA, 0xA2BE979D,
                        0xB5C473D0, 0xB40619E7, 0xB640A7BE, 0xB782CD89, 0xB2CDDB0C, 0xB30FB13B, 0xB1490F62, 0xB08B6555,
                        0xBBD72268, 0xBA15485F, 0xB853F606, 0xB9919C31, 0xBCDE8AB4, 0xBD1CE083, 0xBF5A5EDA, 0xBE9834ED)

    CrcTableOffset56 = (0x00000000, 0xB8BC6765, 0xAA09C88B, 0x12B5AFEE, 0x8F629757, 0x37DEF032, 0x256B5FDC, 0x9DD738B9,
                        0xC5B428EF, 0x7D084F8A, 0x6FBDE064, 0xD7018701, 0x4AD6BFB8, 0xF26AD8DD, 0xE0DF7733, 0x58631056,
                        0x5019579F, 0xE8A530FA, 0xFA109F14, 0x42ACF871, 0xDF7BC0C8, 0x67C7A7AD, 0x75720843, 0xCDCE6F26,
                        0x95AD7F70, 0x2D111815, 0x3FA4B7FB, 0x8718D09E, 0x1ACFE827, 0xA2738F42, 0xB0C620AC, 0x087A47C9,
                        0xA032AF3E, 0x188EC85B, 0x0A3B67B5, 0xB28700D0, 0x2F503869, 0x97EC5F0C, 0x8559F0E2, 0x3DE59787,
                        0x658687D1, 0xDD3AE0B4, 0xCF8F4F5A, 0x7733283F, 0xEAE41086, 0x525877E3, 0x40EDD80D, 0xF851BF68,
                        0xF02BF8A1, 0x48979FC4, 0x5A22302A, 0xE29E574F, 0x7F496FF6, 0xC7F50893, 0xD540A77D, 0x6DFCC018,
                        0x359FD04E, 0x8D23B72B, 0x9F9618C5, 0x272A7FA0, 0xBAFD4719, 0x0241207C, 0x10F48F92, 0xA848E8F7,
                        0x9B14583D, 0x23A83F58, 0x311D90B6, 0x89A1F7D3, 0x1476CF6A, 0xACCAA80F, 0xBE7F07E1, 0x06C36084,
                        0x5EA070D2, 0xE61C17B7, 0xF4A9B859, 0x4C15DF3C, 0xD1C2E785, 0x697E80E0, 0x7BCB2F0E, 0xC377486B,
                        0xCB0D0FA2, 0x73B168C7, 0x6104C729, 0xD9B8A04C, 0x446F98F5, 0xFCD3FF90, 0xEE66507E, 0x56DA371B,
                        0x0EB9274D, 0xB6054028, 0xA4B0EFC6, 0x1C0C88A3, 0x81DBB01A, 0x3967D77F, 0x2BD27891, 0x936E1FF4,
                        0x3B26F703, 0x839A9066, 0x912F3F88, 0x299358ED, 0xB4446054, 0x0CF80731, 0x1E4DA8DF, 0xA6F1CFBA,
                        0xFE92DFEC, 0x462EB889, 0x549B1767, 0xEC277002, 0x71F048BB, 0xC94C2FDE, 0xDBF98030, 0x6345E755,
                        0x6B3FA09C, 0xD383C7F9, 0xC1366817, 0x798A0F72, 0xE45D37CB, 0x5CE150AE, 0x4E54FF40, 0xF6E89825,
                        0xAE8B8873, 0x1637EF16, 0x048240F8, 0xBC3E279D, 0x21E91F24, 0x99557841, 0x8BE0D7AF, 0x335CB0CA,
                        0xED59B63B, 0x55E5D15E, 0x47507EB0, 0xFFEC19D5, 0x623B216C, 0xDA874609, 0xC832E9E7, 0x708E8E82,
                        0x28ED9ED4, 0x9051F9B1, 0x82E4565F, 0x3A58313A, 0xA78F0983, 0x1F336EE6, 0x0D86C108, 0xB53AA66D,
                        0xBD40E1A4, 0x05FC86C1, 0x1749292F, 0xAFF54E4A, 0x322276F3, 0x8A9E1196, 0x982BBE78, 0x2097D91D,
                        0x78F4C94B, 0xC048AE2E, 0xD2FD01C0, 0x6A4166A5, 0xF7965E1C, 0x4F2A3979, 0x5D9F9697, 0xE523F1F2,
                        0x4D6B1905, 0xF5D77E60, 0xE762D18E, 0x5FDEB6EB, 0xC2098E52, 0x7AB5E937, 0x680046D9, 0xD0BC21BC,
                        0x88DF31EA, 0x3063568F, 0x22D6F961, 0x9A6A9E04, 0x07BDA6BD, 0xBF01C1D8, 0xADB46E36, 0x15080953,
                        0x1D724E9A, 0xA5CE29FF, 0xB77B8611, 0x0FC7E174, 0x9210D9CD, 0x2AACBEA8, 0x38191146, 0x80A57623,
                        0xD8C66675, 0x607A0110, 0x72CFAEFE, 0xCA73C99B, 0x57A4F122, 0xEF189647, 0xFDAD39A9, 0x45115ECC,
                        0x764DEE06, 0xCEF18963, 0xDC44268D, 0x64F841E8, 0xF92F7951, 0x41931E34, 0x5326B1DA, 0xEB9AD6BF,
                        0xB3F9C6E9, 0x0B45A18C, 0x19F00E62, 0xA14C6907, 0x3C9B51BE, 0x842736DB, 0x96929935, 0x2E2EFE50,
                        0x2654B999, 0x9EE8DEFC, 0x8C5D7112, 0x34E11677, 0xA9362ECE, 0x118A49AB, 0x033FE645, 0xBB838120,
                        0xE3E09176, 0x5B5CF613, 0x49E959FD, 0xF1553E98, 0x6C820621, 0xD43E6144, 0xC68BCEAA, 0x7E37A9CF,
                        0xD67F4138, 0x6EC3265D, 0x7C7689B3, 0xC4CAEED6, 0x591DD66F, 0xE1A1B10A, 0xF3141EE4, 0x4BA87981,
                        0x13CB69D7, 0xAB770EB2, 0xB9C2A15C, 0x017EC639, 0x9CA9FE80, 0x241599E5, 0x36A0360B, 0x8E1C516E,
                        0x866616A7, 0x3EDA71C2, 0x2C6FDE2C, 0x94D3B949, 0x090481F0, 0xB1B8E695, 0xA30D497B, 0x1BB12E1E,
                        0x43D23E48, 0xFB6E592D, 0xE9DBF6C3, 0x516791A6, 0xCCB0A91F, 0x740CCE7A, 0x66B96194, 0xDE0506F1)

    CrcTableOffset64 = (0x00000000, 0x3D6029B0, 0x7AC05360, 0x47A07AD0, 0xF580A6C0, 0xC8E08F70, 0x8F40F5A0, 0xB220DC10,
                        0x30704BC1, 0x0D106271, 0x4AB018A1, 0x77D03111, 0xC5F0ED01, 0xF890C4B1, 0xBF30BE61, 0x825097D1,
                        0x60E09782, 0x5D80BE32, 0x1A20C4E2, 0x2740ED52, 0x95603142, 0xA80018F2, 0xEFA06222, 0xD2C04B92,
                        0x5090DC43, 0x6DF0F5F3, 0x2A508F23, 0x1730A693, 0xA5107A83, 0x98705333, 0xDFD029E3, 0xE2B00053,
                        0xC1C12F04, 0xFCA106B4, 0xBB017C64, 0x866155D4, 0x344189C4, 0x0921A074, 0x4E81DAA4, 0x73E1F314,
                        0xF1B164C5, 0xCCD14D75, 0x8B7137A5, 0xB6111E15, 0x0431C205, 0x3951EBB5, 0x7EF19165, 0x4391B8D5,
                        0xA121B886, 0x9C419136, 0xDBE1EBE6, 0xE681C256, 0x54A11E46, 0x69C137F6, 0x2E614D26, 0x13016496,
                        0x9151F347, 0xAC31DAF7, 0xEB91A027, 0xD6F18997, 0x64D15587, 0x59B17C37, 0x1E1106E7, 0x23712F57,
                        0x58F35849, 0x659371F9, 0x22330B29, 0x1F532299, 0xAD73FE89, 0x9013D739, 0xD7B3ADE9, 0xEAD38459,
                        0x68831388, 0x55E33A38, 0x124340E8, 0x2F236958, 0x9D03B548, 0xA0639CF8, 0xE7C3E628, 0xDAA3CF98,
                        0x3813CFCB, 0x0573E67B, 0x42D39CAB, 0x7FB3B51B, 0xCD93690B, 0xF0F340BB, 0xB7533A6B, 0x8A3313DB,
                        0x0863840A, 0x3503ADBA, 0x72A3D76A, 0x4FC3FEDA, 0xFDE322CA, 0xC0830B7A, 0x872371AA, 0xBA43581A,
                        0x9932774D, 0xA4525EFD, 0xE3F2242D, 0xDE920D9D, 0x6CB2D18D, 0x51D2F83D, 0x167282ED, 0x2B12AB5D,
                        0xA9423C8C, 0x9422153C, 0xD3826FEC, 0xEEE2465C, 0x5CC29A4C, 0x61A2B3FC, 0x2602C92C, 0x1B62E09C,
                        0xF9D2E0CF, 0xC4B2C97F, 0x8312B3AF, 0xBE729A1F, 0x0C52460F, 0x31326FBF, 0x7692156F, 0x4BF23CDF,
                        0xC9A2AB0E, 0xF4C282BE, 0xB362F86E, 0x8E02D1DE, 0x3C220DCE, 0x0142247E, 0x46E25EAE, 0x7B82771E,
                        0xB1E6B092, 0x8C869922, 0xCB26E3F2, 0xF646CA42, 0x44661652, 0x79063FE2, 0x3EA64532, 0x03C66C82,
                        0x8196FB53, 0xBCF6D2E3, 0xFB56A833, 0xC6368183, 0x74165D93, 0x49767423, 0x0ED60EF3, 0x33B62743,
                        0xD1062710, 0xEC660EA0, 0xABC67470, 0x96A65DC0, 0x248681D0, 0x19E6A860, 0x5E46D2B0, 0x6326FB00,
                        0xE1766CD1, 0xDC164561, 0x9BB63FB1, 0xA6D61601, 0x14F6CA11, 0x2996E3A1, 0x6E369971, 0x5356B0C1,
                        0x70279F96, 0x4D47B626, 0x0AE7CCF6, 0x3787E546, 0x85A73956, 0xB8C710E6, 0xFF676A36, 0xC2074386,
                        0x4057D457, 0x7D37FDE7, 0x3A978737, 0x07F7AE87, 0xB5D77297, 0x88B75B27, 0xCF1721F7, 0xF2770847,
                        0x10C70814, 0x2DA721A4, 0x6A075B74, 0x576772C4, 0xE547AED4, 0xD8278764, 0x9F87FDB4, 0xA2E7D404,
                        0x20B743D5, 0x1DD76A65, 0x5A7710B5, 0x67173905, 0xD537E515, 0xE857CCA5, 0xAFF7B675, 0x92979FC5,
                        0xE915E8DB, 0xD475C16B, 0x93D5BBBB, 0xAEB5920B, 0x1C954E1B, 0x21F567AB, 0x66551D7B, 0x5B3534CB,
                        0xD965A31A, 0xE4058AAA, 0xA3A5F07A, 0x9EC5D9CA, 0x2CE505DA, 0x11852C6A, 0x562556BA, 0x6B457F0A,
                        0x89F57F59, 0xB49556E9, 0xF3352C39, 0xCE550589, 0x7C75D999, 0x4115F029, 0x06B58AF9, 0x3BD5A349,
                        0xB9853498, 0x84E51D28, 0xC34567F8, 0xFE254E48, 0x4C059258, 0x7165BBE8, 0x36C5C138, 0x0BA5E888,
                        0x28D4C7DF, 0x15B4EE6F, 0x521494BF, 0x6F74BD0F, 0xDD54611F, 0xE03448AF, 0xA794327F, 0x9AF41BCF,
                        0x18A48C1E, 0x25C4A5AE, 0x6264DF7E, 0x5F04F6CE, 0xED242ADE, 0xD044036E, 0x97E479BE, 0xAA84500E,
                        0x4834505D, 0x755479ED, 0x32F4033D, 0x0F942A8D, 0xBDB4F69D, 0x80D4DF2D, 0xC774A5FD, 0xFA148C4D,
                        0x78441B9C, 0x4524322C, 0x028448FC, 0x3FE4614C, 0x8DC4BD5C, 0xB0A494EC, 0xF704EE3C, 0xCA64C78C)

    CrcTableOffset72 = (0x00000000, 0xCB5CD3A5, 0x4DC8A10B, 0x869472AE, 0x9B914216, 0x50CD91B3, 0xD659E31D, 0x1D0530B8,
                        0xEC53826D, 0x270F51C8, 0xA19B2366, 0x6AC7F0C3, 0x77C2C07B, 0xBC9E13DE, 0x3A0A6170, 0xF156B2D5,
                        0x03D6029B, 0xC88AD13E, 0x4E1EA390, 0x85427035, 0x9847408D, 0x531B9328, 0xD58FE186, 0x1ED33223,
                        0xEF8580F6, 0x24D95353, 0xA24D21FD, 0x6911F258, 0x7414C2E0, 0xBF481145, 0x39DC63EB, 0xF280B04E,
                        0x07AC0536, 0xCCF0D693, 0x4A64A43D, 0x81387798, 0x9C3D4720, 0x57619485, 0xD1F5E62B, 0x1AA9358E,
                        0xEBFF875B, 0x20A354FE, 0xA6372650, 0x6D6BF5F5, 0x706EC54D, 0xBB3216E8, 0x3DA66446, 0xF6FAB7E3,
                        0x047A07AD, 0xCF26D408, 0x49B2A6A6, 0x82EE7503, 0x9FEB45BB, 0x54B7961E, 0xD223E4B0, 0x197F3715,
                        0xE82985C0, 0x23755665, 0xA5E124CB, 0x6EBDF76E, 0x73B8C7D6, 0xB8E41473, 0x3E7066DD, 0xF52CB578,
                        0x0F580A6C, 0xC404D9C9, 0x4290AB67, 0x89CC78C2, 0x94C9487A, 0x5F959BDF, 0xD901E971, 0x125D3AD4,
                        0xE30B8801, 0x28575BA4, 0xAEC3290A, 0x659FFAAF, 0x789ACA17, 0xB3C619B2, 0x35526B1C, 0xFE0EB8B9,
                        0x0C8E08F7, 0xC7D2DB52, 0x4146A9FC, 0x8A1A7A59, 0x971F4AE1, 0x5C439944, 0xDAD7EBEA, 0x118B384F,
                        0xE0DD8A9A, 0x2B81593F, 0xAD152B91, 0x6649F834, 0x7B4CC88C, 0xB0101B29, 0x36846987, 0xFDD8BA22,
                        0x08F40F5A, 0xC3A8DCFF, 0x453CAE51, 0x8E607DF4, 0x93654D4C, 0x58399EE9, 0xDEADEC47, 0x15F13FE2,
                        0xE4A78D37, 0x2FFB5E92, 0xA96F2C3C, 0x6233FF99, 0x7F36CF21, 0xB46A1C84, 0x32FE6E2A, 0xF9A2BD8F,
                        0x0B220DC1, 0xC07EDE64, 0x46EAACCA, 0x8DB67F6F, 0x90B34FD7, 0x5BEF9C72, 0xDD7BEEDC, 0x16273D79,
                        0xE7718FAC, 0x2C2D5C09, 0xAAB92EA7, 0x61E5FD02, 0x7CE0CDBA, 0xB7BC1E1F, 0x31286CB1, 0xFA74BF14,
                        0x1EB014D8, 0xD5ECC77D, 0x5378B5D3, 0x98246676, 0x852156CE, 0x4E7D856B, 0xC8E9F7C5, 0x03B52460,
                        0xF2E396B5, 0x39BF4510, 0xBF2B37BE, 0x7477E41B, 0x6972D4A3, 0xA22E0706, 0x24BA75A8, 0xEFE6A60D,
                        0x1D661643, 0xD63AC5E6, 0x50AEB748, 0x9BF264ED, 0x86F75455, 0x4DAB87F0, 0xCB3FF55E, 0x006326FB,
                        0xF135942E, 0x3A69478B, 0xBCFD3525, 0x77A1E680, 0x6AA4D638, 0xA1F8059D, 0x276C7733, 0xEC30A496,
                        0x191C11EE, 0xD240C24B, 0x54D4B0E5, 0x9F886340, 0x828D53F8, 0x49D1805D, 0xCF45F2F3, 0x04192156,
                        0xF54F9383, 0x3E134026, 0xB8873288, 0x73DBE12D, 0x6EDED195, 0xA5820230, 0x2316709E, 0xE84AA33B,
                        0x1ACA1375, 0xD196C0D0, 0x5702B27E, 0x9C5E61DB, 0x815B5163, 0x4A0782C6, 0xCC93F068, 0x07CF23CD,
                        0xF6999118, 0x3DC542BD, 0xBB513013, 0x700DE3B6, 0x6D08D30E, 0xA65400AB, 0x20C07205, 0xEB9CA1A0,
                        0x11E81EB4, 0xDAB4CD11, 0x5C20BFBF, 0x977C6C1A, 0x8A795CA2, 0x41258F07, 0xC7B1FDA9, 0x0CED2E0C,
                        0xFDBB9CD9, 0x36E74F7C, 0xB0733DD2, 0x7B2FEE77, 0x662ADECF, 0xAD760D6A, 0x2BE27FC4, 0xE0BEAC61,
                        0x123E1C2F, 0xD962CF8A, 0x5FF6BD24, 0x94AA6E81, 0x89AF5E39, 0x42F38D9C, 0xC467FF32, 0x0F3B2C97,
                        0xFE6D9E42, 0x35314DE7, 0xB3A53F49, 0x78F9ECEC, 0x65FCDC54, 0xAEA00FF1, 0x28347D5F, 0xE368AEFA,
                        0x16441B82, 0xDD18C827, 0x5B8CBA89, 0x90D0692C, 0x8DD55994, 0x46898A31, 0xC01DF89F, 0x0B412B3A,
                        0xFA1799EF, 0x314B4A4A, 0xB7DF38E4, 0x7C83EB41, 0x6186DBF9, 0xAADA085C, 0x2C4E7AF2, 0xE712A957,
                        0x15921919, 0xDECECABC, 0x585AB812, 0x93066BB7, 0x8E035B0F, 0x455F88AA, 0xC3CBFA04, 0x089729A1,
                        0xF9C19B74, 0x329D48D1, 0xB4093A7F, 0x7F55E9DA, 0x6250D962, 0xA90C0AC7, 0x2F987869, 0xE4C4ABCC)

    CrcTableOffset80 = (0x00000000, 0xA6770BB4, 0x979F1129, 0x31E81A9D, 0xF44F2413, 0x52382FA7, 0x63D0353A, 0xC5A73E8E,
                        0x33EF4E67, 0x959845D3, 0xA4705F4E, 0x020754FA, 0xC7A06A74, 0x61D761C0, 0x503F7B5D, 0xF64870E9,
                        0x67DE9CCE, 0xC1A9977A, 0xF0418DE7, 0x56368653, 0x9391B8DD, 0x35E6B369, 0x040EA9F4, 0xA279A240,
                        0x5431D2A9, 0xF246D91D, 0xC3AEC380, 0x65D9C834, 0xA07EF6BA, 0x0609FD0E, 0x37E1E793, 0x9196EC27,
                        0xCFBD399C, 0x69CA3228, 0x582228B5, 0xFE552301, 0x3BF21D8F, 0x9D85163B, 0xAC6D0CA6, 0x0A1A0712,
                        0xFC5277FB, 0x5A257C4F, 0x6BCD66D2, 0xCDBA6D66, 0x081D53E8, 0xAE6A585C, 0x9F8242C1, 0x39F54975,
                        0xA863A552, 0x0E14AEE6, 0x3FFCB47B, 0x998BBFCF, 0x5C2C8141, 0xFA5B8AF5, 0xCBB39068, 0x6DC49BDC,
                        0x9B8CEB35, 0x3DFBE081, 0x0C13FA1C, 0xAA64F1A8, 0x6FC3CF26, 0xC9B4C492, 0xF85CDE0F, 0x5E2BD5BB,
                        0x440B7579, 0xE27C7ECD, 0xD3946450, 0x75E36FE4, 0xB044516A, 0x16335ADE, 0x27DB4043, 0x81AC4BF7,
                        0x77E43B1E, 0xD19330AA, 0xE07B2A37, 0x460C2183, 0x83AB1F0D, 0x25DC14B9, 0x14340E24, 0xB2430590,
                        0x23D5E9B7, 0x85A2E203, 0xB44AF89E, 0x123DF32A, 0xD79ACDA4, 0x71EDC610, 0x4005DC8D, 0xE672D739,
                        0x103AA7D0, 0xB64DAC64, 0x87A5B6F9, 0x21D2BD4D, 0xE47583C3, 0x42028877, 0x73EA92EA, 0xD59D995E,
                        0x8BB64CE5, 0x2DC14751, 0x1C295DCC, 0xBA5E5678, 0x7FF968F6, 0xD98E6342, 0xE86679DF, 0x4E11726B,
                        0xB8590282, 0x1E2E0936, 0x2FC613AB, 0x89B1181F, 0x4C162691, 0xEA612D25, 0xDB8937B8, 0x7DFE3C0C,
                        0xEC68D02B, 0x4A1FDB9F, 0x7BF7C102, 0xDD80CAB6, 0x1827F438, 0xBE50FF8C, 0x8FB8E511, 0x29CFEEA5,
                        0xDF879E4C, 0x79F095F8, 0x48188F65, 0xEE6F84D1, 0x2BC8BA5F, 0x8DBFB1EB, 0xBC57AB76, 0x1A20A0C2,
                        0x8816EAF2, 0x2E61E146, 0x1F89FBDB, 0xB9FEF06F, 0x7C59CEE1, 0xDA2EC555, 0xEBC6DFC8, 0x4DB1D47C,
                        0xBBF9A495, 0x1D8EAF21, 0x2C66B5BC, 0x8A11BE08, 0x4FB68086, 0xE9C18B32, 0xD82991AF, 0x7E5E9A1B,
                        0xEFC8763C, 0x49BF7D88, 0x78576715, 0xDE206CA1, 0x1B87522F, 0xBDF0599B, 0x8C184306, 0x2A6F48B2,
                        0xDC27385B, 0x7A5033EF, 0x4BB82972, 0xEDCF22C6, 0x28681C48, 0x8E1F17FC, 0xBFF70D61, 0x198006D5,
                        0x47ABD36E, 0xE1DCD8DA, 0xD034C247, 0x7643C9F3, 0xB3E4F77D, 0x1593FCC9, 0x247BE654, 0x820CEDE0,
                        0x74449D09, 0xD23396BD, 0xE3DB8C20, 0x45AC8794, 0x800BB91A, 0x267CB2AE, 0x1794A833, 0xB1E3A387,
                        0x20754FA0, 0x86024414, 0xB7EA5E89, 0x119D553D, 0xD43A6BB3, 0x724D6007, 0x43A57A9A, 0xE5D2712E,
                        0x139A01C7, 0xB5ED0A73, 0x840510EE, 0x22721B5A, 0xE7D525D4, 0x41A22E60, 0x704A34FD, 0xD63D3F49,
                        0xCC1D9F8B, 0x6A6A943F, 0x5B828EA2, 0xFDF58516, 0x3852BB98, 0x9E25B02C, 0xAFCDAAB1, 0x09BAA105,
                        0xFFF2D1EC, 0x5985DA58, 0x686DC0C5, 0xCE1ACB71, 0x0BBDF5FF, 0xADCAFE4B, 0x9C22E4D6, 0x3A55EF62,
                        0xABC30345, 0x0DB408F1, 0x3C5C126C, 0x9A2B19D8, 0x5F8C2756, 0xF9FB2CE2, 0xC813367F, 0x6E643DCB,
                        0x982C4D22, 0x3E5B4696, 0x0FB35C0B, 0xA9C457BF, 0x6C636931, 0xCA146285, 0xFBFC7818, 0x5D8B73AC,
                        0x03A0A617, 0xA5D7ADA3, 0x943FB73E, 0x3248BC8A, 0xF7EF8204, 0x519889B0, 0x6070932D, 0xC6079899,
                        0x304FE870, 0x9638E3C4, 0xA7D0F959, 0x01A7F2ED, 0xC400CC63, 0x6277C7D7, 0x539FDD4A, 0xF5E8D6FE,
                        0x647E3AD9, 0xC209316D, 0xF3E12BF0, 0x55962044, 0x90311ECA, 0x3646157E, 0x07AE0FE3, 0xA1D90457,
                        0x579174BE, 0xF1E67F0A, 0xC00E6597, 0x66796E23, 0xA3DE50AD, 0x05A95B19, 0x34414184, 0x92364A30)

    CrcTableOffset88 = (0x00000000, 0xCCAA009E, 0x4225077D, 0x8E8F07E3, 0x844A0EFA, 0x48E00E64, 0xC66F0987, 0x0AC50919,
                        0xD3E51BB5, 0x1F4F1B2B, 0x91C01CC8, 0x5D6A1C56, 0x57AF154F, 0x9B0515D1, 0x158A1232, 0xD92012AC,
                        0x7CBB312B, 0xB01131B5, 0x3E9E3656, 0xF23436C8, 0xF8F13FD1, 0x345B3F4F, 0xBAD438AC, 0x767E3832,
                        0xAF5E2A9E, 0x63F42A00, 0xED7B2DE3, 0x21D12D7D, 0x2B142464, 0xE7BE24FA, 0x69312319, 0xA59B2387,
                        0xF9766256, 0x35DC62C8, 0xBB53652B, 0x77F965B5, 0x7D3C6CAC, 0xB1966C32, 0x3F196BD1, 0xF3B36B4F,
                        0x2A9379E3, 0xE639797D, 0x68B67E9E, 0xA41C7E00, 0xAED97719, 0x62737787, 0xECFC7064, 0x205670FA,
                        0x85CD537D, 0x496753E3, 0xC7E85400, 0x0B42549E, 0x01875D87, 0xCD2D5D19, 0x43A25AFA, 0x8F085A64,
                        0x562848C8, 0x9A824856, 0x140D4FB5, 0xD8A74F2B, 0xD2624632, 0x1EC846AC, 0x9047414F, 0x5CED41D1,
                        0x299DC2ED, 0xE537C273, 0x6BB8C590, 0xA712C50E, 0xADD7CC17, 0x617DCC89, 0xEFF2CB6A, 0x2358CBF4,
                        0xFA78D958, 0x36D2D9C6, 0xB85DDE25, 0x74F7DEBB, 0x7E32D7A2, 0xB298D73C, 0x3C17D0DF, 0xF0BDD041,
                        0x5526F3C6, 0x998CF358, 0x1703F4BB, 0xDBA9F425, 0xD16CFD3C, 0x1DC6FDA2, 0x9349FA41, 0x5FE3FADF,
                        0x86C3E873, 0x4A69E8ED, 0xC4E6EF0E, 0x084CEF90, 0x0289E689, 0xCE23E617, 0x40ACE1F4, 0x8C06E16A,
                        0xD0EBA0BB, 0x1C41A025, 0x92CEA7C6, 0x5E64A758, 0x54A1AE41, 0x980BAEDF, 0x1684A93C, 0xDA2EA9A2,
                        0x030EBB0E, 0xCFA4BB90, 0x412BBC73, 0x8D81BCED, 0x8744B5F4, 0x4BEEB56A, 0xC561B289, 0x09CBB217,
                        0xAC509190, 0x60FA910E, 0xEE7596ED, 0x22DF9673, 0x281A9F6A, 0xE4B09FF4, 0x6A3F9817, 0xA6959889,
                        0x7FB58A25, 0xB31F8ABB, 0x3D908D58, 0xF13A8DC6, 0xFBFF84DF, 0x37558441, 0xB9DA83A2, 0x7570833C,
                        0x533B85DA, 0x9F918544, 0x111E82A7, 0xDDB48239, 0xD7718B20, 0x1BDB8BBE, 0x95548C5D, 0x59FE8CC3,
                        0x80DE9E6F, 0x4C749EF1, 0xC2FB9912, 0x0E51998C, 0x04949095, 0xC83E900B, 0x46B197E8, 0x8A1B9776,
                        0x2F80B4F1, 0xE32AB46F, 0x6DA5B38C, 0xA10FB312, 0xABCABA0B, 0x6760BA95, 0xE9EFBD76, 0x2545BDE8,
                        0xFC65AF44, 0x30CFAFDA, 0xBE40A839, 0x72EAA8A7, 0x782FA1BE, 0xB485A120, 0x3A0AA6C3, 0xF6A0A65D,
                        0xAA4DE78C, 0x66E7E712, 0xE868E0F1, 0x24C2E06F, 0x2E07E976, 0xE2ADE9E8, 0x6C22EE0B, 0xA088EE95,
                        0x79A8FC39, 0xB502FCA7, 0x3B8DFB44, 0xF727FBDA, 0xFDE2F2C3, 0x3148F25D, 0xBFC7F5BE, 0x736DF520,
                        0xD6F6D6A7, 0x1A5CD639, 0x94D3D1DA, 0x5879D144, 0x52BCD85D, 0x9E16D8C3, 0x1099DF20, 0xDC33DFBE,
                        0x0513CD12, 0xC9B9CD8C, 0x4736CA6F, 0x8B9CCAF1, 0x8159C3E8, 0x4DF3C376, 0xC37CC495, 0x0FD6C40B,
                        0x7AA64737, 0xB60C47A9, 0x3883404A, 0xF42940D4, 0xFEEC49CD, 0x32464953, 0xBCC94EB0, 0x70634E2E,
                        0xA9435C82, 0x65E95C1C, 0xEB665BFF, 0x27CC5B61, 0x2D095278, 0xE1A352E6, 0x6F2C5505, 0xA386559B,
                        0x061D761C, 0xCAB77682, 0x44387161, 0x889271FF, 0x825778E6, 0x4EFD7878, 0xC0727F9B, 0x0CD87F05,
                        0xD5F86DA9, 0x19526D37, 0x97DD6AD4, 0x5B776A4A, 0x51B26353, 0x9D1863CD, 0x1397642E, 0xDF3D64B0,
                        0x83D02561, 0x4F7A25FF, 0xC1F5221C, 0x0D5F2282, 0x079A2B9B, 0xCB302B05, 0x45BF2CE6, 0x89152C78,
                        0x50353ED4, 0x9C9F3E4A, 0x121039A9, 0xDEBA3937, 0xD47F302E, 0x18D530B0, 0x965A3753, 0x5AF037CD,
                        0xFF6B144A, 0x33C114D4, 0xBD4E1337, 0x71E413A9, 0x7B211AB0, 0xB78B1A2E, 0x39041DCD, 0xF5AE1D53,
                        0x2C8E0FFF, 0xE0240F61, 0x6EAB0882, 0xA201081C, 0xA8C40105, 0x646E019B, 0xEAE10678, 0x264B06E6)

    @staticmethod
    def ComputeCRC(pv: bytes) -> int:
        """ from [MS-PST]. dwCRC is zero. pv is bytes to CRC. cbLength is length of pv """

        dwCRC: int = 0
        cbLength: int = len(pv)
        if cbLength < 4:
            cbRunningLength: int = 0
        else:
            cbRunningLength = (cbLength // 8) * 8
        cbEndUnalignedBytes: int = cbLength - cbRunningLength

        index: int = 0
        for _ in range(1, (cbRunningLength // 8) + 1):
            dwCRC ^= panutils.unpack_integer('I', pv[index:index + 4])
            dwCRC = CRC.CrcTableOffset88[dwCRC & 0x000000FF] ^ CRC.CrcTableOffset80[(dwCRC >> 8) & 0x000000FF] ^ CRC.CrcTableOffset72[(
                dwCRC >> 16) & 0x000000FF] ^ CRC.CrcTableOffset64[(dwCRC >> 24) & 0x000000FF]
            index += 4

            dw2nd32 = panutils.unpack_integer('I', pv[index:index + 4])
            dwCRC = dwCRC ^ CRC.CrcTableOffset56[dw2nd32 & 0x000000FF] ^ CRC.CrcTableOffset48[(
                dw2nd32 >> 8) & 0x000000FF] ^ CRC.CrcTableOffset40[(dw2nd32 >> 16) & 0x000000FF] ^ CRC.CrcTableOffset32[(dw2nd32 >> 24) & 0x000000FF]
            index += 4

        for i in range(1, cbEndUnalignedBytes + 1):
            dwCRC = CRC.CrcTableOffset32[(dwCRC ^ panutils.unpack_integer(
                'B', pv[index:index + 1])) & 0x000000FF] ^ (dwCRC >> 8)
            index += 1

        return dwCRC


class FieldSize(Enum):
    BYTE = 1
    WORD = 2
    DWORD = 4
    ANSIDWORD = 8


class Header:
    bCryptMethod: CryptMethodEnum

    def __init__(self, fd: BufferedReader) -> None:

        # common ansi/unicode fields
        fd.seek(0)
        self.dwMagic: bytes = fd.read(FieldSize.DWORD.value)
        self.dwCRCPartial: bytes = fd.read(FieldSize.DWORD.value)  # ignore
        self.wMagicClient: bytes = fd.read(FieldSize.WORD.value)

        try:
            self.wVer, self.wVerClient, self.bPlatformCreate, self.bPlatformAccess = struct.unpack(
                'HHBB', fd.read(FieldSize.WORD.value + FieldSize.WORD.value + FieldSize.BYTE.value + FieldSize.BYTE.value))
        except struct.error:
            self.validPST = False
            return

        self.dwReserved1 = fd.read(FieldSize.DWORD.value)  # ignore
        self.dwReserved2 = fd.read(FieldSize.DWORD.value)  # ignore

        self.validPST = (
            self.dwMagic == b'!BDN' and self.wMagicClient == b'SM')
        if not self.validPST:
            return
        self.is_ansi = (self.wVer in (14, 15))
        self.is_unicode = (self.wVer == 23)
        if not (self.is_ansi or self.is_unicode):
            self.validPST = False
            return

        if self.is_ansi:
            self.bidNextB = BID(fd.read(FieldSize.DWORD.value))
            self.bidNextP = BID(fd.read(FieldSize.DWORD.value))
            self.dwUnique = fd.read(FieldSize.DWORD.value)
            self.rgnid = struct.unpack(
                'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', fd.read(128))
            self.root = Root(fd.read(40), True)
            self.rgbFM = fd.read(128)  # unused
            self.rgbFP = fd.read(128)  # unused
            self.bSentinel, self.bCryptMethod = struct.unpack(
                'BB', fd.read(FieldSize.BYTE.value + FieldSize.BYTE.value))
            self.rgbReserved = fd.read(FieldSize.WORD.value)  # unused
            self.ullReserved = fd.read(8)  # unused
            self.dwReserved = fd.read(FieldSize.DWORD.value)  # unused
            self.rgbReserved2 = fd.read(3)  # unused
            self.bReserved = fd.read(1)  # unused
            self.rgbReserved3 = fd.read(32)  # unused

        if self.is_unicode:
            self.bidUnused = fd.read(FieldSize.ANSIDWORD.value)  # unused
            self.bidNextP = BID(fd.read(FieldSize.ANSIDWORD.value))
            # self.bidNextB = fd.read(FieldSize.ANSIDWORD.value) # the spec is wrong, example in appendix is correct
            self.dwUnique = fd.read(FieldSize.DWORD.value)  # ignore
            self.rgnid = struct.unpack(
                'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', fd.read(128))
            self.qwUnused = fd.read(FieldSize.ANSIDWORD.value)  # unused
            self.root = Root(fd.read(72), False)
            self.dwAlign = fd.read(FieldSize.DWORD.value)  # unused
            self.rgbFM = fd.read(128)  # unused
            self.rgbFP = fd.read(128)  # unused
            self.bSentinel, self.bCryptMethod = struct.unpack(
                'BB', fd.read(FieldSize.BYTE.value + FieldSize.BYTE.value))
            self.rgbReserved = fd.read(FieldSize.WORD.value)  # unused
            # repeated from above in spec
            self.bidNextB = BID(fd.read(FieldSize.ANSIDWORD.value))
            self.dwCRCFull = fd.read(FieldSize.DWORD.value)  # ignored
            self.rgbReserved2 = fd.read(3)  # unused
            self.bReserved = fd.read(1)  # unused
            self.rgbReserved3 = fd.read(32)  # unused


class Root:

    def __init__(self, value_bytes: bytes, is_ansi: bool) -> None:

        if is_ansi:  # 40
            self.ibFileEof, self.ibAMapLast, self.cbAMapFree, self.cbPMapFree, self.BREFNBT, self.BREFBBT, self.fAMapValid = \
                struct.unpack('IIII8s8sB', value_bytes[4:-3])
        else:  # unicode #72
            self.ibFileEof, self.ibAMapLast, self.cbAMapFree, self.cbPMapFree, self.BREFNBT, self.BREFBBT, self.fAMapValid = \
                struct.unpack('QQQQ16s16sB', value_bytes[4:-3])
        self.BREFNBT: BREF = BREF(self.BREFNBT)
        self.BREFBBT: BREF = BREF(self.BREFBBT)


class PST:
    nbd: NBD
    ltp: LTP
    messaging: Messaging
    fd: BufferedReader
    header: Header

    def __init__(self, pst_file: str) -> None:

        self.fd = open(pst_file, 'rb')
        self.header = Header(self.fd)
        if not self.header.validPST:
            raise PSTException('PST file is not a valid PST')

        # unencoded or NDB_CRYPT_PERMUTE
        if self.header.bCryptMethod == CryptMethodEnum.Unsupported:
            raise PSTException(
                'Unsupported encoding/crypt method %s' % self.header.bCryptMethod)

        self.nbd = NBD(self.fd, self.header)
        self.ltp = LTP(self.nbd)
        self.messaging = Messaging(self.ltp)

    def close(self) -> None:

        self.fd.close()

    def folder_generator(self):

        root_folder: Folder = self.messaging.get_folder(
            self.messaging.root_entryid, '')
        subfolder_stack: list[SubFolder] = root_folder.subfolders
        yield root_folder

        # Deleted Items should also be in root folder, so don't need to get this one
        # bin_folder = self.messaging.get_folder(self.messaging.deleted_items_entryid, '')
        # subfolder_stack.extend(bin_folder.subfolders)
        # yield bin_folder

        while subfolder_stack:
            subfolder: SubFolder = subfolder_stack.pop()
            try:
                folder: Folder = Folder(subfolder.nid, self.ltp,
                                        subfolder.parent_path, self.messaging)
                subfolder_stack.extend(folder.subfolders)
                yield folder
            except PSTException as e:
                log_error(e)

    def message_generator(self, folder):

        try:
            for submessage in folder.submessages:
                try:
                    message: Message = Message(submessage.nid, self.ltp,
                                               messaging=self.messaging)
                    yield message
                except PSTException as e:
                    log_error(e)
        except GeneratorExit:
            pass
        finally:
            pass

    def export_all_attachments(self, path='', progressbar=None, total_attachments=0, overwrite=True) -> None:
        """dumps all attachments in the PST to a path"""

        attachments_completed: int = 0
        for folder in self.folder_generator():
            for message in self.message_generator(folder):
                if message.HasAttachments:
                    for subattachment in message.subattachments:
                        attachment = message.get_attachment(
                            subattachment)
                        if attachment:
                            if len(attachment.data) != 0:
                                filepath: str = os.path.join(
                                    path, attachment.Filename)
                                if overwrite:
                                    if os.path.exists(filepath):
                                        os.remove(filepath)
                                else:
                                    filepath = get_unused_filename(filepath)
                                panutils.write_ascii_file(
                                    filepath, attachment.data, 'wb')
                            attachments_completed += 1
                            if progressbar:
                                progressbar.update(
                                    attachments_completed * 100.0 / total_attachments)

    def export_all_messages(self, path: str = '', progress_bar: Optional[progressbar.ProgressBar] = None, total_messages: int = 0) -> None:

        messages_completed: int = 0
        for folder in self.folder_generator():
            filepath: str = get_unused_filename(os.path.join(
                path, panutils.get_safe_filename(folder.path.replace('\\', '_')) + '.txt'))
            msg_txt: str = ''
            for message in self.message_generator(folder):
                msg_txt += 'Subject: %s\nFrom: %s (%s)\n' % (
                    message.Subject, message.SenderName, message.SenderSmtpAddress)
                msg_txt += 'To: %s\n' % ('; '.join(['%s (%s)' % (
                    subrecipient.DisplayName, subrecipient.EmailAddress) for subrecipient in message.subrecipients]))
                msg_txt += 'Sent: %s\nDelivered: %s\n' % (
                    message.ClientSubmitTime, message.MessageDeliveryTime)
                msg_txt += 'MessageClass: %s\n' % (message.MessageClass)
                if message.HasAttachments:
                    msg_txt += 'Attachments: %s\n' % (', '.join(
                        [subattachment.__repr__() for subattachment in message.subattachments]))
                msg_txt += '\n%s\n\n\n' % message.Body
            if msg_txt:
                panutils.write_ascii_file(
                    filepath, panutils.unicode2ascii(msg_txt), 'w')
                messages_completed += 1
                if progress_bar:
                    progress_bar.update(messages_completed *
                                        100.0 / total_messages)

    def get_total_message_count(self) -> int:

        total_message_count: int = 0
        for folder in self.folder_generator():
            total_message_count += len(folder.submessages)
        return total_message_count

    def get_total_attachment_count(self) -> int:

        total_attachment_count: int = 0
        for folder in self.folder_generator():
            for message in self.message_generator(folder):
                if message.HasAttachments:
                    total_attachment_count += len(message.subattachments)
        return total_attachment_count

    def get_pst_status(self) -> str:

        status: str = 'Valid PST: %s, Unicode: %s, CryptMethod: %s, Name: %s, Password: %s' % (
            self.header.validPST, self.header.is_unicode, self.header.bCryptMethod, self.messaging.message_store.getval(PropIdEnum.PidTagDisplayName), self.messaging.PasswordCRC32Hash)
        return status

    @staticmethod
    def bruteforce(charset, maxlength: int):

        return (''.join(candidate) for candidate in itertools.chain.from_iterable(itertools.product(charset, repeat=i) for i in range(1, maxlength + 1)))

    @staticmethod
    def crack_password(crc, dictionary_file: str = '') -> str:
        """either does a dictionary attack against the PST password CRC hash, or does a brute force of up to 4 chars"""

        if dictionary_file:
            dic_entries: list[str] = panutils.read_ascii_file(
                dictionary_file).split('\n')
            for password_check in dic_entries:
                crc_check: int = CRC.ComputeCRC(
                    password_check.strip().encode())
                if crc == crc_check:
                    return password_check
        else:  # brute force
            charset: str = string.ascii_lowercase + string.digits
            for password_length in range(1, 5):
                for password_check in PST.bruteforce(charset, password_length):
                    crc_check = CRC.ComputeCRC(password_check.encode())
                    if crc == crc_check:
                        return password_check
        return str()


###################################################################################################################################
#  _   _ _   _ _ _ _           _____                 _   _
# | | | | |_(_) (_) |_ _   _  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
# | | | | __| | | | __| | | | | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |_| | |_| | | | |_| |_| | |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#  \___/ \__|_|_|_|\__|\__, | |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#                      |___/
###################################################################################################################################

def get_unused_filename(filepath: str) -> str:
    """ adds numbered suffix to filepath if filename already exists"""

    if os.path.exists(filepath):
        suffix: int = 1
        while os.path.exists('%s-%s%s' % (os.path.splitext(filepath)[0], suffix, os.path.splitext(filepath)[1])):
            suffix += 1
        return '%s-%s%s' % (os.path.splitext(filepath)
                            [0], suffix, os.path.splitext(filepath)[1])
    return filepath


def log_error(e) -> None:

    # global error_log_list
    # error_log_list.append(e.message)
    # Implement a logging solution
    sys.stderr.write(e.message + '\n')


###############################################################################################################################
#
#  _____         _     _____                 _   _
# |_   _|__  ___| |_  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
#   | |/ _ \/ __| __| | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
#   | |  __/\__ \ |_  |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#   |_|\___||___/\__| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###############################################################################################################################


def test_status_pst(pst_filepath) -> None:

    pst = PST(pst_filepath)
    print((panutils.unicode2ascii(pst.get_pst_status())))
    print(('Total Messages: %s' % pst.get_total_message_count()))
    print(('Total Attachments: %s' % pst.get_total_attachment_count()))
    pst.close()


def get_simple_progressbar(title) -> progressbar.ProgressBar:

    pbar_widgets = [title, progressbar.Percentage(), ' ', progressbar.Bar(
        marker=progressbar.RotatingMarker()), ' ', progressbar.ETA()]
    return progressbar.ProgressBar(widgets=pbar_widgets).start()


def test_dump_pst(pst_filepath, output_path) -> None:
    """ dump out all PST email attachments and emails (into text files) to output_path folder"""

    pst = PST(pst_filepath)
    print((pst.get_pst_status()))

    pbar = get_simple_progressbar('Messages: ')
    total_messages = pst.get_total_message_count()
    pst.export_all_messages(output_path, pbar, total_messages)
    pbar.finish()

    pbar = get_simple_progressbar('Attachments: ')
    total_attachments = pst.get_total_attachment_count()
    pst.export_all_attachments(output_path, pbar, total_attachments)
    pbar.finish()

    pst.close()


def test_folder_psts(psts_folder):

    # global error_log_list

    s: str = ''
    for pst_filepath in [os.path.join(psts_folder, filename) for filename in os.listdir(psts_folder) if os.path.isfile(os.path.join(psts_folder, filename)) and os.path.splitext(filename.lower())[1] == '.pst']:
        try:
            s += 'Opening %s\n' % pst_filepath
            error_log_list = []
            pst = PST(pst_filepath)
            status: str = panutils.unicode2ascii(pst.get_pst_status())
            print(status)
            password: str = ''
            if pst.messaging.PasswordCRC32Hash:
                password = pst.crack_password(pst.messaging.PasswordCRC32Hash)
                if password:
                    password = ' (%s)' % password
            s += status + password + '\n'
            pst.close()
            s += '\n'.join(error_log_list)
            s += '\n\n\n'
        except Exception as e:
            s += 'ERROR: %s\n' % e

    panutils.write_ascii_file(os.path.join(psts_folder, 'psts_test.txt'), s)


###################################################################################################################################
#  __  __       _
# |  \/  | __ _(_)_ __
# | |\/| |/ _` | | '_ \
# | |  | | (_| | | | | |
# |_|  |_|\__,_|_|_| |_|
#
###################################################################################################################################


if __name__ == "__main__":

    input_pst_file = ''
    output_folder = 'dump'

    arg_parser = argparse.ArgumentParser(
        prog='pst', description='PST: parses PST files. Can dump emails and attachments.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-i', dest='input_pst_file',
                            default=input_pst_file, help='input PST file to dump')
    arg_parser.add_argument('-o', dest='output_folder',
                            default=output_folder, help='output folder')
    arg_parser.add_argument('-t', dest='debug', help=argparse.SUPPRESS,
                            action='store_true', default=False)  # hidden argument

    args = arg_parser.parse_args()

    if not args.debug:

        input_pst_file = args.input_pst_file
        output_folder = args.output_folder

        if not os.path.exists(input_pst_file):
            print('Input PST file does not exist')
            sys.exit(1)

        if not os.path.exists(output_folder):
            print('Output folder does not exist')
            sys.exit(1)

        test_dump_pst(input_pst_file, output_folder)

    else:  # debug

        pass
        # test_folder = 'D:\\'
        # test_status_pst(test_folder+'sample.pst')
        # test_dump_pst(test_folder+'sample.pst', test_folder+'dump')
        # test_folder_psts(test_folder)
