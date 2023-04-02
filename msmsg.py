#! /usr/bin/env python
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# By BB
# based on MS-OXMSG and MS-CFB Microsoft specification for MSG file format [MS-OXMSG].pdf v20140130
#

import datetime as dt
import os
import struct
from io import BufferedReader
from typing import TYPE_CHECKING, Optional, TypeAlias, Union
from exceptions import MSGException

import panutils
from panutils import write_ascii_file, write_unicode_file
from PropIdEnum import PropIdEnum
from PType import PType
from PTypeEnum import PTypeEnum

TYPE_CHECKING = True
if TYPE_CHECKING:
    from _typeshed import FileDescriptorOrPath

_FilePathOrFileObject: TypeAlias = FileDescriptorOrPath | BufferedReader
_ValueType = Optional[Union[int, float, dt.datetime, bool, str,
                            bytes, list[int], list[float], list[dt.datetime], list[bytes], list[str]]]



# error_log_list: list = []


###################################################################################################################################
#  __  __ ____         ____ _____ ____
# |  \/  / ___|       / ___|  ___| __ )
# | |\/| \___ \ _____| |   | |_  |  _ \
# | |  | |___) |_____| |___|  _| | |_) |
# |_|  |_|____/       \____|_|   |____/
#
###################################################################################################################################


class FAT:

    DIFSECT = 0xFFFFFFFC
    FATSECT = 0xFFFFFFFD
    ENDOFCHAIN = 0xFFFFFFFE
    FREESECT = 0xFFFFFFFF

    def __init__(self, mscfb: 'MSCFB') -> None:

        self.mscfb: MSCFB = mscfb  # Microsoft Compound File Binary File
        difat_index: int = 0
        self.entries: list[bytes] = []
        while mscfb.DIFAT[difat_index] != FAT.FREESECT:
            sector = mscfb.DIFAT[difat_index]
            sector_bytes: bytes = mscfb.get_sector_bytes(sector)
            sector_fat_entries = struct.unpack(
                'I' * int(mscfb.SectorSize / 4), sector_bytes)
            self.entries.extend(sector_fat_entries)
            difat_index += 1

    def get_stream(self, sector: int, size: int) -> bytes:

        stream_bytes: bytes = b''
        while sector != FAT.ENDOFCHAIN:
            stream_bytes += self.mscfb.get_sector_bytes(sector)
            sector += len(self.entries[sector])
        # if size != 0:
        if size > len(stream_bytes) or size < len(stream_bytes) - self.mscfb.SectorSize:
            raise MSGException(
                'FAT stream size does not match number of sectors')
        return stream_bytes[:size]
        # else:
        #    return bytes

    def __str__(self) -> str:

        return ', '.join([f"{hex(sector)}:{panutils.to_hex(entry)}" for sector, entry in zip(list(range(len(self.entries))), self.entries)])


class MiniFAT:

    SECTORSIZE: int = 64

    def __init__(self, mscfb: 'MSCFB') -> None:

        self.entries: list = []
        self.mscfb = mscfb
        self.mini_stream_bytes: bytes = b''

        current_sector = mscfb.FirstMiniFATSectorLocation
        for _ in range(mscfb.MiniFATSectors):
            sector_bytes = mscfb.get_sector_bytes(current_sector)
            current_sector = mscfb.fat.entries[current_sector]
            minifat_entries = struct.unpack(
                'I' * int(mscfb.SectorSize / 4), sector_bytes)
            self.entries.extend(minifat_entries)

    def get_all_mini_stream_fat_sectors(self) -> None:
        if self.mscfb.MiniStreamSectorLocation != FAT.ENDOFCHAIN:
            self.mini_stream_bytes = self.mscfb.fat.get_stream(
                self.mscfb.MiniStreamSectorLocation, self.mscfb.MiniStreamSize)

    def get_stream(self, sector: int, size: int) -> bytes:

        stream_bytes: bytes = b''
        while sector != FAT.ENDOFCHAIN:
            stream_bytes += self.mini_stream_bytes[sector *
                                                   MiniFAT.SECTORSIZE: sector * MiniFAT.SECTORSIZE + MiniFAT.SECTORSIZE]
            sector = self.entries[sector]
        if size > len(stream_bytes) or size < len(stream_bytes) - MiniFAT.SECTORSIZE:
            raise MSGException(
                'Mini FAT mini stream size does not match number of mini sectors')
        return stream_bytes[:size]

    def __str__(self) -> str:

        return ', '.join([f"{hex(sector)}:{panutils.to_hex(entry)}" for sector, entry in zip(list(range(len(self.entries))), self.entries)])


class Directory:

    mscfb: 'MSCFB'
    entries: list['DirectoryEntry']

    def __init__(self, mscfb: 'MSCFB') -> None:

        self.mscfb = mscfb
        self.entries = self.get_all_directory_entries(
            self.mscfb.FirstDirectorySectorLocation)
        self.set_entry_children(self.entries[0])  # recursive

    def get_all_directory_entries(self, start_sector: int) -> list['DirectoryEntry']:

        entries: list[DirectoryEntry] = []
        sector: int = start_sector
        while sector != FAT.ENDOFCHAIN:
            entries.extend(self.get_directory_sector(sector))
            sector += int(self.mscfb.fat.entries[sector])
        return entries

    def set_entry_children(self, dir_entry) -> None:

        dir_entry.childs = {}
        child_ids_queue = []
        if dir_entry.ChildID != DirectoryEntry.NOSTREAM:
            child_ids_queue.append(dir_entry.ChildID)
            while child_ids_queue:
                child_entry = self.entries[child_ids_queue.pop()]
                if child_entry.Name in list(dir_entry.childs.keys()):
                    raise MSGException(
                        'Directory Entry Name already in children dictionary')
                dir_entry.childs[child_entry.Name] = child_entry
                if child_entry.SiblingID != DirectoryEntry.NOSTREAM:
                    child_ids_queue.append(child_entry.SiblingID)
                if child_entry.RightSiblingID != DirectoryEntry.NOSTREAM:
                    child_ids_queue.append(child_entry.RightSiblingID)
                if child_entry.ChildID != DirectoryEntry.NOSTREAM:
                    self.set_entry_children(child_entry)

    def get_directory_sector(self, sector: int) -> list['DirectoryEntry']:

        entries: list[DirectoryEntry] = []
        sector_bytes: bytes = self.mscfb.get_sector_bytes(sector)
        sector_directory_entry_count: int = int(self.mscfb.SectorSize / 128)
        for i in range(sector_directory_entry_count):
            entries.append(DirectoryEntry(
                self.mscfb, sector_bytes[DirectoryEntry.ENTRY_SIZE * i:DirectoryEntry.ENTRY_SIZE * i + DirectoryEntry.ENTRY_SIZE]))
        return entries

    def __str__(self) -> str:

        return ', '.join([str(entry) for entry in self.entries])


class DirectoryEntry:

    ENTRY_SIZE = 128
    OBJECT_UNKNOWN = 0x0
    OBJECT_STORAGE = 0x1  # folder
    OBJECT_STREAM = 0x2  # file
    OBJECT_ROOT_STORAGE = 0x5
    NOSTREAM = 0xFFFFFFFF

    mscfb: 'MSCFB'
    ObjectType: int
    ColorFlag: int
    SiblingID: int
    RightSiblingID: int
    ChildID: int
    CLSID: bytes
    StateBits: int
    CreationTime: Optional[dt.datetime]
    ModifiedTime: Optional[dt.datetime]
    NameLength: int
    StreamSize: int
    StartingSectorLocation: int
    stream_data: bytes
    childs: dict[str, 'DirectoryEntry']

    def __init__(self, mscfb: 'MSCFB', directory_bytes: bytes) -> None:

        if len(directory_bytes) != DirectoryEntry.ENTRY_SIZE:
            raise MSGException('Directory Entry not 128 bytes')

        self.mscfb = mscfb
        self.NameLength = panutils.unpack_integer('H', directory_bytes[64:66])
        if self.NameLength > 64:
            raise MSGException('Directory Entry name cannot be longer than 64')
        self.Name: str = directory_bytes[:self.NameLength -
                                         2].decode('utf-16-le')
        self.ObjectType, self.ColorFlag = struct.unpack(
            'BB', directory_bytes[66:68])
        self.SiblingID, self.RightSiblingID, self.ChildID = struct.unpack(
            'III', directory_bytes[68:80])
        self.CLSID = struct.unpack('16s', directory_bytes[80:96])[0]
        self.StateBits = panutils.unpack_integer('I', directory_bytes[96:100])
        creation_time_bytes, modified_time_bytes = struct.unpack(
            '8s8s', directory_bytes[100:116])
        if creation_time_bytes == '\x00' * 8:
            self.CreationTime = None
        else:
            self.CreationTime = panutils.bytes_to_time(creation_time_bytes)
        if modified_time_bytes == '\x00' * 8:
            self.ModifiedTime = None
        else:
            self.ModifiedTime = panutils.bytes_to_time(modified_time_bytes)
        self.StartingSectorLocation = struct.unpack(
            'I', directory_bytes[116:120])[0]
        self.StreamSize = panutils.unpack_integer(
            'Q', directory_bytes[120:128])
        if mscfb.MajorVersion == 3:
            self.StreamSize = self.StreamSize & 0xFFFFFFFF  # upper 32 bits may not be zero
        self.childs = {}

    def __cmp__(self, other: 'DirectoryEntry') -> bool:
        return self.Name == other.Name

    def get_data(self) -> bytes:

        if self.ObjectType != DirectoryEntry.OBJECT_STREAM:
            raise MSGException('Directory Entry is not a stream object')
        if self.StreamSize < self.mscfb.MiniStreamCutoffSize:  # Mini FAT stream
            self.stream_data = self.mscfb.minifat.get_stream(
                self.StartingSectorLocation, self.StreamSize)
        else:  # FAT
            self.stream_data = self.mscfb.fat.get_stream(
                self.StartingSectorLocation, self.StreamSize)
        return self.stream_data

    def list_children(self, level: int = 0, expand: bool = False) -> str:

        line_pfx: str = '\t' * level
        s: str = ''
        sorted_entries: list[DirectoryEntry] = [
            i for i in self.childs.values()]
        sorted_entries.sort(key=lambda x: x.Name)
        for child_entry in sorted_entries:
            line_sfx: str = ''
            if child_entry.ObjectType == DirectoryEntry.OBJECT_STORAGE:
                line_sfx = f"({len(list(child_entry.childs.keys()))})"
            s += f"{(line_pfx, child_entry.Name, line_sfx)}\n"
            if expand:
                s += child_entry.list_children(level + 1, expand)
        return s

    def __str__(self) -> str:
        return f"{self.Name} ({self.ObjectType}, {hex(self.SiblingID)}, {hex(self.RightSiblingID)}, {hex(self.ChildID)}, {hex(self.StartingSectorLocation)}, {hex(self.StreamSize)})"


class MSCFB:
    fd: BufferedReader
    fat: FAT
    minifat: MiniFAT
    directory: Directory
    validCFB: bool
    SectorSize: int
    MiniStreamSectorLocation: int
    MiniStreamSize: int
    MinorVersion: int
    MajorVersion: int
    ByteOrder: int
    SectorShift: int
    MiniSectorShift: int
    DirectorySector: int
    FATSectors: int
    FirstDirectorySectorLocation: int
    TransactionSignatureNumber: int
    MiniStreamCutoffSize: int
    FirstMiniFATSectorLocation: int
    MiniFATSectors: int
    FirstDIFATSectorLocation: int
    DIFATSectors: int
    DIFAT: tuple

    def __init__(self, cfb_file: _FilePathOrFileObject) -> None:
        """cfb_file is unicode or string filename or a file object"""

        if isinstance(cfb_file, BufferedReader):
            self.fd = cfb_file
        else:
            self.fd = open(cfb_file, 'rb')

        self.read_header(self.fd)
        if not self.validCFB:
            # DevSkim: ignore DS187371
            raise MSGException('MSG file is not a valid CFB')
        if self.MajorVersion == 3:
            self.SectorSize = 512
        else:  # 4
            self.SectorSize = 4096

        self.fat = FAT(self)
        self.minifat = MiniFAT(self)
        self.directory = Directory(self)
        self.MiniStreamSectorLocation = self.directory.entries[0].StartingSectorLocation
        # Root directory entry
        self.MiniStreamSize = self.directory.entries[0].StreamSize
        self.minifat.get_all_mini_stream_fat_sectors()

    def read_header(self, fd: BufferedReader) -> None:

        self.validCFB = False
        fd.seek(0)
        self.signature: bytes = fd.read(8)
        if self.signature != b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            return
        self.CLSID: bytes = fd.read(16)
        self.MinorVersion, self.MajorVersion, self.ByteOrder, self.SectorShift, self.MiniSectorShift = struct.unpack(
            'HHHHH', fd.read(10))
        if self.MajorVersion not in (3, 4):
            return
        _ = fd.read(6)
        self.DirectorySector, self.FATSectors, self.FirstDirectorySectorLocation, self.TransactionSignatureNumber = struct.unpack(
            'IIII', fd.read(16))
        self.MiniStreamCutoffSize, self.FirstMiniFATSectorLocation, self.MiniFATSectors, self.FirstDIFATSectorLocation, self.DIFATSectors = struct.unpack(
            'IIIII', fd.read(20))
        self.DIFAT = struct.unpack('I' * 109, fd.read(436))
        self.validCFB = True

        if self.FirstDIFATSectorLocation != FAT.ENDOFCHAIN:
            raise MSGException('More than 109 DIFAT entries not supported')

    def get_sector_offset(self, sector: int) -> int:

        return (sector + 1) * self.SectorSize

    def get_sector_bytes(self, sector: int) -> bytes:

        offset: int = self.get_sector_offset(sector)
        self.fd.seek(offset)
        return self.fd.read(self.SectorSize)

    def __del__(self) -> None:
        self.fd.close()


###################################################################################################################################
#  __  __ ____         _____  ____  __ ____   ____
# |  \/  / ___|       / _ \ \/ /  \/  / ___| / ___|
# | |\/| \___ \ _____| | | \  /| |\/| \___ \| |  _
# | |  | |___) |_____| |_| /  \| |  | |___) | |_| |
# |_|  |_|____/       \___/_/\_\_|  |_|____/ \____|
#
###################################################################################################################################


class PropertyStream:

    PROPERTY_STREAM_NAME: str = '__properties_version1.0'
    TOPLEVEL_HEADER_SIZE: int = 32
    RECIP_OR_ATTACH_HEADER_SIZE: int = 8
    EMBEDDED_MSG_HEADER_SIZE: int = 24

    msmsg: 'MSMSG'
    properties: dict[PropIdEnum, 'PropertyEntry']
    NextRecipientID: int
    NextAttachmentID: int
    RecipientCount: int
    AttachmentCount: int

    def __init__(self, msmsg_obj: 'MSMSG', parent_dir_entry: DirectoryEntry, header_size: int) -> None:

        self.msmsg = msmsg_obj
        property_dir_entry: DirectoryEntry = parent_dir_entry.childs[
            PropertyStream.PROPERTY_STREAM_NAME]
        property_bytes: bytes = property_dir_entry.get_data()
        self.properties = {}
        if property_bytes:
            if header_size >= PropertyStream.EMBEDDED_MSG_HEADER_SIZE:
                _, self.NextRecipientID, self.NextAttachmentID, self.RecipientCount, self.AttachmentCount = struct.unpack(
                    '8sIIII', property_bytes[:24])
            if (len(property_bytes) - header_size) % 16 != 0:
                raise MSGException(
                    'Property Stream size less header is not exactly divisible by 16')
            property_entries_count: int = int(
                (len(property_bytes) - header_size) / 16)
            for i in range(property_entries_count):
                prop_entry: PropertyEntry = PropertyEntry(
                    self.msmsg, parent_dir_entry, property_bytes[header_size + i * 16: header_size + i * 16 + 16])
                if prop_entry in self.properties.values():
                    raise MSGException(
                        'PropertyID already in properties dictionary')
                self.properties[PropIdEnum(
                    prop_entry.PropertyID)] = prop_entry

    def get_value(self, prop_id: PropIdEnum) -> 'PropertyEntry':

        if prop_id in self.properties:
            return self.properties[prop_id]

        raise IndexError('prop_id')

    def __str__(self) -> str:
        return '\n'.join([str(prop) for prop in list(self.properties.values())])


class PropertyEntry:

    SUB_PREFIX: str = '__substg1.0_'

    PropertyTag: int
    Flags: int
    PropertyID: int
    PropertyType: int
    size: int
    name: str
    value: _ValueType

    def __init__(self, msmsg: 'MSMSG', parent_dir_entry: DirectoryEntry, property_entry_bytes: bytes) -> None:
        propertyTag: int
        Flags: int
        propertyTag, Flags = struct.unpack('II', property_entry_bytes[:8])

        self.PropertyTag = propertyTag
        self.Flags = Flags
        self.PropertyID = self.PropertyTag >> 16
        self.PropertyType = self.PropertyTag & 0xFFFF
        ptype: PType = msmsg.ptype_mapping[PTypeEnum(self.PropertyType)]
        if ptype.is_variable or ptype.is_multi:
            self.size = panutils.unpack_integer(
                'I', property_entry_bytes[8:12])
            stream_name: str = PropertyEntry.SUB_PREFIX + \
                panutils.to_zeropaddedhex(self.PropertyTag, 8)
            property_bytes: bytes = parent_dir_entry.childs[stream_name].get_data(
            )

            if len(property_bytes) != self.size:
                if (ptype.ptype == PTypeEnum.PtypString and len(property_bytes) + 2 != self.size) or (ptype.ptype == PTypeEnum.PtypString8 and len(property_bytes) + 1 != self.size):
                    raise MSGException(
                        'Property Entry size and byte length mismatch')

            if ptype.is_multi and ptype.is_variable:
                if ptype.ptype == PTypeEnum.PtypMultipleBinary:
                    len_item_size: int = 8
                else:  # PtypMultipleString8 or PtypMultipleString
                    len_item_size = 4

                value_lengths: list[int] = []
                for i in range(int(len(property_bytes) / len_item_size)):
                    value_lengths.append(panutils.unpack_integer(
                        'I', property_bytes[i * len_item_size:i * len_item_size + 4]))

                property_byte_list: list[bytes] = []
                for i in range(len(value_lengths)):
                    index_stream_name: str = f"{stream_name}-{i}"
                    property_byte_list.append(
                        parent_dir_entry.childs[index_stream_name].get_data())

                self.value = ptype.value(
                    b''.join(property_byte_list))
            else:
                self.value = ptype.value(property_bytes)

        else:  # fixed size
            self.size = ptype.byte_count
            self.value = ptype.value(property_entry_bytes[8:8 + self.size])

    def __str__(self) -> str:
        return f"{hex(self.PropertyTag)}-{str(self.value)}"

    def to_binary(self) -> bytes:
        if isinstance(self.value, bytes):
            return self.value
        raise TypeError()

    def to_str(self) -> str:
        if isinstance(self.value, str):
            return self.value
        raise TypeError()

    def to_int(self) -> int:
        if isinstance(self.value, int):
            return self.value
        raise TypeError()

    def to_datetime(self) -> dt.datetime:
        if isinstance(self.value, dt.datetime):
            return self.value
        raise TypeError()


class Recipient:
    RecipientType: int
    DisplayName: str
    ObjectType: int
    AddressType: str
    EmailAddress: str
    DisplayType: int

    def __init__(self, prop_stream: PropertyStream) -> None:

        self.RecipientType = prop_stream.get_value(
            PropIdEnum.PidTagRecipientType).to_int()
        self.DisplayName = prop_stream.get_value(
            PropIdEnum.PidTagDisplayName).to_str()
        self.ObjectType = prop_stream.get_value(
            PropIdEnum.PidTagObjectType).to_int()
        self.AddressType = prop_stream.get_value(
            PropIdEnum.PidTagAddressType).to_str()
        self.EmailAddress = prop_stream.get_value(
            PropIdEnum.PidTagEmailAddress).to_str()
        self.DisplayType = prop_stream.get_value(
            PropIdEnum.PidTagDisplayType).to_int()

    def __str__(self) -> str:
        return f"{self.DisplayName} ({self.EmailAddress})"


class Attachment:
    DisplayName: str
    AttachMethod: int
    AttachmentSize: int
    AttachFilename: str
    AttachLongFilename: str
    Filename: str
    BinaryData: bytes
    AttachMimeTag: str
    AttachExtension: str

    def __init__(self, prop_stream: PropertyStream) -> None:

        self.DisplayName = prop_stream.get_value(
            PropIdEnum.PidTagDisplayName).to_str()
        self.AttachMethod = prop_stream.get_value(
            PropIdEnum.PidTagAttachMethod).to_int()
        self.AttachmentSize = prop_stream.get_value(
            PropIdEnum.PidTagAttachmentSize).to_int()
        self.AttachFilename = prop_stream.get_value(
            PropIdEnum.PidTagAttachFilename).to_str()
        self.AttachLongFilename = prop_stream.get_value(
            PropIdEnum.PidTagAttachLongFilename).to_str()
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = f'[NoFilename_Method{self.AttachMethod}]'
        self.BinaryData = prop_stream.get_value(
            PropIdEnum.PidTagAttachDataBinary).to_binary()
        self.AttachMimeTag = prop_stream.get_value(
            PropIdEnum.PidTagAttachMimeTag).to_str()
        self.AttachExtension = prop_stream.get_value(
            PropIdEnum.PidTagAttachExtension).to_str()

    def __str__(self) -> str:

        return f"{self.Filename} ({panutils.size_friendly(self.AttachmentSize)} \
        / {panutils.size_friendly(len(self.BinaryData))})"


class MSMSG:

    cfb: MSCFB
    validMSG: bool
    root_dir_entry: DirectoryEntry
    prop_stream: PropertyStream
    recipients: list[Recipient]
    attachments: list[Attachment]
    ptype_mapping: dict[PTypeEnum, PType]
    Subject: str
    ClientSubmitTime: dt.datetime
    SentRepresentingName: str
    SenderName: str
    SenderSmtpAddress: str
    MessageDeliveryTime: dt.datetime
    MessageFlags: int
    MessageStatus: int
    MessageSize: int
    Body: str
    TransportMessageHeaders: str
    DisplayTo: str
    XOriginatingIP: str

    def __init__(self, msg_file_path: _FilePathOrFileObject) -> None:
        """msg_file is unicode or string filename or a file object"""

        self.set_property_types()
        self.cfb = MSCFB(msg_file_path)
        self.validMSG = self.cfb.validCFB

        self.root_dir_entry = self.cfb.directory.entries[0]
        self.prop_stream = PropertyStream(
            self, self.root_dir_entry, PropertyStream.TOPLEVEL_HEADER_SIZE)  # root

        self.set_common_properties()
        self.set_recipients()
        self.set_attachments()

    def set_common_properties(self) -> None:

        self.Subject = self.prop_stream.get_value(
            PropIdEnum.PidTagSubjectW).to_str()
        self.ClientSubmitTime = self.prop_stream.get_value(
            PropIdEnum.PidTagClientSubmitTime).to_datetime()
        self.SentRepresentingName = self.prop_stream.get_value(
            PropIdEnum.PidTagSentRepresentingNameW).to_str()
        self.SenderName = self.prop_stream.get_value(
            PropIdEnum.PidTagSenderName).to_str()
        self.SenderSmtpAddress = self.prop_stream.get_value(
            PropIdEnum.PidTagSenderSmtpAddress).to_str()
        self.MessageDeliveryTime = self.prop_stream.get_value(
            PropIdEnum.PidTagMessageDeliveryTime).to_datetime()
        self.MessageFlags = self.prop_stream.get_value(
            PropIdEnum.PidTagMessageFlags).to_int()
        self.MessageStatus = self.prop_stream.get_value(
            PropIdEnum.PidTagMessageStatus).to_int()
        # self.HasAttachments  = (self.MessageFlags & Message.mfHasAttach == Message.mfHasAttach)
        self.MessageSize = self.prop_stream.get_value(
            PropIdEnum.PidTagMessageSize).to_int()
        self.Body = self.prop_stream.get_value(
            PropIdEnum.PidTagBody).to_str()
        # self.Read = (self.MessageFlags & Message.mfRead == Message.mfRead)
        self.TransportMessageHeaders = self.prop_stream.get_value(
            PropIdEnum.PidTagTransportMessageHeaders).to_str()
        self.DisplayTo = self.prop_stream.get_value(
            PropIdEnum.PidTagDisplayToW).to_str()
        self.XOriginatingIP = self.prop_stream.get_value(
            PropIdEnum(0x8028)).to_str()  # x-originating-ip

    def set_recipients(self) -> None:

        self.recipients = []
        recipient_dir_index: int = 0
        while True:
            recipient_dir_name: str = f'__recip_version1.0_#{panutils.to_zeropaddedhex(recipient_dir_index, 8)}'
            if recipient_dir_name in list(self.root_dir_entry.childs.keys()):
                recipient_dir_entry: DirectoryEntry = self.root_dir_entry.childs[
                    recipient_dir_name]
                rps: PropertyStream = PropertyStream(
                    self, recipient_dir_entry, PropertyStream.RECIP_OR_ATTACH_HEADER_SIZE)
                recipient: Recipient = Recipient(rps)
                self.recipients.append(recipient)
                recipient_dir_index += 1
            else:
                break

    def set_attachments(self) -> None:
        self.attachments = []
        attachment_dir_index: int = 0
        while True:
            attachment_dir_name: str = f'__attach_version1.0_#{panutils.to_zeropaddedhex(attachment_dir_index, 8)}'
            if attachment_dir_name in list(self.root_dir_entry.childs.keys()):
                attachment_dir_entry: DirectoryEntry = self.root_dir_entry.childs[
                    attachment_dir_name]
                aps: PropertyStream = PropertyStream(
                    self, attachment_dir_entry, PropertyStream.RECIP_OR_ATTACH_HEADER_SIZE)
                attachment: Attachment = Attachment(aps)
                self.attachments.append(attachment)
                attachment_dir_index += 1
            else:
                break

    def set_property_types(self) -> None:

        self.ptype_mapping = {
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
            PTypeEnum.PtypObject: PType(PTypeEnum.PtypObject, 0, False, False)
        }


###################################################################################################################################
#  __  __           _       _        _____                 _   _
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################


###############################################################################################################################
#
#  _____         _     _____                 _   _
# |_   _|__  ___| |_  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
#   | |/ _ \/ __| __| | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
#   | |  __/\__ \ |_  |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#   |_|\___||___/\__| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###############################################################################################################################


def test_status_msg(msg_file_path: str) -> None:

    msg: MSMSG = MSMSG(msg_file_path)
    print(msg.cfb.directory)


def test_folder_msgs(folder_path: str) -> None:

    # global error_log_list

    s: str = ''
    for msg_filepath in [os.path.join(folder_path, filename) for filename in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, filename)) and os.path.splitext(filename.lower())[1] == '.msg']:
        # try:
        s += f'Opening {msg_filepath}\n'
        # error_log_list = []
        msg: MSMSG = MSMSG(msg_filepath)
        # s += u'MajorVersion: %s, FATSectors: %s, MiniFATSectors: %s,  DIFATSectors %s\n' % (msg.cfb.MajorVersion, msg.cfb.FATSectors, msg.cfb.MiniFATSectors, msg.cfb.DIFATSectors)
        # s += u'MiniStreamSectorLocation: %s, MiniStreamSize: %s\n' % (hex(msg.cfb.MiniStreamSectorLocation), msg.cfb.MiniStreamSize)
        # s += u'\n' + msg.cfb.directory.entries[0].list_children(level=0, expand=True)
        # s += u'\n' + msg.prop_stream.__str__()
        s += f"Recipients: {', '.join([str(recip) for recip in msg.recipients])}\n"
        s += f"Attachments: {', '.join([str(attach) for attach in msg.attachments])}\n"
        s += f"Subject: {msg.Subject}\nBody: {msg.Body}\n"

        s += '\n\n\n'
        # dump attachments if needed:
        dump_attachments: bool = False
        if dump_attachments:
            for attachment in msg.attachments:
                if len(attachment.BinaryData) != 0:
                    filepath = os.path.join(folder_path, attachment.Filename)
                    write_ascii_file(filepath, attachment.BinaryData, 'wb')
        # except Exception as e:
        #    s += 'ERROR: %s\n' % e

    write_unicode_file(os.path.join(folder_path, 'msgs_test.txt'), s)


###################################################################################################################################
#  __  __       _
# |  \/  | __ _(_)_ __
# | |\/| |/ _` | | '_ \
# | |  | | (_| | | | | |
# |_|  |_|\__,_|_|_| |_|
#
###################################################################################################################################


if __name__ == "__main__":

    test_folder: str = 'D:\\'
    # test_status_msg(test_folder+'test.msg')
    # test_folder_msgs(test_folder)
