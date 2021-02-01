#! /usr/bin/env python
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# By BB
# based on MS-OXMSG and MS-CFB Microsoft specification for MSG file format [MS-OXMSG].pdf v20140130
#  

import struct, datetime, os, sys, unicodedata, codecs


class MSGException(Exception):
    pass

error_log_list = []


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

    def __init__(self, mscfb):

        self.mscfb = mscfb
        difat_index = 0
        self.entries = []
        while mscfb.DIFAT[difat_index] != FAT.FREESECT:
            sector = mscfb.DIFAT[difat_index]
            bytes = mscfb.get_sector_bytes(sector)
            sector_fat_entries = struct.unpack('I' * (mscfb.SectorSize/4), bytes)
            self.entries.extend(sector_fat_entries)
            difat_index += 1


    def get_stream(self, sector, size):

        bytes = ''
        while sector != FAT.ENDOFCHAIN:
            bytes += self.mscfb.get_sector_bytes(sector)
            sector = self.entries[sector]
        #if size != 0:
        if size > len(bytes) or size < len(bytes) - self.mscfb.SectorSize:
            raise MSGException('FAT stream size does not match number of sectors')
        return bytes[:size]
        #else:
        #    return bytes


    def __repr__(self):

        return ', '.join(['%s:%s' % (hex(sector), hex(entry)) for sector, entry in zip(list(range(len(self.entries))), self.entries)])



class MiniFAT:

    SECTORSIZE = 64

    def __init__(self, mscfb):

        self.entries = []
        self.mscfb = mscfb
        current_sector = mscfb.FirstMiniFATSectorLocation
        for i in range(mscfb.MiniFATSectors):
            bytes = mscfb.get_sector_bytes(current_sector)
            current_sector = mscfb.fat.entries[current_sector]
            minifat_entries = struct.unpack('I' * (mscfb.SectorSize/4), bytes)
            self.entries.extend(minifat_entries)
    

    def get_all_mini_stream_fat_sectors(self):

        if self.mscfb.MiniStreamSectorLocation == FAT.ENDOFCHAIN:
            self.mini_stream_bytes = ''
        else:
            self.mini_stream_bytes = self.mscfb.fat.get_stream(self.mscfb.MiniStreamSectorLocation, self.mscfb.MiniStreamSize)


    def get_stream(self, sector, size):

        bytes = ''
        while sector != FAT.ENDOFCHAIN:
            bytes += self.mini_stream_bytes[sector * MiniFAT.SECTORSIZE : sector * MiniFAT.SECTORSIZE + MiniFAT.SECTORSIZE]
            sector = self.entries[sector]
        if size > len(bytes) or size < len(bytes) - MiniFAT.SECTORSIZE:
            raise MSGException('Mini FAT mini stream size does not match number of mini sectors')
        return bytes[:size]


    def __repr__(self):

        return ', '.join(['%s:%s' % (hex(sector), hex(entry)) for sector, entry in zip(list(range(len(self.entries))), self.entries)])



class Directory:

    def __init__(self, mscfb):

        self.mscfb = mscfb
        self.entries = self.get_all_directory_entries(self.mscfb.FirstDirectorySectorLocation)
        self.set_entry_children(self.entries[0]) # recursive

        
    def get_all_directory_entries(self, start_sector):
        
        entries = []
        sector = start_sector
        while sector != FAT.ENDOFCHAIN:
            entries.extend(self.get_directory_sector(sector))
            sector = self.mscfb.fat.entries[sector]
        return entries


    def set_entry_children(self, dir_entry):

        dir_entry.childs = {}
        child_ids_queue = []
        if dir_entry.ChildID != DirectoryEntry.NOSTREAM:
            child_ids_queue.append(dir_entry.ChildID)
            while child_ids_queue:
                child_entry =  self.entries[child_ids_queue.pop()]
                if child_entry.Name in list(dir_entry.childs.keys()):
                    raise MSGException('Directory Entry Name already in children dictionary')
                dir_entry.childs[child_entry.Name] = child_entry
                if child_entry.SiblingID != DirectoryEntry.NOSTREAM:
                    child_ids_queue.append(child_entry.SiblingID)
                if child_entry.RightSiblingID != DirectoryEntry.NOSTREAM:
                    child_ids_queue.append(child_entry.RightSiblingID)
                if child_entry.ChildID != DirectoryEntry.NOSTREAM:
                    self.set_entry_children(child_entry)


    def get_directory_sector(self, sector):

        entries = []
        bytes = self.mscfb.get_sector_bytes(sector)
        sector_directory_entry_count = self.mscfb.SectorSize / 128
        for i in range(sector_directory_entry_count):
            entries.append(DirectoryEntry(self.mscfb, bytes[DirectoryEntry.ENTRY_SIZE * i:DirectoryEntry.ENTRY_SIZE * i + DirectoryEntry.ENTRY_SIZE]))
        return entries


    def __repr__(self):

        return ', '.join([entry.__repr__() for entry in self.entries])



class DirectoryEntry:

    ENTRY_SIZE = 128
    OBJECT_UNKNOWN = 0x0
    OBJECT_STORAGE = 0x1  # folder
    OBJECT_STREAM = 0x2  # file
    OBJECT_ROOT_STORAGE = 0x5
    NOSTREAM = 0xFFFFFFFF

    def __init__(self, mscfb, bytes):

        if len(bytes) != DirectoryEntry.ENTRY_SIZE:
            raise MSGException('Directory Entry not 128 bytes')
        
        self.mscfb = mscfb
        self.NameLength = struct.unpack('H', bytes[64:66])[0]
        if self.NameLength > 64:
            raise MSGException('Directory Entry name cannot be longer than 64')
        self.Name = bytes[:self.NameLength-2].decode('utf-16-le')
        self.ObjectType, self.ColorFlag = struct.unpack('BB', bytes[66:68])
        self.SiblingID, self.RightSiblingID, self.ChildID = struct.unpack('III', bytes[68:80])
        self.CLSID = struct.unpack('16s', bytes[80:96])[0]
        self.StateBits = struct.unpack('I', bytes[96:100])[0]
        self.CreationTime, self.ModifiedTime =  struct.unpack('8s8s', bytes[100:116])
        if self.CreationTime == '\x00'*8:
            self.CreationTime = None
        else:
            self.CreationTime = get_time(self.CreationTime)
        if self.ModifiedTime == '\x00'*8:
            self.ModifiedTime = None
        else:   
            self.ModifiedTime = get_time(self.ModifiedTime)
        self.StartingSectorLocation = struct.unpack('I', bytes[116:120])[0]
        self.StreamSize = struct.unpack('Q', bytes[120:128])[0]
        if mscfb.MajorVersion == 3:
            self.StreamSize = self.StreamSize & 0xFFFFFFFF # upper 32 bits may not be zero
        self.childs = {}
    
                    
    def __lt__(self, other):
        return self.Name < other.Name


    def get_data(self):

        if self.ObjectType != DirectoryEntry.OBJECT_STREAM:
            raise MSGException('Directory Entry is not a stream object')
        if self.StreamSize < self.mscfb.MiniStreamCutoffSize: # Mini FAT stream
            self.stream_data = self.mscfb.minifat.get_stream(self.StartingSectorLocation, self.StreamSize)
        else: # FAT
            self.stream_data = self.mscfb.fat.get_stream(self.StartingSectorLocation, self.StreamSize)
        return self.stream_data 


    def list_children(self, level=0, expand=False):

        line_pfx = '\t' * level
        s = ''
        for child_entry in sorted(self.childs.values()):
            line_sfx = ''
            if child_entry.ObjectType == DirectoryEntry.OBJECT_STORAGE:
                line_sfx = '(%s)' % len(list(child_entry.childs.keys()))
            s += '%s %s %s\n' % (line_pfx, child_entry.Name, line_sfx)
            if expand:
                s += child_entry.list_children(level+1, expand)
        return s


    def __repr__(self):

        return '%s (%s, %s, %s, %s, %s, %s)' % (self.Name, self.ObjectType, hex(self.SiblingID), hex(self.RightSiblingID), hex(self.ChildID), hex(self.StartingSectorLocation), hex(self.StreamSize))



class MSCFB:

    def __init__(self, cfb_file):
        """cfb_file is unicode or string filename or a file object"""

        if isinstance(cfb_file, str) or isinstance(cfb_file, str):
            self.fd = open(cfb_file,'rb')
        else:
            self.fd = cfb_file

        self.read_header(self.fd)
        if not self.validCFB:
            raise MSGException('MSG file is not a valid CFB')
        if self.MajorVersion == 3:
            self.SectorSize = 512
        else: # 4
            self.SectorSize = 4096

        self.fat = FAT(self)
        self.minifat = MiniFAT(self)
        self.directory = Directory(self)
        self.MiniStreamSectorLocation, self.MiniStreamSize = self.directory.entries[0].StartingSectorLocation, self.directory.entries[0].StreamSize # Root directory entry
        self.minifat.get_all_mini_stream_fat_sectors()
        pass


    def read_header(self, fd):

        self.validCFB = False
        fd.seek(0)       
        self.signature = fd.read(8)
        if self.signature != '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
            return
        self.CLSID = fd.read(16)
        self.MinorVersion, self.MajorVersion, self.ByteOrder, self.SectorShift, self.MiniSectorShift = struct.unpack('HHHHH',fd.read(10))
        if self.MajorVersion not in (3,4):
            return
        reserved = fd.read(6)
        self.DirectorySector, self.FATSectors, self.FirstDirectorySectorLocation, self.TransactionSignatureNumber = struct.unpack('IIII',fd.read(16))
        self.MiniStreamCutoffSize, self.FirstMiniFATSectorLocation, self.MiniFATSectors, self.FirstDIFATSectorLocation, self.DIFATSectors = struct.unpack('IIIII',fd.read(20))
        self.DIFAT = struct.unpack('I'*109,fd.read(436))
        self.validCFB = True

        if self.FirstDIFATSectorLocation != FAT.ENDOFCHAIN:
            raise MSGException('More than 109 DIFAT entries not supported')


    def get_sector_offset(self, sector):

        return (sector+1) * self.SectorSize


    def get_sector_bytes(self, sector):

        offset = self.get_sector_offset(sector)
        self.fd.seek(offset)
        return self.fd.read(self.SectorSize)


    def close(self):

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

    PROPERTY_STREAM_NAME = '__properties_version1.0'
    TOPLEVEL_HEADER_SIZE = 32
    RECIP_OR_ATTACH_HEADER_SIZE = 8
    EMBEDDED_MSG_HEADER_SIZE = 24

    def __init__(self, msmsg, parent_dir_entry, header_size):

        self.msmsg = msmsg
        property_dir_entry = parent_dir_entry.childs[PropertyStream.PROPERTY_STREAM_NAME]
        bytes = property_dir_entry.get_data()
        self.properties = {}
        if bytes:
            if header_size >= PropertyStream.EMBEDDED_MSG_HEADER_SIZE:
                reserved, self.NextRecipientID, self.NextAttachmentID, self.RecipientCount, self.AttachmentCount = struct.unpack('8sIIII', bytes[:24])
            if (len(bytes) - header_size) % 16 != 0:
                raise MSGException('Property Stream size less header is not exactly divisible by 16')
            property_entries_count = (len(bytes) - header_size) / 16        
            for i in range(property_entries_count):
                prop_entry = PropertyEntry(self.msmsg, parent_dir_entry, bytes[header_size + i*16: header_size + i*16 + 16])
                if prop_entry in list(self.properties.keys()):
                    raise MSGException('PropertyID already in properties dictionary')
                self.properties[prop_entry.PropertyID] = prop_entry


    def getval(self, prop_id):

        if prop_id in list(self.properties.keys()):
            return self.properties[prop_id].value
        else:
            return None


    def __repr__(self):

        return '\n'.join([prop.__repr__() for prop in list(self.properties.values())])



class PropertyEntry:

    SUB_PREFIX = '__substg1.0_'

    def __init__(self, msmsg, parent_dir_entry, bytes):

        self.PropertyTag, self.Flags = struct.unpack('II', bytes[:8])
        self.PropertyID = self.PropertyTag >> 16
        self.PropertyType = self.PropertyTag & 0xFFFF
        ptype = msmsg.ptypes[self.PropertyType]
        if ptype.is_variable or ptype.is_multi:
            self.size = struct.unpack('I', bytes[8:12])[0]
            stream_name = PropertyEntry.SUB_PREFIX + zeropadhex(self.PropertyTag, 8)
            bytes = parent_dir_entry.childs[stream_name].get_data()
            if len(bytes) != self.size:
                if (ptype.ptype == PTypeEnum.PtypString and len(bytes)+2 != self.size) or (ptype.ptype == PTypeEnum.PtypString8 and len(bytes)+1 != self.size):
                    raise MSGException('Property Entry size and byte length mismatch')
            if ptype.is_multi and ptype.is_variable:
                if ptype.ptype == PTypeEnum.PtypMultipleBinary:
                    len_item_size = 8
                else: # PtypMultipleString8 or PtypMultipleString
                    len_item_size = 4
                value_lengths = []
                for i in range(len(bytes)/len_item_size):
                    value_lengths.append(struct.unpack('I', bytes[i*len_item_size:i*len_item_size+4])[0])
                value_bytes = []
                for i in range(len(value_lengths)):
                    index_stream_name = '%s-%X' % (stream_name, i)
                    value_bytes.append(parent_dir_entry.childs[index_stream_name].get_data())
                self.value = ptype.value(value_bytes)
            else: 
                self.value = ptype.value(bytes)

        else: # fixed size
            self.size = ptype.byte_count
            self.value = ptype.value(bytes[8:8+self.size])


    def __repr__(self):

        return '%s=%s' % (hex(self.PropertyTag), self.value.__repr__())



class PTypeEnum:

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



class PType:

    def __init__(self, ptype, byte_count, is_variable, is_multi):

        self.ptype, self.byte_count, self.is_variable, self.is_multi = ptype, byte_count, is_variable, is_multi
    

    def value(self, bytes):
        """bytes is normally a string of bytes, but if multi and variable, bytes is a list of bytes"""

        if self.ptype ==  PTypeEnum.PtypInteger16:
            return struct.unpack('h', bytes)[0]
        elif self.ptype == PTypeEnum.PtypInteger32:
            return struct.unpack('i', bytes)[0]
        elif self.ptype == PTypeEnum.PtypFloating32:
            return struct.unpack('f', bytes)[0]
        elif self.ptype == PTypeEnum.PtypFloating64:
            return struct.unpack('d', bytes)[0]
        elif self.ptype == PTypeEnum.PtypCurrency:
            raise MSGException('PtypCurrency value not implemented')
        elif self.ptype == PTypeEnum.PtypFloatingTime:
            return self.get_floating_time(bytes)
        elif self.ptype == PTypeEnum.PtypErrorCode:
            return struct.unpack('I', bytes)[0]
        elif self.ptype == PTypeEnum.PtypBoolean:
            return (struct.unpack('B', bytes)[0] != 0)
        elif self.ptype == PTypeEnum.PtypInteger64:
            return struct.unpack('q', bytes)[0]
        elif self.ptype == PTypeEnum.PtypString:
            return bytes.decode('utf-16-le') # unicode
        elif self.ptype == PTypeEnum.PtypString8:
            if bytes[-1:] == '\x00':
                return bytes[:-1]
            else:
                return bytes
        elif self.ptype == PTypeEnum.PtypTime:
            return self.get_time(bytes)
        elif self.ptype == PTypeEnum.PtypGuid:
            return bytes
        elif self.ptype == PTypeEnum.PtypServerId:
            raise MSGException('PtypServerId value not implemented')
        elif self.ptype == PTypeEnum.PtypRestriction:
            raise MSGException('PtypRestriction value not implemented')
        elif self.ptype == PTypeEnum.PtypRuleAction:
            raise MSGException('PtypRuleAction value not implemented')
        elif self.ptype == PTypeEnum.PtypBinary:
            return bytes
        elif self.ptype == PTypeEnum.PtypMultipleInteger16:
            count = len(bytes) / 2
            return [struct.unpack('h', bytes[i*2:(i+1)*2])[0] for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleInteger32:
            count = len(bytes) / 4
            return [struct.unpack('i', bytes[i*4:(i+1)*4])[0] for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleFloating32:
            count = len(bytes) / 4
            return [struct.unpack('f', bytes[i*4:(i+1)*4])[0] for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleFloating64:
            ccount = len(bytes) / 8
            return [struct.unpack('d', bytes[i*8:(i+1)*8])[0] for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleCurrency:
            raise PSTException('PtypMultipleCurrency value not implemented')
        elif self.ptype == PTypeEnum.PtypMultipleFloatingTime:
            count = len(bytes) / 8
            return [self.get_floating_time(bytes[i*8:(i+1)*8]) for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleInteger64:
            count = len(bytes) / 8
            return [struct.unpack('q', bytes[i*8:(i+1)*8])[0] for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleString:
            for item_bytes in bytes:          
                s.append(item_bytes.decode('utf-16-le'))
            return s
        elif self.ptype == PTypeEnum.PtypMultipleString8:
            return bytes # list
        elif self.ptype == PTypeEnum.PtypMultipleTime:
            count = len(bytes) / 8
            return [self.get_time(bytes[i*8:(i+1)*8]) for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleGuid:
            count = len(bytes) / 16
            return [bytes[i*16:(i+1)*16] for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleBinary:
            return bytes
        elif self.ptype == PTypeEnum.PtypUnspecified:
            return bytes
        elif self.ptype == PTypeEnum.PtypNull:
            return None
        elif self.ptype == PTypeEnum.PtypObject:
            return bytes
        else:
            raise MSGException('Invalid PTypeEnum for value %s ' % self.ptype)


    def get_floating_time(self, bytes):

        return datetime.datetime(year=1899, month=12, day=30) + datetime.timedelta(days=struct.unpack('d', bytes)[0])


    def get_time(self, bytes):

        return datetime.datetime(year=1601, month=1, day=1) + datetime.timedelta(microseconds = struct.unpack('q', bytes)[0]/10.0)


    def get_multi_value_offsets(self, bytes):

        ulCount = struct.unpack('I', bytes[:4])[0]
        if ulCount == 1:
            rgulDataOffsets = [8] # not documented, but seems as if a single length multi only has a 4 byte ULONG with the offset. Boo!
        else:
            rgulDataOffsets = [struct.unpack('Q', bytes[4+i*8:4+(i+1)*8])[0] for i in range(ulCount)]
        rgulDataOffsets.append(len(bytes))
        return ulCount, rgulDataOffsets



class PropIdEnum:

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
    PidTagSecureSubmitFlags = 0x65C6
    PidTagOfflineAddressBookName = 0x6800
    PidTagSendOutlookRecallReport = 0x6803
    PidTagOfflineAddressBookTruncatedProperties = 0x6805
    PidTagMapiFormComposeCommand = 0x682F
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
    PidTagSenderName = 0x0C1A
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
    PidTagAttachMimeTag = 0x370E
    PidTagAttachExtension = 0x3703
    PidTagAttachLongFilename = 0x3707



class Recipient:

    def __init__(self, prop_stream):

        self.RecipientType = prop_stream.getval(PropIdEnum.PidTagRecipientType)
        self.DisplayName = prop_stream.getval(PropIdEnum.PidTagDisplayName)
        self.ObjectType = prop_stream.getval(PropIdEnum.PidTagObjectType)
        self.AddressType = prop_stream.getval(PropIdEnum.PidTagAddressType)
        self.EmailAddress = prop_stream.getval(PropIdEnum.PidTagEmailAddress)
        self.DisplayType = prop_stream.getval(PropIdEnum.PidTagDisplayType)


    def __repr__(self):

        return '%s (%s)' % (self.DisplayName, self.EmailAddress)



class Attachment:

    def __init__(self, prop_stream):

        self.DisplayName = prop_stream.getval(PropIdEnum.PidTagDisplayName)
        self.AttachMethod = prop_stream.getval(PropIdEnum.PidTagAttachMethod)
        self.AttachmentSize = prop_stream.getval(PropIdEnum.PidTagAttachmentSize)
        self.AttachFilename = prop_stream.getval(PropIdEnum.PidTagAttachFilename) # 8.3 short name
        self.AttachLongFilename = prop_stream.getval(PropIdEnum.PidTagAttachLongFilename)
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = '[NoFilename_Method%s]' % self.AttachMethod        
        self.data = prop_stream.getval(PropIdEnum.PidTagAttachDataBinary)
        self.AttachMimeTag = prop_stream.getval(PropIdEnum.PidTagAttachMimeTag)
        self.AttachExtension = prop_stream.getval(PropIdEnum.PidTagAttachExtension)


    def __repr__(self):

        return '%s (%s / %s)' % (self.Filename, size_friendly(self.AttachmentSize), size_friendly(len(self.data)))



class MSMSG:

    def __init__(self, msg_file):
        """msg_file is unicode or string filename or a file object"""

        self.set_property_types()
        self.cfb = MSCFB(msg_file)
        self.validMSG = self.cfb.validCFB

        self.root_dir_entry = self.cfb.directory.entries[0]
        self.prop_stream = PropertyStream(self, self.root_dir_entry, PropertyStream.TOPLEVEL_HEADER_SIZE) # root

        self.set_common_properties()
        self.set_recipients()
        self.set_attachments()


    def set_common_properties(self):

        self.Subject = self.prop_stream.getval(PropIdEnum.PidTagSubjectW)
        self.ClientSubmitTime = self.prop_stream.getval(PropIdEnum.PidTagClientSubmitTime)
        self.SentRepresentingName = self.prop_stream.getval(PropIdEnum.PidTagSentRepresentingNameW)
        self.SenderName = self.prop_stream.getval(PropIdEnum.PidTagSenderName)
        self.SenderSmtpAddress = self.prop_stream.getval(PropIdEnum.PidTagSenderSmtpAddress)
        self.MessageDeliveryTime = self.prop_stream.getval(PropIdEnum.PidTagMessageDeliveryTime)
        self.MessageFlags = self.prop_stream.getval(PropIdEnum.PidTagMessageFlags)
        self.MessageStatus = self.prop_stream.getval(PropIdEnum.PidTagMessageStatus)
        #self.HasAttachments  = (self.MessageFlags & Message.mfHasAttach == Message.mfHasAttach)
        self.MessageSize = self.prop_stream.getval(PropIdEnum.PidTagMessageSize)
        self.Body = self.prop_stream.getval(PropIdEnum.PidTagBody)
        #self.Read = (self.MessageFlags & Message.mfRead == Message.mfRead)
        self.TransportMessageHeaders = self.prop_stream.getval(PropIdEnum.PidTagTransportMessageHeaders)
        self.DisplayTo = self.prop_stream.getval(PropIdEnum.PidTagDisplayToW)
        self.XOriginatingIP =  self.prop_stream.getval(0x8028) # x-originating-ip


    def set_recipients(self):

        self.recipients = []
        recipient_dir_index = 0
        while True:
            recipient_dir_name = '__recip_version1.0_#%s' % zeropadhex(recipient_dir_index, 8)
            if recipient_dir_name in list(self.root_dir_entry.childs.keys()):
                recipient_dir_entry = self.root_dir_entry.childs[recipient_dir_name]
                rps = PropertyStream(self, recipient_dir_entry, PropertyStream.RECIP_OR_ATTACH_HEADER_SIZE)
                recipient = Recipient(rps)
                self.recipients.append(recipient)
                recipient_dir_index += 1
            else:
                break


    def set_attachments(self):

        self.attachments = []
        attachment_dir_index = 0
        while True:
            attachment_dir_name = '__attach_version1.0_#%s' % zeropadhex(attachment_dir_index, 8)
            if attachment_dir_name in list(self.root_dir_entry.childs.keys()):
                attachment_dir_entry = self.root_dir_entry.childs[attachment_dir_name]
                aps = PropertyStream(self, attachment_dir_entry, PropertyStream.RECIP_OR_ATTACH_HEADER_SIZE)
                attachment = Attachment(aps)
                self.attachments.append(attachment)
                attachment_dir_index += 1
            else:
                break


    def set_property_types(self):

        self.ptypes = {              
            PTypeEnum.PtypInteger16:PType(PTypeEnum.PtypInteger16, 2, False, False),
            PTypeEnum.PtypInteger32:PType(PTypeEnum.PtypInteger32, 4, False, False), 
            PTypeEnum.PtypFloating32:PType(PTypeEnum.PtypFloating32, 4, False, False), 
            PTypeEnum.PtypFloating64:PType(PTypeEnum.PtypFloating64, 8, False, False), 
            PTypeEnum.PtypCurrency:PType(PTypeEnum.PtypCurrency, 8, False, False), 
            PTypeEnum.PtypFloatingTime:PType(PTypeEnum.PtypFloatingTime, 8, False, False), 
            PTypeEnum.PtypErrorCode:PType(PTypeEnum.PtypErrorCode, 4, False, False), 
            PTypeEnum.PtypBoolean:PType(PTypeEnum.PtypBoolean, 1, False, False), 
            PTypeEnum.PtypInteger64:PType(PTypeEnum.PtypInteger64, 8, False, False), 
            PTypeEnum.PtypString:PType(PTypeEnum.PtypString, 0, True, False), 
            PTypeEnum.PtypString8:PType(PTypeEnum.PtypString8, 0, True, False), 
            PTypeEnum.PtypTime:PType(PTypeEnum.PtypTime, 8, False, False), 
            PTypeEnum.PtypGuid:PType(PTypeEnum.PtypGuid, 16, False, False),
            PTypeEnum.PtypServerId:PType(PTypeEnum.PtypServerId, 2, False, True), 
            PTypeEnum.PtypRestriction:PType(PTypeEnum.PtypRestriction, 0, True, False), 
            PTypeEnum.PtypRuleAction:PType(PTypeEnum.PtypRuleAction, 2, False, True), 
            PTypeEnum.PtypBinary:PType(PTypeEnum.PtypBinary, 2, False, True), 
            PTypeEnum.PtypMultipleInteger16:PType(PTypeEnum.PtypMultipleInteger16, 2, False, True), 
            PTypeEnum.PtypMultipleInteger32:PType(PTypeEnum.PtypMultipleInteger32, 2, False, True), 
            PTypeEnum.PtypMultipleFloating32:PType(PTypeEnum.PtypMultipleFloating32, 2, False, True), 
            PTypeEnum.PtypMultipleFloating64:PType(PTypeEnum.PtypMultipleFloating64, 2, False, True), 
            PTypeEnum.PtypMultipleCurrency:PType(PTypeEnum.PtypMultipleCurrency, 2, False, True), 
            PTypeEnum.PtypMultipleFloatingTime:PType(PTypeEnum.PtypMultipleFloatingTime, 2, False, True),
            PTypeEnum.PtypMultipleInteger64:PType(PTypeEnum.PtypMultipleInteger64, 2, False, True), 
            PTypeEnum.PtypMultipleString:PType(PTypeEnum.PtypMultipleString, 2, True, True), 
            PTypeEnum.PtypMultipleString8:PType(PTypeEnum.PtypMultipleString8, 2, True, True), 
            PTypeEnum.PtypMultipleTime:PType(PTypeEnum.PtypMultipleTime, 2, False, True), 
            PTypeEnum.PtypMultipleGuid:PType(PTypeEnum.PtypMultipleGuid, 2, False, True), 
            PTypeEnum.PtypMultipleBinary:PType(PTypeEnum.PtypMultipleBinary, 2, False, True), 
            PTypeEnum.PtypUnspecified:PType(PTypeEnum.PtypUnspecified, 0, False, False), 
            PTypeEnum.PtypNull:PType(PTypeEnum.PtypNull, 0, False, False), 
            PTypeEnum.PtypObject:PType(PTypeEnum.PtypObject, 0, False, False)
        }


    def close(self):

        self.cfb.close()


###################################################################################################################################
#  __  __           _       _        _____                 _   _                 
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___ 
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################     


def hex(i):

    return '0x%x' % i


def zeropadhex(i, fixed_length):

    return ('%X' % i).zfill(fixed_length)


def get_time(bytes):

    return datetime.datetime(year=1601, month=1, day=1) + datetime.timedelta(microseconds = struct.unpack('q', bytes)[0]/10.0)


def write_file(fn, s, write_mode='w'):

    f = open(fn,write_mode)
    f.write(s)
    f.close()


def read_unicode_file(fn):

    f = codecs.open(fn, encoding='utf-8', mode='r')
    s = f.read()
    f.close()
    return s


def write_unicode_file(fn,s):

    f = codecs.open(fn, encoding='utf-8', mode='w')
    f.write(s)
    f.close()


def unicode2ascii(unicode_str):

    return unicodedata.normalize('NFKD', unicode_str).encode('ascii','ignore')


def size_friendly(size):

    if size < 1024:
        return '%sB' % (size)
    elif size < 1024*1024:
        return '%sKB' % (size/1024)
    elif size < 1024*1024*1024:
        return '%sMB' % (size/(1024*1024))
    else:
        return '%sGB' % (size/(1024*1024*1024))


###############################################################################################################################
#
#  _____         _     _____                 _   _                 
# |_   _|__  ___| |_  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___ 
#   | |/ _ \/ __| __| | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
#   | |  __/\__ \ |_  |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
#   |_|\___||___/\__| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###############################################################################################################################


def test_status_msg(msg_file):

    msg = MSMSG(msg_file)
    print(msg.cfb.directory)
    msg.close()


def test_folder_msgs(test_folder):

    global error_log_list

    s = ''
    for msg_filepath in [os.path.join(test_folder, filename) for filename in os.listdir(test_folder) if os.path.isfile(os.path.join(test_folder, filename)) and os.path.splitext(filename.lower())[1] == '.msg']:
        #try:
            s += 'Opening %s\n' % msg_filepath
            error_log_list = []
            msg = MSMSG(msg_filepath)
            #s += u'MajorVersion: %s, FATSectors: %s, MiniFATSectors: %s,  DIFATSectors %s\n' % (msg.cfb.MajorVersion, msg.cfb.FATSectors, msg.cfb.MiniFATSectors, msg.cfb.DIFATSectors)
            #s += u'MiniStreamSectorLocation: %s, MiniStreamSize: %s\n' % (hex(msg.cfb.MiniStreamSectorLocation), msg.cfb.MiniStreamSize)
            #s += u'\n' + msg.cfb.directory.entries[0].list_children(level=0, expand=True)
            #s += u'\n' + msg.prop_stream.__repr__()
            s += 'Recipients: %s\n' % ', '.join([recip.__repr__() for recip in msg.recipients])
            s += 'Attachments: %s\n' % ', '.join([attach.__repr__() for attach in msg.attachments])
            s += 'Subject: %s\nBody: %s\n' % (msg.Subject.__repr__(), msg.Body.__repr__())
            s += '\n\n\n'
            # dump attachments:
            if False: 
                for attachment in msg.attachments:
                    if len(attachment.data) !=0:
                        filepath = os.path.join(test_folder, attachment.Filename)
                        write_file(filepath, attachment.data, 'wb')
            msg.close()
        #except Exception as e:
        #    s += 'ERROR: %s\n' % e

    write_unicode_file(os.path.join(test_folder, 'msgs_test.txt'), s)


###################################################################################################################################
#  __  __       _       
# |  \/  | __ _(_)_ __  
# | |\/| |/ _` | | '_ \ 
# | |  | | (_| | | | | |
# |_|  |_|\__,_|_|_| |_|
#
###################################################################################################################################


if __name__=="__main__":

    test_folder = 'D:\\'
    #test_status_msg(test_folder+'test.msg')
    #test_folder_msgs(test_folder)