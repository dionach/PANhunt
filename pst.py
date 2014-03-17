#! /usr/bin/env python
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# By BB
# based on MS-PST Microsoft specification for PST file format [MS-PST].pdf v2.1
# 

import struct, binascii, datetime, math, os, sys, unicodedata, re, argparse
import colorama
import progressbar


class PSTException(Exception):
    pass


error_log_list = []


###########################################################################################################


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

    def __init__(self, bytes_or_nid):

        if isinstance(bytes_or_nid, (int,long)):
            self.nid = bytes_or_nid
        else:
            self.nid = struct.unpack('I', bytes_or_nid)[0]
        self.nidType = self.nid & 0x1f
        self.nidIndex = self.nid & 0xffffffe0
        self.is_hid = False
        self.is_nid = True

    def __repr__(self):

        return 'nid: %s, %s' % (hex(self.nid), hex(self.nidType))



class BID:

    def __init__(self, bytes):

        if len(bytes) == 4: # ansi
            self.bid = struct.unpack('I', bytes)[0]            
        else: #unicode (8)
            self.bid = struct.unpack('Q', bytes)[0]
        if self.bid % 2 == 1: # A
            self.bid -= 1
        self.is_internal = (self.bid & 2 == 2) # B

    def __repr__(self):
        if self.is_internal:
            int_ext = 'I'
        else:
            int_ext = 'E'
        return 'bid: %s %s' % (self.bid, int_ext)



class BREF:

    def __init__(self, bytes):

        if len(bytes) == 8: # ansi
            self.bid, self.ib = struct.unpack('4sI', bytes)
        else: #unicode (16)
            self.bid, self.ib = struct.unpack('8sQ', bytes)
        self.bid = BID(self.bid)

    def __repr__(self):
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

    def __init__(self, bytes, is_ansi):

        # fixed 512 bytes
        if len(bytes) != Page.PAGE_SIZE:
            raise PSTException('Invalid Page size')
        if is_ansi:
            self.ptype, self.ptypeRepeat, self.wSig, self.bid, self.dwCRC = struct.unpack('BBHII', bytes[-12:])
        else: # unicode
            self.ptype, self.ptypeRepeat, self.wSig, self.dwCRC, self.bid = struct.unpack('BBHIQ', bytes[-16:])

        if self.ptype < Page.ptypeBBT or self.ptype > Page.ptypeDL:
            raise PSTException('Invalid Page Type %s ' % hex(self.ptype))
        if self.ptype != self.ptypeRepeat:
            raise PSTException('Page Type does not match Page Type Repeat %s!=%s ' % (hex(self.ptype), hex(self.ptypeRepeat)))

        if self.ptype in (Page.ptypeBBT, Page.ptypeNBT):
            if is_ansi:
                self.cEnt, self.cEntMax, self.cbEnt, self.cLevel = struct.unpack('BBBB', bytes[-16:-12])
                 # rgEntries 492 (cLevel>0) or 496 bytes (cLevel=0)
                entry_size = 12
            else: # unicode
                self.cEnt, self.cEntMax, self.cbEnt, self.cLevel = struct.unpack('BBBB', bytes[-24:-20])
                # rgEntries 488 bytes
                entry_size = 24
            if self.cLevel == 0:
                if self.ptype == Page.ptypeBBT:
                    entry_type = BBTENTRY
                else: # ptypeNBT
                    entry_type = NBTENTRY
                    entry_size = entry_size + entry_size/3
            else: # BTENTRY
                entry_type = BTENTRY

            self.rgEntries = []
            for i in range(self.cEnt): # self.cbEnt is size of each entry which may be different to entry_size
                self.rgEntries.append(entry_type(bytes[i*self.cbEnt:i*self.cbEnt+entry_size]))

    def __repr__(self):

        return 'PageType: %s, Entries: %s, Level: %s' % (hex(self.ptype), self.cEnt, self.cLevel)



class BTENTRY:
    
    def __init__(self, bytes):

        if len(bytes) == 12: # ansi 
            self.btkey = struct.unpack('I',bytes[:4])[0]
            self.BREF = BREF(bytes[4:])
        else: # unicode 24
            self.btkey = struct.unpack('Q',bytes[:8])[0]
            self.BREF = BREF(bytes[8:])

    def __repr__(self):

        return '%s' % (self.BREF)



class BBTENTRY:

    def __init__(self, bytes):

        if len(bytes) == 12: #ansi
            self.BREF = BREF(bytes[:8])
            self.cb, self.cRef = struct.unpack('HH',bytes[8:12])
        else: # unicode (24)
            self.BREF = BREF(bytes[:16])
            self.cb, self.cRef = struct.unpack('HH',bytes[16:20])
        self.key = self.BREF.bid.bid

    def __repr__(self):

        return '%s, data size: %s' % (self.BREF, self.cb)



class NBTENTRY:
    
    def __init__(self, bytes):

        if len(bytes) == 16: #ansi
            self.nid, self.bidData, self.bidSub, self.nidParent = struct.unpack('4s4s4s4s',bytes)          
        else: # unicode (32)
            self.nid, padding, self.bidData, self.bidSub, self.nidParent = struct.unpack('4s4s8s8s4s',bytes[:-4])
        self.nid = NID(self.nid)
        self.bidData = BID(self.bidData)
        self.bidSub = BID(self.bidSub)
        self.nidParent = NID(self.nidParent)
        self.key = self.nid.nid
        

    def __repr__(self):

        return '%s, bidData: %s, bidSub: %s' % (self.nid, self.bidData, self.bidSub)



class SLENTRY:

    def __init__(self, bytes):

        if len(bytes) == 12: #ansi
            self.nid, self.bidData, self.bidSub = struct.unpack('4s4s4s',bytes)   
        else: # unicode 24
            self.nid, padding, self.bidData, self.bidSub = struct.unpack('4s4s8s8s',bytes)  
        self.nid = NID(self.nid)
        self.bidData = BID(self.bidData)
        self.bidSub = BID(self.bidSub)


    def __repr__(self):

        return '%s %s sub%s' % (self.nid, self.bidData, self.bidSub)



class SIENTRY:

    def __init__(self, bytes):

        if len(bytes) == 8: #ansi
            self.nid, self.bid = struct.unpack('4s4s',bytes)   
        else: # unicode 16
            self.nid, padding, self.bid = struct.unpack('4s4s8s',bytes)  
        self.nid = NID(self.nid)
        self.bid = BID(self.bid)



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

    btypeData = 0
    btypeXBLOCK = 1
    btypeXXBLOCK = 2
    btypeSLBLOCK = 3
    btypeSIBLOCK = 4

    def decode_permute(self, pv, cb):
        """ NDB_CRYPT_PERMUTE: pv is byte array, cb is data length to decode"""

        temp = 0
        for pvIndex in range(cb):
            pv[pvIndex] = Block.mpbbCryptFrom512[pv[pvIndex]] # Block.mpbbCrypt[pv[pvIndex] + 512]
        return str(pv)


    def __init__(self, bytes, offset, data_size, is_ansi, bid_check, bCryptMethod):

        self.is_ansi = is_ansi
        self.offset = offset # for debugging

        if self.is_ansi: # 12
            self.cb, self.wSig, self.bid, self.dwCRC = struct.unpack('HH4sI',bytes[-12:])
            bid_size = 4
            slentry_size = 12
            sientry_size = 8
            sl_si_entries_offset = 4 # [MS-PST] WRONG for SLBLOCK and SIBLOCK for ANSI: there is no 4 byte padding
        else: # unicode 16       
            self.cb, self.wSig, self.dwCRC, self.bid = struct.unpack('HHI8s',bytes[-16:])
            bid_size = 8
            slentry_size = 24
            sientry_size = 16
            sl_si_entries_offset = 8
        self.bid = BID(self.bid)

        if self.bid.bid != bid_check.bid:
            raise PSTException('Block bid %s != ref bid %s' % (self.bid, bid_check))
        if data_size != self.cb:
            raise PSTException('BBT Entry data size %s != Block data size %s' % (data_size, self.cb) )

        if not self.bid.is_internal:

            self.block_type = Block.btypeData
            self.btype = 0
            self.cLevel = 0
            if bCryptMethod == 1: #NDB_CRYPT_PERMUTE
                self.data = self.decode_permute(bytearray(bytes[:data_size]), data_size)
            else: # no data encoding
                self.data = bytes[:data_size] # data block

        else: # XBLOCK, XXBLOCK, SLBLOCK or SIBLOCK

            self.btype, self.cLevel, self.cEnt = struct.unpack('BBH',bytes[:4])      
              
            if self.btype == 1: #XBLOCK, XXBLOCK
                self.lcbTotal = struct.unpack('I',bytes[4:8])[0]
                if self.cLevel == 1: #XBLOCK
                    self.block_type = Block.btypeXBLOCK
                elif self.cLevel == 2: #XXBLOCK
                    self.block_type = Block.btypeXXBLOCK
                else:
                    raise PSTException('Invalid Block Level %s' % self.cLevel) 
                self.rgbid = []
                for i in range(self.cEnt):
                    self.rgbid.append(BID(bytes[8+i*bid_size:8+(i+1)*bid_size]))

            elif self.btype == 2: # SLBLOCK, SIBLOCK 

                self.rgentries = []
                if self.cLevel == 0: #SLBLOCK
                    self.block_type = Block.btypeSLBLOCK                   
                    for i in range(self.cEnt):
                        self.rgentries.append(SLENTRY(bytes[sl_si_entries_offset + i*slentry_size:sl_si_entries_offset + (i+1)*slentry_size]))
                elif self.cLevel ==1: #SIBLOCK
                    self.block_type = Block.btypeSIBLOCK
                    for i in range(self.cEnt):
                        self.rgentries.append(SIENTRY(bytes[sl_si_entries_offset + i*sientry_size:sl_si_entries_offset + (i+1)*sientry_size]))
                else:
                    raise PSTException('Invalid Block Level %s' % self.cLevel) 

            else:
                raise PSTException('Invalid Block Type %s' % self.btype) 


    def __repr__(self):

        return 'Block %s %s %s' % (self.bid, self.btype, self.cLevel)



class NBD:
    """Node Database Layer"""

    def __init__(self, fd, header):

        self.fd = fd
        self.header = header
        self.nbt_entries = self.get_page_leaf_entries(NBTENTRY, self.header.root.BREFNBT.ib)
        self.bbt_entries = self.get_page_leaf_entries(BBTENTRY, self.header.root.BREFBBT.ib)


    def fetch_page(self, offset):

        self.fd.seek(offset)
        return Page(self.fd.read(Page.PAGE_SIZE), self.header.is_ansi)

        
    def fetch_block(self, bid):

        if bid.bid in self.bbt_entries.keys():
            bbt_entry = self.bbt_entries[bid.bid]
        else:
            raise PSTException('Invalid BBTEntry: %s' % bid)
        offset = bbt_entry.BREF.ib
        data_size = bbt_entry.cb

        if self.header.is_ansi:
            block_trailer_size = 12
        else: # unicode
            block_trailer_size = 16
        # block size must align on 64 bytes
        size_diff = (data_size + block_trailer_size) % 64
        if size_diff == 0:
            block_size = data_size + block_trailer_size
        else:
            block_size = data_size + block_trailer_size + 64 - size_diff
        self.fd.seek(offset)
        return Block(self.fd.read(block_size), offset, data_size, self.header.is_ansi, bid, self.header.bCryptMethod)


    def fetch_all_block_data(self, bid):
        """returns list of block datas"""

        datas = []
        block = self.fetch_block(bid)
        if block.block_type == Block.btypeData:
            datas.append(block.data)
        elif block.block_type == Block.btypeXBLOCK:
            for xbid in block.rgbid:
                xblock = self.fetch_block(xbid)
                if xblock.block_type != Block.btypeData:
                    raise PSTException('Expecting data block, got block type %s' % xblock.block_type) 
                datas.append(xblock.data)
        elif block.block_type == Block.btypeXXBLOCK:
            for xxbid in block.rgbid:
                xxblock = self.fetch_block(xxbid)
                if xxblock.block_type != Block.btypeXBLOCK:
                    raise PSTException('Expecting XBLOCK, got block type %s' % xxblock.block_type) 
                datas.extend(self.fetch_all_block_data(xxbid))
        else:
            raise PSTException('Invalid block type (not data/XBLOCK/XXBLOCK), got %s' % block.block_type) 
        return datas


    def fetch_subnodes(self, bid):
        """ get dictionary of subnode SLENTRYs for subnode bid"""
        
        subnodes = {}
        block = self.fetch_block(bid)
        if block.block_type == Block.btypeSLBLOCK:
            for slentry in block.rgentries:
                if slentry.nid in subnodes.keys():
                    raise PSTException('Duplicate subnode %s' % slentry.nid)
                subnodes[slentry.nid.nid] = slentry
        elif block.block_type == Block.btypeSIBLOCK:
            for sientry in block.rgentries:
                subnodes.update(self.fetch_subnodes(sientry.bid))
        else:
            raise PSTException('Invalid block type (not SLBLOCK/SIBLOCK), got %s' % block.block_type) 
        return subnodes


    def get_page_leaf_entries(self, entry_type, page_offset):
        """ entry type is NBTENTRY or BBTENTRY"""

        leaf_entries = {}
        page = self.fetch_page(page_offset)
        for entry in page.rgEntries:
            if isinstance(entry, entry_type):
                if entry.key in leaf_entries.keys():
                    raise PSTException('Invalid Leaf Key %s' % entry)
                leaf_entries[entry.key] = entry
            elif isinstance(entry, BTENTRY):
                leaf_entries.update(self.get_page_leaf_entries(entry_type, entry.BREF.ib))                
            else:
                raise PSTException('Invalid Entry Type')
        return leaf_entries




###########################################################################################################



class HID:

    def __init__(self, bytes):

        # hidIndex cannot be zero, first 5 bits must be zero (hidType)
        self.hidIndex, self.hidBlockIndex = struct.unpack('HH', bytes)
        self.hidType = self.hidIndex & 0x1F
        self.hidIndex = (self.hidIndex >> 5) & 0x7FF
        self.is_hid = True
        self.is_nid = False



class HNPAGEMAP:

    def __init__(self, bytes):

        self.cAlloc, self.cFree = struct.unpack('HH', bytes[:4])
        self.rgibAlloc = []
        for i in range(self.cAlloc+1): # cAlloc+1 is next free
            self.rgibAlloc.append(struct.unpack('H', bytes[4+i*2:4+(i+1)*2])[0])
    
    

class HN:

    bTypeTC = 0x7C
    bTypeBTH = 0xB5
    bTypePC = 0xBC

    def __init__(self, nbt_entry, ltp, datas):
        """datas = list of data sections from blocks"""

        self.nbt_entry = nbt_entry
        self.datas = datas
        self.ltp = ltp
        self.hnpagemaps = []
        for i in range(len(datas)):
            bytes = datas[i]
            if i == 0: # HNHDR
                ibHnpm, self.bSig, self.bClientSig, self.hidUserRoot, self.rgbFillLevel = struct.unpack('HBB4sI', bytes[:12])
                self.hidUserRoot = HID(self.hidUserRoot)
                if self.bSig != 0xEC:
                    raise PSTException('Invalid HN Signature %s' % self.bSig)
            else: # HNPAGEHDR or HNBITMAPHDR
                ibHnpm = struct.unpack('H', bytes[:2])[0]
            self.hnpagemaps.append(HNPAGEMAP(bytes[ibHnpm:]))
        
        # subnode SLENTRYs
        self.subnodes = None
        if self.nbt_entry.bidSub.bid != 0:
            self.subnodes = self.ltp.nbd.fetch_subnodes(self.nbt_entry.bidSub)            


    def get_hid_data(self, hid):

        start_offset = self.hnpagemaps[hid.hidBlockIndex].rgibAlloc[hid.hidIndex-1]
        end_offset = self.hnpagemaps[hid.hidBlockIndex].rgibAlloc[hid.hidIndex]
        return self.datas[hid.hidBlockIndex][start_offset:end_offset]


    def __repr__(self):

        return 'HN: %s, Blocks: %s' % (self.nbt_entry, len(self.datas))



class BTHData:

    def __init__(self, key, data):

        self.key = key
        self.data = data



class BTHIntermediate:

    def __init__(self, key, hidNextLevel, bIdxLevel):

        self.key = key
        self.hidNextLevel = hidNextLevel
        self.bIdxLevel = bIdxLevel



class BTH:

    def __init__(self, hn, bth_hid):
        """ hn = HN heapnode, bth_hid is hid of BTH header"""

        #BTHHEADER
        bth_header_bytes = hn.get_hid_data(bth_hid)
        self.bType, self.cbKey, self.cbEnt, self.bIdxLevels, self.hidRoot = struct.unpack('BBBB4s', bth_header_bytes)
        self.hidRoot = HID(self.hidRoot)
        if self.bType != HN.bTypeBTH:
            raise PSTException('Invalid BTH Type %s' % self.bType)        
        self.bth_datas = []
        bth_working_stack = []
        if self.hidRoot != 0:
            bytes = hn.get_hid_data(self.hidRoot)
            bth_record_list = self.get_bth_records(bytes, self.bIdxLevels)
            if self.bIdxLevels == 0: # no intermediate levels
                self.bth_datas = bth_record_list
            else:
                bth_working_stack = bth_record_list
                while bth_working_stack:
                    bth_intermediate = bth_working_stack.pop()
                    bth_record_list = self.get_bth_records(bytes, bth_intermediate.bIdxLevel - 1)
                    if bth_intermediate.bIdxLevel - 1 == 0: # leafs
                        self.bth_datas.extend(bth_record_list)
                    else:
                        bth_working_stack.extend(bth_record_list)
             

    def get_bth_records(self, bytes, bIdxLevel):

        bth_record_list = []
        if bIdxLevel == 0: # leaf
            record_size = self.cbKey + self.cbEnt
            records = len(bytes) / record_size
            for i in range(records):
                key, data = struct.unpack('%ss%ss' % (self.cbKey, self.cbEnt) , bytes[i*record_size:(i+1)*record_size])
                bth_record_list.append(BTHData(key, data))
        else: # intermediate
            record_size = self.cbKey + 4
            records = len(bytes) / record_size
            for i in range(records):
                key, hidNextLevel = struct.unpack('%ss4s' % self.cbKey , bytes[i*record_size:(i+1)*record_size])
                hidNextLevel = HID(hidNextLevel)
                bth_record_list.append(BTHIntermediate(key, hidNextLevel, bIdxLevel))
        return bth_record_list



class PCBTHData:

    def __init__(self, bth_data, hn):

        self.wPropId = struct.unpack('H', bth_data.key)[0]
        self.wPropType, self.dwValueHnid = struct.unpack('H4s', bth_data.data)
        ptype = hn.ltp.ptypes[self.wPropType]
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
                if self.subnode_nid.nid in hn.subnodes.keys():
                    subnode_nid_bid = hn.subnodes[self.subnode_nid.nid].bidData
                else:
                    raise PSTException('Invalid NID subnode reference %s' % self.subnode_nid)
                datas = hn.ltp.nbd.fetch_all_block_data(subnode_nid_bid)
                self.value = ptype.value(''.join(datas))        

    def __repr__(self):

        return '%s (%s) = %s' % (hex(self.wPropId), hex(self.wPropType), repr(self.value))



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

        if self.ptype ==  PTypeEnum.PtypInteger16:
            return struct.unpack('h', bytes)[0]
        elif self.ptype == PTypeEnum.PtypInteger32:
            return struct.unpack('i', bytes)[0]
        elif self.ptype == PTypeEnum.PtypFloating32:
            return struct.unpack('f', bytes)[0]
        elif self.ptype == PTypeEnum.PtypFloating64:
            return struct.unpack('d', bytes)[0]
        elif self.ptype == PTypeEnum.PtypCurrency:
            raise PSTException('PtypCurrency value not implemented')
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
            return bytes
        elif self.ptype == PTypeEnum.PtypTime:
            return self.get_time(bytes)
        elif self.ptype == PTypeEnum.PtypGuid:
            return bytes
        elif self.ptype == PTypeEnum.PtypServerId:
            raise PSTException('PtypServerId value not implemented')
        elif self.ptype == PTypeEnum.PtypRestriction:
            raise PSTException('PtypRestriction value not implemented')
        elif self.ptype == PTypeEnum.PtypRuleAction:
            raise PSTException('PtypRuleAction value not implemented')
        elif self.ptype == PTypeEnum.PtypBinary:
            #count = struct.unpack('H', bytes[:2])[0]
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
            ulCount, rgulDataOffsets = self.get_multi_value_offsets(bytes)
            s = []
            for i in range(ulCount):
                s.append(bytes[rgulDataOffsets[i]:rgulDataOffsets[i+1]].decode('utf-16-le'))
            return s
        elif self.ptype == PTypeEnum.PtypMultipleString8:
            ulCount, rgulDataOffsets = self.get_multi_value_offsets(bytes)
            datas = []
            for i in range(ulCount):
                datas.append(bytes[rgulDataOffsets[i]:rgulDataOffsets[i+1]])
            return datas
        elif self.ptype == PTypeEnum.PtypMultipleTime:
            count = len(bytes) / 8
            return [self.get_time(bytes[i*8:(i+1)*8]) for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleGuid:
            count = len(bytes) / 16
            return [bytes[i*16:(i+1)*16] for i in range(count)]
        elif self.ptype == PTypeEnum.PtypMultipleBinary:
            ulCount, rgulDataOffsets = self.get_multi_value_offsets(bytes)
            datas = []
            for i in range(ulCount):
                datas.append(bytes[rgulDataOffsets[i]:rgulDataOffsets[i+1]])
            return datas
        elif self.ptype == PTypeEnum.PtypUnspecified:
            return bytes
        elif self.ptype == PTypeEnum.PtypNull:
            return None
        elif self.ptype == PTypeEnum.PtypObject:
            return bytes
        else:
            raise PSTException('Invalid PTypeEnum for value %s ' % self.ptype)


    def get_floating_time(self, bytes):

        return datetime.datetime(year=1899, month=12, day=30) + datetime.timedelta(days=struct.unpack('d', bytes)[0])


    def get_time(self, bytes):

        return datetime.datetime(year=1601, month=1, day=1) + datetime.timedelta(microseconds = struct.unpack('q', bytes)[0]/10.0)


    def get_multi_value_offsets(self, bytes):

        ulCount = struct.unpack('I', bytes[:4])[0]
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

class PC: # Property Context

    def __init__(self, hn):

        self.hn = hn
        if hn.bClientSig != HN.bTypePC:
            raise PSTException('Invalid HN bClientSig, not bTypePC, is %s' % hn.bClientSig)
        self.bth = BTH(hn, hn.hidUserRoot)
        if self.bth.cbKey != 2:
            raise PSTException('Invalid PC BTH key size: %s' % self.bth.cbKey)
        if self.bth.cbEnt != 6:
            raise PSTException('Invalid PC BTH data size: %s' % self.bth.cbEnt)
        self.props = {}
        for bth_data in self.bth.bth_datas:
            pc_prop = PCBTHData(bth_data, hn)
            if pc_prop.wPropId in (PropIdEnum.PidTagFinderEntryId, PropIdEnum.PidTagIpmSubTreeEntryId, PropIdEnum.PidTagIpmWastebasketEntryId, PropIdEnum.PidTagEntryID):
                pc_prop.value = EntryID(pc_prop.value)
            self.props[pc_prop.wPropId] = pc_prop


    def getval(self, propid):
        
        if propid in self.props.keys():
            return self.props[propid].value 
        else:
            return None


    def __repr__(self):

        s = 'PC %s\n' % self.hn
        s += '\n'.join(['Property %s' % self.props[wPropId] for wPropId in sorted(self.props.keys())])
        return s



class TCOLDESC:

    def __init__(self, bytes):

        #self.tag is 4 byte (self.wPropId, self.wPropType): where is documentation MS?
        self.wPropType, self.wPropId, self.ibData, self.cbData, self.iBit = struct.unpack('HHHBB', bytes)

    def __repr__(self):

        return 'Tag: %s/%s, Offset+Size: %s+%s' % (hex(self.wPropId), hex(self.wPropType), self.ibData, self.cbData)



class TCROWID:

    def __init__(self, bth_data):

        self.dwRowID = struct.unpack('I', bth_data.key)[0] # dwRowID
        self.nid = NID(bth_data.key) # for hierarchy TCs
        if len(bth_data.data) == 2: # ansi
            self.dwRowIndex = struct.unpack('H', bth_data.data)[0]
        else: # unicode (4)
            self.dwRowIndex = struct.unpack('I', bth_data.data)[0]



class TC: # Table Context

    TCI_4b = 0
    TCI_2b = 1
    TCI_1b = 2
    TCI_bm = 3

    def __init__(self, hn):

        self.hn = hn
        if hn.bClientSig != HN.bTypeTC:
            raise PSTException('Invalid HN bClientSig, not bTypeTC, is %s' % hn.bClientSig)
        tcinfo_bytes = hn.get_hid_data(hn.hidUserRoot)
        self.bType, self.cCols = struct.unpack('BB', tcinfo_bytes[:2])
        if self.bType != HN.bTypeTC:
            raise PSTException('Invalid TCINFO bType, not bTypeTC, is %s' % self.bType)
        self.rgib = struct.unpack('HHHH', tcinfo_bytes[2:10])
        self.hidRowIndex, self.hnidRows, self.hidIndex = struct.unpack('4s4s4s', tcinfo_bytes[10:22])
        self.hidRowIndex = HID(self.hidRowIndex)
        if NID(self.hnidRows).nidType == NID.NID_TYPE_HID:
            self.hnidRows = HID(self.hnidRows)
        else:
            self.hnidRows = NID(self.hnidRows)
        self.rgTCOLDESC = []
        for i in range(self.cCols):
            self.rgTCOLDESC.append(TCOLDESC(tcinfo_bytes[22+i*8:22+(i+1)*8]))
        
        self.setup_row_index()
        self.setup_row_matrix()


    def setup_row_index(self):

        self.RowIndex = {} # key is dwRowID, value is dwRowIndex
        if not (self.hnidRows.is_hid and self.hnidRows.hidIndex == 0):
            row_index_bth = BTH(self.hn, self.hidRowIndex)
            if row_index_bth.cbKey != 4:
                raise PSTException('Invalid TC RowIndex key size %s' % row_index_bth.cbKey)
            for bth_data in row_index_bth.bth_datas:
                tcrowid = TCROWID(bth_data)
                self.RowIndex[tcrowid.dwRowIndex] = tcrowid

    
    def setup_row_matrix(self):

        self.RowMatrix = {}
        if self.RowIndex:
            if self.hn.ltp.nbd.header.is_ansi:
                size_BlockTrailer = 12
            else: # unicode
                size_BlockTrailer = 16
            row_size = self.rgib[TC.TCI_bm]
            RowsPerBlock = int(math.floor((8192.0 - size_BlockTrailer) / row_size))
            if self.hnidRows.is_hid:
                row_matrix_datas = [self.hn.get_hid_data(self.hnidRows)] # block data list
            else:
                if self.hnidRows.nid in self.hn.subnodes.keys():
                    subnode_nid_bid = self.hn.subnodes[self.hnidRows.nid].bidData
                else:
                    raise PSTException('Row Matrix HNID not in Subnodes: %s' % self.hnidRows.nid)
                row_matrix_datas = self.hn.ltp.nbd.fetch_all_block_data(subnode_nid_bid)

            for irow in range(len(self.RowIndex)):
                BlockIndex = irow / RowsPerBlock
                RowIndex = irow % RowsPerBlock
                row_bytes = row_matrix_datas[BlockIndex][RowIndex * row_size:(RowIndex+1) * row_size]
                dwRowID = struct.unpack('I', row_bytes[:4])[0]
                rgbCEB = row_bytes[self.rgib[TC.TCI_1b]:]                
                #row_datas = []
                rowvals = {}
                for tcoldesc in self.rgTCOLDESC:
                    is_fCEB = ((struct.unpack('B',rgbCEB[tcoldesc.iBit / 8])[0] & (1 << (7 - (tcoldesc.iBit % 8)))) != 0)
                    if is_fCEB:
                        data_bytes = row_bytes[tcoldesc.ibData:tcoldesc.ibData+tcoldesc.cbData]
                    else:
                        data_bytes = None
                    #row_datas.append(self.get_row_cell_value(data_bytes, tcoldesc))
                    if tcoldesc.wPropId in rowvals.keys():
                        raise PSTException('Property ID %s already in row data' % hex(tcoldesc.wPropId))
                    rowvals[tcoldesc.wPropId] = self.get_row_cell_value(data_bytes, tcoldesc)
                self.RowMatrix[dwRowID] = rowvals #row_datas
        

    def get_row_cell_value(self, data_bytes, tcoldesc):

        if data_bytes is None:
            return None
        else:
            ptype = self.hn.ltp.ptypes[tcoldesc.wPropType]

            if not ptype.is_variable and not ptype.is_multi:
               if ptype.byte_count <= 8:
                   return ptype.value(data_bytes)
               else:
                   hid = HID(data_bytes)
                   return ptype.value(self.hn.get_hid_data(hid)) 
            else:
                if NID(data_bytes).nidType == NID.NID_TYPE_HID:
                    hid = HID(data_bytes)
                    return ptype.value(self.hn.get_hid_data(hid))
                else:
                    subnode_nid = NID(data_bytes)
                    if subnode_nid.nid in self.hn.subnodes.keys():
                        subnode_nid_bid = self.hn.subnodes[subnode_nid.nid].bidData
                    else:
                        raise PSTException('Row Matrix Value HNID Subnode invalid: %s' % subnode_nid)
                    datas = self.hn.ltp.nbd.fetch_all_block_data(subnode_nid_bid)
                    return ptype.value(''.join(datas))        


    def get_row_ID(self, RowIndex):

        return self.RowIndex[RowIndex].dwRowID


    def getval(self, RowIndex, wPropId):

        dwRowID = self.get_row_ID(RowIndex)
        rowvals = self.RowMatrix[dwRowID]
        if wPropId in rowvals.keys():
            return rowvals[wPropId]
        else:
            return None


    def __repr__(self):

        s = 'TC Rows: %s, %s\n' % (len(self.RowIndex), self.hn)
        s += 'Columns: ' + ''.join([' %s' % tcoldesc for tcoldesc in self.rgTCOLDESC])
        s += '\nData:\n' + '\n'.join(['%s: %s' % (hex(dwRowID), rowvals) for dwRowID,rowvals in self.RowMatrix.items()])
        return s



class LTP:
    """LTP layer"""

    def __init__(self, nbd):

        self.nbd = nbd

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


    def get_pc_by_nid(self, nid):

        nbt_entry = self.nbd.nbt_entries[nid.nid]
        datas = self.nbd.fetch_all_block_data(nbt_entry.bidData)
        hn = HN(nbt_entry, self, datas)
        return PC(hn)


    def get_pc_by_slentry(self, slentry):

        datas = self.nbd.fetch_all_block_data(slentry.bidData)
        hn = HN(slentry, self, datas)
        return PC(hn)


    def get_tc_by_nid(self, nid):

        nbt_entry = self.nbd.nbt_entries[nid.nid]
        datas = self.nbd.fetch_all_block_data(nbt_entry.bidData)
        hn = HN(nbt_entry, self, datas)
        return TC(hn)


    def get_tc_by_slentry(self, slentry):

        datas = self.nbd.fetch_all_block_data(slentry.bidData)
        hn = HN(slentry, self, datas)
        return TC(hn)


    def strip_SubjectPrefix(self, Subject):

        if Subject and ord(Subject[:1]) == 0x01:
            #prefix_length = ord(Subject[1:2])
            #return Subject[prefix_length+1:]
            return Subject[2:]
        else:
            return Subject



##############################################################################################################



class EntryID:

    def __init__(self, bytes):

        self.rgbFlags, self.uid, self.nid = struct.unpack('4s16s4s', bytes)
        self.nid = NID(self.nid)

    def __repr__(self):

        return 'EntryID %s' % self.nid



class SubFolder:

    def __init__(self, nid, name, parent_path):

        self.nid = nid
        self.name = name
        self.parent_path = parent_path

    def __repr__(self):

        return '%s (%s)' % (self.name, self.nid)



class SubMessage:

    def __init__(self, nid, SentRepresentingName, Subject, ClientSubmitTime):

        self.nid = nid
        self.SentRepresentingName = SentRepresentingName
        self.Subject = Subject
        self.ClientSubmitTime = ClientSubmitTime

    def __repr__(self):

        return '%s (%s)' % (self.Subject, self.nid)



class Folder:

    def __init__(self, nid, ltp, parent_path=''):

        if nid.nidType != NID.NID_TYPE_NORMAL_FOLDER:
            raise PSTException('Invalid Folder NID Type: %s' % nid.nidType)
        self.pc = ltp.get_pc_by_nid(nid)
        self.DisplayName = self.pc.getval(PropIdEnum.PidTagDisplayName)
        self.path = parent_path+'\\'+self.DisplayName
            
        #print 'FOLDER DEBUG', self.DisplayName, self.pc

        self.ContentCount = self.pc.getval(PropIdEnum.PidTagContentCount)
        self.ContainerClass = self.pc.getval(PropIdEnum.PidTagContainerClass)
        self.HasSubfolders = self.pc.getval(PropIdEnum.PidTagSubfolders)

        nid_hierachy = NID(nid.nidIndex | NID.NID_TYPE_HIERARCHY_TABLE)
        nid_contents = NID(nid.nidIndex | NID.NID_TYPE_CONTENTS_TABLE)
        nid_fai = NID(nid.nidIndex | NID.NID_TYPE_ASSOC_CONTENTS_TABLE) # FAI = Folder Associated Information

        try:
            self.tc_hierachy = None
            self.subfolders = []
            self.tc_hierachy = ltp.get_tc_by_nid(nid_hierachy)
            self.subfolders = [SubFolder(self.tc_hierachy.RowIndex[RowIndex].nid, self.tc_hierachy.getval(RowIndex,PropIdEnum.PidTagDisplayName), self.path) for RowIndex in range(len(self.tc_hierachy.RowIndex))]
        except PSTException as e:
            log_error(e)               

        try:
            self.tc_contents = None
            self.submessages = []
            self.tc_contents = ltp.get_tc_by_nid(nid_contents)
            self.submessages = [SubMessage(self.tc_contents.RowIndex[RowIndex].nid, \
                    self.tc_contents.getval(RowIndex,PropIdEnum.PidTagSentRepresentingNameW), ltp.strip_SubjectPrefix(self.tc_contents.getval(RowIndex,PropIdEnum.PidTagSubjectW)), \
                    self.tc_contents.getval(RowIndex,PropIdEnum.PidTagClientSubmitTime)) \
                    for RowIndex in range(len(self.tc_contents.RowIndex)) if RowIndex in self.tc_contents.RowIndex.keys()]
        except PSTException as e:
            log_error(e)                          

        try:
            self.tc_fai = None
            self.tc_fai = ltp.get_tc_by_nid(nid_fai)
        except PSTException as e:
            log_error(e)  


    def __repr__(self):

        return 'Folder: %s, %s items, messages: %s, subfolders: %s' % (self.DisplayName, len(self.submessages), self.subfolders)



class SubAttachment:

    def __init__(self, nid, AttachmentSize, AttachFilename, AttachLongFilename):

        self.nid, self.AttachmentSize, self.AttachFilename, self.AttachLongFilename = nid, AttachmentSize, AttachFilename, AttachLongFilename
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = '[None]' 

    def __repr__(self):

        return '%s (%s)' % (self.Filename, size_friendly(self.AttachmentSize))



class SubRecipient:

    def __init__(self, RecipientType, DisplayName, ObjectType, AddressType, EmailAddress, DisplayType):

        self.RecipientType, self.DisplayName, self.ObjectType, self.AddressType, self.EmailAddress, self.DisplayType = RecipientType, DisplayName, ObjectType, AddressType, EmailAddress, DisplayType


    def __repr__(self):

        return '%s (%s)' % (self.DisplayName, self.EmailAddress)


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


    def __init__(self, nid, ltp):

        if nid.nidType != NID.NID_TYPE_NORMAL_MESSAGE:
            raise PSTException('Invalid Message NID Type: %s' % nid_pc.nidType)
        self.ltp = ltp
        self.pc = ltp.get_pc_by_nid(nid)
        self.MessageClass = self.pc.getval(PropIdEnum.PidTagMessageClassW)
        self.Subject = ltp.strip_SubjectPrefix(self.pc.getval(PropIdEnum.PidTagSubjectW))
        self.ClientSubmitTime = self.pc.getval(PropIdEnum.PidTagClientSubmitTime)
        self.SentRepresentingName = self.pc.getval(PropIdEnum.PidTagSentRepresentingNameW)
        self.SenderName = self.pc.getval(PropIdEnum.PidTagSenderName)
        self.SenderSmtpAddress = self.pc.getval(PropIdEnum.PidTagSenderSmtpAddress)
        self.MessageDeliveryTime = self.pc.getval(PropIdEnum.PidTagMessageDeliveryTime)
        self.MessageFlags = self.pc.getval(PropIdEnum.PidTagMessageFlags)
        self.MessageStatus = self.pc.getval(PropIdEnum.PidTagMessageStatus)
        self.HasAttachments  = (self.MessageFlags & Message.mfHasAttach == Message.mfHasAttach)
        self.MessageSize = self.pc.getval(PropIdEnum.PidTagMessageSize)
        self.Body = self.pc.getval(PropIdEnum.PidTagBody)
        self.Read = (self.MessageFlags & Message.mfRead == Message.mfRead)
        self.TransportMessageHeaders = self.pc.getval(PropIdEnum.PidTagTransportMessageHeaders)
        self.DisplayTo = self.pc.getval(PropIdEnum.PidTagDisplayToW)
        self.XOriginatingIP =  self.pc.getval(0x8028) # x-originating-ip

        self.tc_attachments = None
        self.tc_recipients = None
        if self.pc.hn.subnodes:
            for subnode in self.pc.hn.subnodes.values(): #SLENTRYs
                if subnode.nid.nidType == NID.NID_TYPE_ATTACHMENT_TABLE:
                    self.tc_attachments = self.ltp.get_tc_by_slentry(subnode)
                elif subnode.nid.nidType == NID.NID_TYPE_RECIPIENT_TABLE:
                    self.tc_recipients = ltp.get_tc_by_slentry(subnode)
        
        self.subattachments = []
        if self.tc_attachments:
            self.subattachments = [SubAttachment(self.tc_attachments.RowIndex[RowIndex].nid, self.tc_attachments.getval(RowIndex,PropIdEnum.PidTagAttachmentSize), \
                    self.tc_attachments.getval(RowIndex,PropIdEnum.PidTagAttachFilename), self.tc_attachments.getval(RowIndex,PropIdEnum.PidTagAttachLongFilename)) for RowIndex in range(len(self.tc_attachments.RowIndex))]
        
        self.subrecipients = []
        if self.tc_recipients:
            self.subrecipients = [SubRecipient(self.tc_recipients.getval(RowIndex,PropIdEnum.PidTagRecipientType), self.tc_recipients.getval(RowIndex,PropIdEnum.PidTagDisplayName), \
                    self.tc_recipients.getval(RowIndex,PropIdEnum.PidTagObjectType), self.tc_recipients.getval(RowIndex,PropIdEnum.PidTagAddressType), \
                    self.tc_recipients.getval(RowIndex,PropIdEnum.PidTagEmailAddress), self.tc_recipients.getval(RowIndex,PropIdEnum.PidTagDisplayType)) for RowIndex in range(len(self.tc_recipients.RowIndex))]
        

    def get_attachment(self, subattachment):
        """ fetch attachment on demand, not when Message instanced"""
            
        return Attachment(self.ltp, self.pc.hn.subnodes[subattachment.nid.nid])


    def get_all_properties(self):

        return self.pc.__repr__()


    def __repr__(self):

        attachments = ', '.join(['%s' % subattachment for subattachment in self.subattachments])
        return 'Message: %s, From: %s, %s, Size: %s, Attachments: %s' % (repr(self.Subject), repr(self.SentRepresentingName), self.ClientSubmitTime, size_friendly(self.MessageSize), attachments)



class Attachment:

    def __init__(self, ltp, slentry):

        self.ltp = ltp
        self.slentry = slentry
        self.pc = self.ltp.get_pc_by_slentry(slentry)

        self.DisplayName = self.pc.getval(PropIdEnum.PidTagDisplayName)
        self.AttachMethod = self.pc.getval(PropIdEnum.PidTagAttachMethod)
        self.AttachmentSize = self.pc.getval(PropIdEnum.PidTagAttachmentSize)
        self.AttachFilename = self.pc.getval(PropIdEnum.PidTagAttachFilename) # 8.3 short name
        self.AttachLongFilename = self.pc.getval(PropIdEnum.PidTagAttachLongFilename)
        if self.AttachLongFilename:
            self.Filename = self.AttachLongFilename
        else:
            self.Filename = self.AttachFilename
        if self.Filename:
            self.Filename = os.path.basename(self.Filename)
        else:
            self.Filename = '[NoFilename_Method%s]' % self.AttachMethod        
        
        if self.AttachMethod == Message.afByValue:
            self.data = self.pc.getval(PropIdEnum.PidTagAttachDataBinary)
        else:
            self.data = self.pc.getval(PropIdEnum.PidTagAttachDataObject)
            #raise PSTException('Unsupported Attachment Method %s' % self.AttachMethod)
        self.AttachMimeTag = self.pc.getval(PropIdEnum.PidTagAttachMimeTag)
        self.AttachExtension = self.pc.getval(PropIdEnum.PidTagAttachExtension)


    def get_all_properties(self):

        return self.pc.__repr__()



class NAMEID:

    def __init__(self, bytes):

        self.dwPropertyID, self.wGuid, self.wPropIdx  = struct.unpack('IHH', bytes)
        self.N = self.wGuid & 0x01
        self.wGuid = self.wGuid >> 1
        self.NPID = self.wPropIdx + 0x8000



class Messaging:
    """Messaging Layer"""

    def __init__(self, ltp):

        self.ltp = ltp
        self.set_message_store()
        try:
            self.set_name_to_id_map()
        except PSTException as e:
            log_error(e)
            

    def set_message_store(self):

        self.message_store = self.ltp.get_pc_by_nid(NID(NID.NID_MESSAGE_STORE))        

        if PropIdEnum.PidTagPstPassword in self.message_store.props.keys():
            self.PasswordCRC32Hash = self.message_store.getval(PropIdEnum.PidTagPstPassword)
        else:
            self.PasswordCRC32Hash = None
        self.root_entryid = self.message_store.getval(PropIdEnum.PidTagIpmSubTreeEntryId)
        self.deleted_items_entryid = self.message_store.getval(PropIdEnum.PidTagIpmWastebasketEntryId)


    def set_name_to_id_map(self):

        self.nameid_entries = []
        self.pc_name_to_id_map = self.ltp.get_pc_by_nid(NID(NID.NID_NAME_TO_ID_MAP))

        nameid_entrystream = self.pc_name_to_id_map.getval(PropIdEnum.PidTagNameidStreamEntry)
        self.nameid_entries = [NAMEID(nameid_entrystream[i*8:(i+1)*8]) for i in range(len(nameid_entrystream)/8)]
        nameid_stringstream = self.pc_name_to_id_map.getval(PropIdEnum.PidTagNameidStreamString)
        nameid_guidstream = self.pc_name_to_id_map.getval(PropIdEnum.PidTagNameidStreamGuid)
        for nameid in self.nameid_entries:
            if nameid.N == 1:
                name_len = struct.unpack('I', nameid_stringstream[nameid.dwPropertyID:nameid.dwPropertyID+4])[0]
                nameid.name = nameid_stringstream[nameid.dwPropertyID+4:nameid.dwPropertyID+4+name_len].decode('utf-16-le') # unicode


    def get_folder(self, entryid, parent_path=''):

        return Folder(entryid.nid, self.ltp, parent_path)


    def get_named_properties(self):

        return '\n'.join(['%s = %s' % (hex(nameid.NPID), repr(nameid.name)) for nameid in self.nameid_entries if nameid.N==1])


##############################################################################################################


class FieldSize:
    BYTE = 1
    WORD = 2
    DWORD = 4
    ANSIDWORD = 8


class Header:
    
    def __init__(self, fd):

        # common ansi/unicode fields
        fd.seek(0)       
        self.dwMagic = fd.read(FieldSize.DWORD)
        self.dwCRCPartial = fd.read(FieldSize.DWORD) # ignore
        self.wMagicClient = fd.read(FieldSize.WORD)
        self.wVer, self.wVerClient, self.bPlatformCreate, self.bPlatformAccess = struct.unpack('HHBB',fd.read(FieldSize.WORD+FieldSize.WORD+FieldSize.BYTE+FieldSize.BYTE))
        self.dwReserved1 = fd.read(FieldSize.DWORD) # ignore
        self.dwReserved2 = fd.read(FieldSize.DWORD) # ignore

        self.validPST = (self.dwMagic == '!BDN' and self.wMagicClient == 'SM')
        if not self.validPST:
            return
        self.is_ansi = (self.wVer in (14, 15))
        self.is_unicode = (self.wVer == 23)
        if not (self.is_ansi or self.is_unicode):
            self.validPST = False
            return

        if self.is_ansi:
            self.bidNextB = BID(fd.read(FieldSize.DWORD))
            self.bidNextP = BID(fd.read(FieldSize.DWORD))
            self.dwUnique = fd.read(FieldSize.DWORD)
            self.rgnid = struct.unpack('IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', fd.read(128))
            self.root = Root(fd.read(40), True)
            self.rgbFM = fd.read(128) # unused
            self.rgbFP = fd.read(128) # unused
            self.bSentinel, self.bCryptMethod = struct.unpack('BB', fd.read(FieldSize.BYTE+FieldSize.BYTE))
            self.rgbReserved = fd.read(FieldSize.WORD) # unused
            self.ullReserved = fd.read(8) # unused
            self.dwReserved = fd.read(FieldSize.DWORD) # unused
            self.rgbReserved2 = fd.read(3) # unused
            self.bReserved = fd.read(1) # unused
            self.rgbReserved3 = fd.read(32) # unused

        if self.is_unicode:
            self.bidUnused = fd.read(FieldSize.ANSIDWORD) # unused 
            self.bidNextP = BID(fd.read(FieldSize.ANSIDWORD))
            #self.bidNextB = fd.read(FieldSize.ANSIDWORD) # the spec is wrong, example in appendix is correct
            self.dwUnique = fd.read(FieldSize.DWORD) # ignore
            self.rgnid = struct.unpack('IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII', fd.read(128))
            self.qwUnused = fd.read(FieldSize.ANSIDWORD) # unused
            self.root = Root(fd.read(72), False)
            self.dwAlign = fd.read(FieldSize.DWORD) # unused
            self.rgbFM = fd.read(128) # unused
            self.rgbFP = fd.read(128) # unused
            self.bSentinel, self.bCryptMethod = struct.unpack('BB', fd.read(FieldSize.BYTE+FieldSize.BYTE))
            self.rgbReserved = fd.read(FieldSize.WORD) # unused
            self.bidNextB = BID(fd.read(FieldSize.ANSIDWORD)) # repeated from above in spec
            self.dwCRCFull = fd.read(FieldSize.DWORD) # ignored
            self.rgbReserved2 = fd.read(3) # unused
            self.bReserved = fd.read(1) # unused
            self.rgbReserved3 = fd.read(32) # unused



class Root:

    def __init__(self, bytes, is_ansi):

        if is_ansi: # 40
            self.ibFileEof, self.ibAMapLast, self.cbAMapFree, self.cbPMapFree, self.BREFNBT, self.BREFBBT, self.fAMapValid = \
                struct.unpack('IIII8s8sB', bytes[4:-3])
        else: #unicode #72
            self.ibFileEof, self.ibAMapLast, self.cbAMapFree, self.cbPMapFree, self.BREFNBT, self.BREFBBT, self.fAMapValid = \
                struct.unpack('QQQQ16s16sB', bytes[4:-3])
        self.BREFNBT = BREF(self.BREFNBT)
        self.BREFBBT = BREF(self.BREFBBT)



class PST:

    def __init__(self, pst_file):

        self.fd = open(pst_file,'rb')
        self.header = Header(self.fd)
        if not self.header.validPST:
            raise PSTException('PST file is not a valid PST')

        if self.header.bCryptMethod not in (0,1): # unencoded or NDB_CRYPT_PERMUTE
            raise PSTException('Unsupported encoding/crypt method %s' % self.header.bCryptMethod)

        self.nbd = NBD(self.fd, self.header)
        self.ltp = LTP(self.nbd)
        self.messaging = Messaging(self.ltp)


    def close(self):

        self.fd.close()


    def folder_generator(self):

        root_folder = self.messaging.get_folder(self.messaging.root_entryid, '')
        subfolder_stack = root_folder.subfolders
        yield root_folder

        #Deleted Items should also be in root folder, so don't need to get this one
        #bin_folder = self.messaging.get_folder(self.messaging.deleted_items_entryid, '')        
        #subfolder_stack.extend(bin_folder.subfolders)
        #yield bin_folder

        while subfolder_stack:
            subfolder = subfolder_stack.pop()
            try:
                folder = Folder(subfolder.nid, self.ltp, subfolder.parent_path)
                subfolder_stack.extend(folder.subfolders)
                yield folder
            except PSTException as e:
                log_error(e)    


    def message_generator(self, folder):

        try:
            for submessage in folder.submessages:
                try:
                    message = Message(submessage.nid, self.ltp)
                    yield message
                except PSTException as e:
                    log_error(e)                 
        except GeneratorExit:
            pass
        finally: 
            pass

  
    def export_all_attachments(self, path='', progressbar = None, total_attachments = 0, overwrite=True):
        """dumps all attachments in the PST to a path"""

        attachments_completed = 0
        for folder in self.folder_generator():
            for message in self.message_generator(folder):
                if message.HasAttachments:
                    for subattachment in message.subattachments:
                        attachment = message.get_attachment(subattachment)
                        if len(attachment.data) !=0:
                            filepath = os.path.join(path, attachment.Filename)                        
                            if overwrite:
                                if os.path.exists(filepath):
                                    os.remove(filepath)
                            else:
                                filepath = get_unused_filename(filepath)
                            write_file(filepath, attachment.data, 'wb')
                        attachments_completed += 1
                        if progressbar:
                            progressbar.update(attachments_completed * 100.0 / total_attachments)


    def export_all_messages(self, path='', progressbar = None, total_messages = 0):

        messages_completed = 0
        for folder in self.folder_generator():
            filepath = get_unused_filename(os.path.join(path, get_safe_filename(folder.path.replace('\\','_'))+'.txt'))
            msg_txt = u''
            for message in self.message_generator(folder):
                msg_txt += u'Subject: %s\nFrom: %s (%s)\n' % (message.Subject, message.SenderName, message.SenderSmtpAddress)
                msg_txt += u'To: %s\n' % ('; '.join([u'%s (%s)' % (subrecipient.DisplayName, subrecipient.EmailAddress) for subrecipient in message.subrecipients]))
                msg_txt += u'Sent: %s\nDelivered: %s\n' % (message.ClientSubmitTime, message.MessageDeliveryTime)
                msg_txt += u'MessageClass: %s\n' % (message.MessageClass)
                if message.HasAttachments:
                    msg_txt += u'Attachments: %s\n' % (u', '.join([subattachment.__repr__() for subattachment in message.subattachments]))
                msg_txt += u'\n%s\n\n\n' % message.Body
            if msg_txt:
                write_file(filepath, unicode2ascii(msg_txt), 'w')
                messages_completed += 1
                if progressbar:
                    progressbar.update(messages_completed * 100.0 / total_messages)


    def get_total_message_count(self):

        total_message_count = 0
        for folder in self.folder_generator():
            total_message_count += len(folder.submessages)
        return total_message_count


    def get_total_attachment_count(self):

        total_attachment_count = 0
        for folder in self.folder_generator():
            for message in self.message_generator(folder):
                if message.HasAttachments:
                    total_attachment_count += len(message.subattachments)
        return total_attachment_count


    def get_pst_status(self):

        status = u'Valid PST: %s, Unicode: %s, CryptMethod: %s, Name: %s, Password: %s' % (self.header.validPST, self.header.is_unicode, self.header.bCryptMethod, self.messaging.message_store.getval(PropIdEnum.PidTagDisplayName), self.messaging.PasswordCRC32Hash)
        return status

                       


#################### GENERAL FUNCTIONS #########################


def hex(i):

    return '0x%x' % i


def bin_bytes(bytes):

    return ''.join([bin(ord(c)).lstrip('0b').zfill(8) for c in bytes])


def bit_shift_bytes_left(bytes, offset):

    new_bytes = ''
    for c in bytes:        
        new_bytes += chr( ord(c) << offset)
    return new_bytes


def size_friendly(size):

    if size < 1024:
        return '%sB' % (size)
    elif size < 1024*1024:
        return '%sKB' % (size/1024)
    elif size < 1024*1024*1024:
        return '%sMB' % (size/(1024*1024))
    else:
        return '%sGB' % (size/(1024*1024*1024))


def unicode2ascii(unicode_str):

    return unicodedata.normalize('NFKD', unicode_str).encode('ascii','ignore')


def write_file(fn, s, write_mode='w'):

    f = open(fn,write_mode)
    f.write(s)
    f.close()


def get_unused_filename(filepath):
    """ adds numbered suffix to filepath if filename already exists"""

    if os.path.exists(filepath):
        suffix = 1
        while os.path.exists('%s-%s%s' % (os.path.splitext(filepath)[0], suffix, os.path.splitext(filepath)[1])):
            suffix += 1
        filepath = '%s-%s%s' % (os.path.splitext(filepath)[0], suffix, os.path.splitext(filepath)[1])
    return filepath


def get_safe_filename(filename):

    return re.sub(r'[/\\;,><&\*:%=\+@!#\^\(\)|\?]', '', filename)


def log_error(e):

    global error_log_list
    error_log_list.append(e.message)
    sys.stderr.write(e.message+'\n')


########################## TEST/EXAMPLES ###############################


def test_status_pst(pst_filepath):

    pst = PST(pst_filepath)
    print unicode2ascii(pst.get_pst_status())
    print 'Total Messages: %s' % pst.get_total_message_count()
    print 'Total Attachments: %s' % pst.get_total_attachment_count()
    pst.close()


def get_simple_progressbar(title):

        pbar_widgets = [title, progressbar.Percentage(), ' ', progressbar.Bar(marker = progressbar.RotatingMarker()), ' ', progressbar.ETA()]
        pbar = progressbar.ProgressBar(widgets = pbar_widgets).start()
        return pbar


def test_dump_pst(pst_filepath, output_path):
    """ dump out all PST email attachments and emails (into text files) to output_path folder"""

    pst = PST(pst_filepath)
    print pst.get_pst_status()

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

    global error_log_list

    s = ''
    for pst_filepath in [os.path.join(psts_folder, filename) for filename in os.listdir(psts_folder) if os.path.isfile(os.path.join(psts_folder, filename)) and os.path.splitext(filename.lower())[1] == '.pst']:
        try:
            s += 'Opening %s\n' % pst_filepath
            error_log_list = []
            pst = PST(pst_filepath)
            status = unicode2ascii(pst.get_pst_status())
            print status
            s += status +'\n'
            pst.close()
            s += '\n'.join(error_log_list)
            s += '\n\n\n'
        except Exception as e:
            s += 'ERROR: %s\n' % e

    write_file(os.path.join(psts_folder, 'psts_test.txt'), s)
     
        


########################## MAIN #######################################


if __name__=="__main__":

    input_pst_file = ''
    output_folder = 'dump'

    arg_parser = argparse.ArgumentParser(prog='pst', description='PST: parses PST files. Can dump emails and attachments.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-i', dest='input_pst_file', default=input_pst_file, help='input PST file to dump')
    arg_parser.add_argument('-o', dest='output_folder', default=output_folder, help='output folder')
    arg_parser.add_argument('-t', dest='debug', help=argparse.SUPPRESS, action='store_true', default=False) # hidden argument

    args = arg_parser.parse_args()    

    if not args.debug:

        input_pst_file = args.input_pst_file
        output_folder = args.output_folder

        if not os.path.exists(input_pst_file):
            print 'Input PST file does not exist'
            sys.exit(1)

        if not os.path.exists(output_folder):
            print 'Output folder does not exist'
            sys.exit(1)

        test_dump_pst(input_pst_file,output_folder)

    else: # debug

        pass
        #test_folder = 'D:\\test\\'
        #test_status_pst(test_folder+'sample.pst')
        #test_dump_pst(test_folder+'sample.pst', test_folder+'dump')
        #test_folder_psts(test_folder)