#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# filehunt: general file searching library for use by PANhunt and PassHunt
# By BB

import os, sys, zipfile, re, datetime, cStringIO, argparse, time, hashlib, unicodedata, codecs
import colorama
import progressbar


class AFile:
    """ AFile: class for a file that can search itself"""

    def __init__(self, filename, file_dir):
        
        self.filename = filename
        self.dir = file_dir
        self.path = os.path.join(self.dir, self.filename)
        self.root, self.ext = os.path.splitext(self.filename)
        self.errors = []
        self.type = None


    def __cmp__(self, other):
    
        return cmp(self.path.lower(), other.path.lower())


    def set_file_stats(self):

        try:
            stat = os.stat(self.path)
            self.size = stat.st_size
            self.accessed = self.dtm_from_ts(stat.st_atime)
            self.modified = self.dtm_from_ts(stat.st_mtime)
            self.created = self.dtm_from_ts(stat.st_ctime)
        except WindowsError:
            self.size = -1
            self.set_error(sys.exc_info()[1])            
            

    def dtm_from_ts(self, ts):
        
        try:
            return datetime.datetime.fromtimestamp(ts)
        except ValueError: 
            if ts == -753549904:
                return datetime.datetime(1946, 2, 14, 8, 34, 56) # Mac OSX "while copying" thing
            else:
                self.set_error(sys.exc_info()[1])                         


    def size_friendly(self):

        if self.size < 1024:
            return '%sB' % (self.size)
        elif self.size < 1024*1024:
            return '%sKB' % (self.size/1024)
        elif self.size < 1024*1024*1024:
            return '%sMB' % (self.size/(1024*1024))
        else:
            return '%sGB' % (self.size/(1024*1024*1024))


    def set_error(self, error_msg):

        self.errors.append(error_msg)
        print colorama.Fore.RED + unicode2ascii(u'ERROR %s on %s' % (error_msg, self.path)) + colorama.Fore.WHITE



#################### MODULE FUNCTIONS ##############################


def find_all_files_in_directory(AFileClass, root_dir, excluded_directories, search_extensions):
    """Recursively searches a directory for files. search_extensions is a dictionary of extension lists"""
    
    all_extensions = [ext for ext_list in search_extensions.values() for ext in ext_list]

    extension_types = {}
    for ext_type, ext_list in search_extensions.iteritems():
        for ext in ext_list:
            extension_types[ext] = ext_type

    pbar_widgets = ['Doc Hunt: ', progressbar.Percentage(), ' ', progressbar.Bar(marker = progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' Docs:0')]
    pbar = progressbar.ProgressBar(widgets = pbar_widgets).start()

    doc_files = []
    root_dir_dirs = None
    root_items_completed = 0
    docs_found = 0

    for root, sub_dirs, files in os.walk(root_dir):
        sub_dirs[:] = [check_dir for check_dir in sub_dirs if os.path.join(root, check_dir).lower() not in excluded_directories]
        if not root_dir_dirs:
             root_dir_dirs = [os.path.join(root, sub_dir) for sub_dir in sub_dirs]
             root_total_items = len(root_dir_dirs) + len(files)
        if root in root_dir_dirs:
            root_items_completed += 1
            pbar_widgets[6] = progressbar.FormatLabel(' Docs:%s' % docs_found)
            pbar.update(root_items_completed * 100.0 / root_total_items)
        for filename in files:
            if root == root_dir:
                root_items_completed += 1
            afile = AFileClass(filename, root) # AFile or PANFile
            if afile.ext.lower() in all_extensions:
                afile.set_file_stats()
                afile.type = extension_types[afile.ext.lower()]
                doc_files.append(afile)
                if not afile.errors:
                    docs_found += 1    
                pbar_widgets[6] = progressbar.FormatLabel(' Docs:%s' % docs_found)
                pbar.update(root_items_completed * 100.0 / root_total_items)

    pbar.finish()
    return doc_files




#################### UTILITY FUNCTIONS ############################


def save_object(fn, obj):

    pkl_file = open(fn, 'wb')
    pickle.dump(obj, pkl_file, -1)
    pkl_file.close()


def load_object(fn):

    pkl_file = open(fn, 'rb')
    obj = pickle.load(pkl_file)
    pkl_file.close()
    return obj


def read_file(fn, open_mode="r"):
    f = open(fn, open_mode)
    s = f.read()
    f.close()
    return s


def write_file(fn,s):

    f = open(fn,"w")
    f.write(s)
    f.close()


def write_unicode_file(fn,s):

    f = codecs.open(fn, encoding='utf-8', mode='w')
    f.write(s)
    f.close()


def write_csv(fn,dlines):

    f = open(fn,"w")
    for d in dlines:
        s = ','.join(['"%s"' % str(i).replace('"',"'") for i in d])
        f.write('%s\n' % s)
    f.close()


def unicode2ascii(unicode_str):

    return unicodedata.normalize('NFKD', unicode_str).encode('ascii','ignore')


def decode_zip_filename(str):

    if type(str) is unicode:
        return str
    else:
        return str.decode('cp437')


