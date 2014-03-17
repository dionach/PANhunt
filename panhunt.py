#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# PANhunt: search directories and sub directories for documents with PANs
# By BB

import os, sys, zipfile, re, datetime, cStringIO, argparse, time, hashlib, unicodedata
import colorama
import progressbar
import pst

########## CLASSES ######################


class AFile:
    """ AFile: class for a file that can check itself for PANs"""

    def __init__(self, filename, file_dir):
        
        self.filename = filename
        self.dir = file_dir
        self.path = os.path.join(self.dir, self.filename)
        self.root, self.ext = os.path.splitext(self.filename)
        self.errors = []
        self.pans = []
        self.type = None # DOC, ZIP, MAIL, DB, OTHER


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
                          
                      
    def sizeK(self):
        
        return int(self.size/1024)


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
        print colorama.Fore.RED + 'ERROR %s on %s' % (error_msg, self.path) + colorama.Fore.WHITE


    def check_for_pans(self, pan_regexs, doc_extensions, zip_extensions):
        """Checks the file for PANs: if a ZIP then each file in the ZIP (recursively) or the text in a document"""

        if self.type == 'ZIP':
            try:
                if zipfile.is_zipfile(self.path):
                    zf = zipfile.ZipFile(self.path)
                    self.check_zip_for_pans(zf, pan_regexs, doc_extensions, zip_extensions, '')                                             
                else:
                    self.set_error('Invalid ZIP file')
            except IOError:
                self.set_error(sys.exc_info()[1])
        elif self.type == 'DOC':
            try:
                file_text = read_file(self.path, 'rb')
                self.check_text_for_pans(file_text, pan_regexs, '')
            except WindowsError:
                self.set_error(sys.exc_info()[1])
            except IOError:
                self.set_error(sys.exc_info()[1])
        return self.pans


    def check_pst_for_pans(self, pan_regexs, doc_extensions, zip_extensions):
        """ Searches a pst file for PANs in messages and attachments using regular expressions"""

        all_extensions = doc_extensions + zip_extensions

        pbar_widgets = ['PAN Hunt %s: ' % self.filename, progressbar.Percentage(), ' ', progressbar.Bar(marker = progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' PANs:0')]
        pbar = progressbar.ProgressBar(widgets = pbar_widgets).start()

        try:
            apst = pst.PST(self.path)

            total_messages = apst.get_total_message_count()
            total_attachments = apst.get_total_attachment_count()
            total_items = total_messages + total_attachments
            items_completed = 0

            for folder in apst.folder_generator():
                for message in apst.message_generator(folder):
                    if message.Subject:
                        message_path = os.path.join(folder.path, message.Subject)
                    else:
                        message_path = os.path.join(folder.path, u'[NoSubject]')
                    if message.Body:
                        self.check_text_for_pans(message.Body, pan_regexs, message_path)
                    if message.HasAttachments:
                        for subattachment in message.subattachments:
                            attachment_ext = os.path.splitext(subattachment.Filename)[1].lower()
                            if attachment_ext in doc_extensions:
                                attachment = message.get_attachment(subattachment)
                                if attachment.data:
                                    self.check_text_for_pans(attachment.data, pan_regexs, os.path.join(message_path, subattachment.Filename))
                            if attachment_ext in zip_extensions:
                                attachment = message.get_attachment(subattachment)
                                if attachment.data:
                                    try:
                                        memory_zip = cStringIO.StringIO()
                                        memory_zip.write(attachment.data)
                                        zf = zipfile.ZipFile(memory_zip)
                                        self.check_zip_for_pans(zf, pan_regexs, doc_extensions, zip_extensions, os.path.join(message_path, subattachment.Filename))
                                    except: #RuntimeError: # e.g. zip needs password
                                        self.set_error(sys.exc_info()[1])
                            items_completed += 1
                    items_completed += 1
                    pbar_widgets[6] = progressbar.FormatLabel(' PANs:%s' % len(self.pans))
                    pbar.update(items_completed * 100.0 / total_items)
    
            apst.close()    

        except IOError:
            self.set_error(sys.exc_info()[1])
                            
        pbar.finish()
        return self.pans


    def check_zip_for_pans(self, zf, pan_regexs, doc_extensions, zip_extensions, sub_path):
        """Checks a zip file for valid documents that are then checked for PANs"""

        files_in_zip = [file_in_zip for file_in_zip in zf.namelist() if os.path.splitext(file_in_zip)[1] in doc_extensions or os.path.splitext(file_in_zip)[1] in zip_extensions]
        for file_in_zip in files_in_zip:
            if os.path.splitext(file_in_zip)[1] in zip_extensions: # nested zip file
                try:
                    memory_zip = cStringIO.StringIO()
                    memory_zip.write(zf.open(file_in_zip).read())
                    nested_zf = zipfile.ZipFile(memory_zip)
                    self.check_zip_for_pans(nested_zf, pan_regexs, doc_extensions, zip_extensions, os.path.join(sub_path, file_in_zip.decode('latin-1')))
                except: #RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            else: #normal doc
                try:
                    file_text = zf.open(file_in_zip).read()
                    self.check_text_for_pans(file_text, pan_regexs, os.path.join(sub_path, file_in_zip.decode('latin-1')))   
                except: # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])     


    def check_text_for_pans(self, text, pan_regexs, sub_path):
        """Uses regular expressions to check for PANs in text"""

        for brand, regex in pan_regexs.items():
            pans = regex.findall(text)
            if pans:
                for pan in pans:
                    self.pans.append(PAN(self.path, sub_path, brand, pan))


class PAN:
    """PAN: A class for recording PANs, their brand and where they were found"""

    def __init__(self, path, sub_path, brand, pan):
        
        self.path, self.sub_path, self.brand, self.pan = path, sub_path, brand, pan


    def __repr__(self, mask_pan=True):

        if mask_pan:
            pan_out = self.get_masked_pan()
        else:
            pan_out = self.pan
        return '%s %s:%s' % (self.sub_path, self.brand, pan_out)


    def get_masked_pan(self):
        return re.sub('\d','*',self.pan[:-4]) + self.pan[-4:]

        
################ UTILITY FUNCTIONS #################


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


def write_csv(fn,dlines):

    f = open(fn,"w")
    for d in dlines:
        s = ','.join(['"%s"' % str(i).replace('"',"'") for i in d])
        f.write('%s\n' % s)
    f.close()


def unicode2ascii(unicode_str):

    return unicodedata.normalize('NFKD', unicode_str).encode('ascii','ignore')


################ MODULE FUNCTIONS #################


def find_all_files_in_directory(root_dir, excluded_directories, doc_extensions, zip_extensions, mail_extensions, database_extensions):
    """Recursively searches a directory for files with document or archive extensions"""

    all_extensions = doc_extensions + zip_extensions + mail_extensions + database_extensions

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
            #print colorama.Fore.CYAN +'LOOKING FOR DOCUMENTS IN %s ' % root
            pbar_widgets[6] = progressbar.FormatLabel(' Docs:%s' % docs_found)
            pbar.update(root_items_completed * 100.0 / root_total_items)
        for filename in files:
            if root == root_dir:
                root_items_completed += 1
            afile = AFile(filename, root)
            if afile.ext.lower() in all_extensions:
                afile.set_file_stats()
                if afile.ext.lower() in doc_extensions:
                    afile.type = 'DOC'
                elif afile.ext.lower() in zip_extensions:
                    afile.type = 'ZIP'
                elif afile.ext.lower() in mail_extensions:
                    afile.type = 'MAIL'
                elif afile.ext.lower() in interesting_extensions:
                    afile.type = 'OTHER'
                doc_files.append(afile)
                if not afile.errors:
                    docs_found += 1    
                pbar_widgets[6] = progressbar.FormatLabel(' Docs:%s' % docs_found)
                pbar.update(root_items_completed * 100.0 / root_total_items)

    pbar.finish()
    return doc_files


def find_all_pans_in_files(doc_files, pan_regexs, doc_extensions, zip_extensions):
    """ Searches files in doc_files list for PANs using regular expressions"""

    pbar_widgets = ['PAN Hunt: ', progressbar.Percentage(), ' ', progressbar.Bar(marker = progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' PANs:0')]
    pbar = progressbar.ProgressBar(widgets = pbar_widgets).start()
    total_docs = len(doc_files)
    docs_completed = 0
    pans_found = 0

    for afile in doc_files:
        pans = afile.check_for_pans(pan_regexs, doc_extensions, zip_extensions)
        pans_found += len(pans)
        docs_completed += 1
        pbar_widgets[6] = progressbar.FormatLabel(' PANs:%s' % pans_found)
        pbar.update(docs_completed * 100.0 / total_docs)
    pbar.finish()

    return total_docs, pans_found


def find_all_pans_in_psts(pst_files, pan_regexs, doc_extensions, zip_extensions):
    """ Searches psts in pst_files list for PANs in messages and attachments using regular expressions"""

    total_psts = len(pst_files)
    psts_completed = 0
    pans_found = 0

    for afile in pst_files:
        pans = afile.check_pst_for_pans(pan_regexs, doc_extensions, zip_extensions)
        pans_found += len(pans)
        psts_completed += 1

    return total_psts, pans_found


def get_text_hash(text):

    return hashlib.sha512(text+'PAN').hexdigest()


def check_file_hash(text_file):
    
    text_output = read_file(text_file)
    hash_pos = text_output.rfind('\n')
    hash_in_file =  text_output[hash_pos+1:]
    hash_check = get_text_hash(text_output[:hash_pos])
    if hash_in_file == hash_check:
        print colorama.Fore.GREEN + 'Hashes OK'
    else:
        print colorama.Fore.RED + 'Hashes Not OK'
    print colorama.Fore.WHITE + hash_in_file +'\n' + hash_check


################ MAIN #################

if __name__ == "__main__":

    colorama.init()

    # defaults
    search_dir = 'C:\\'
    output_file = 'pans_found.txt'
    excluded_directories_string = 'C:\\Windows,C:\\Program Files,C:\\Program Files (x86)'
    doc_extensions_string =  '.doc,.xls,.xml,.txt,.csv'
    zip_extensions_string = '.docx,.xlsx,.zip'
    
    # Command Line Arguments
    arg_parser = argparse.ArgumentParser(prog='panhunt', description='PAN Hunt: search directories and sub directories for documents containing PANs.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-s', dest='search', default=search_dir, help='base directory to search in')
    arg_parser.add_argument('-x', dest='exclude', default=excluded_directories_string, help='directories to exclude from the search')
    arg_parser.add_argument('-d', dest='docfiles', default=doc_extensions_string, help='document file extensions to search')
    arg_parser.add_argument('-z', dest='zipfiles', default=zip_extensions_string, help='zip file extensions to search')
    arg_parser.add_argument('-o', dest='outfile', default=output_file, help='output file name for PAN report')
    arg_parser.add_argument('-u', dest='unmask', action='store_true', default=False, help='unmask PANs in output')
    arg_parser.add_argument('-c', dest='checkfilehash', help=argparse.SUPPRESS) # hidden argument

    args = arg_parser.parse_args()    
    
    if args.checkfilehash:
        check_file_hash(args.checkfilehash)
        sys.exit()
    
    search_dir = args.search
    output_file = args.outfile
    excluded_directories_string = args.exclude
    doc_extensions_string = args.docfiles
    zip_extensions_string = args.zipfiles     
    mask_pans = not args.unmask

    excluded_directories = [exc_dir.lower() for exc_dir in excluded_directories_string.split(',')]
    doc_extensions = doc_extensions_string.split(',')
    zip_extensions = zip_extensions_string.split(',')
    mail_extensions = ['.pst']
    interesting_extensions = ['.ost', '.accdb','.mdb'] # checks for existence of files that can't be checked automatically
    # TO DO: how about network drives, other databases?

    pan_regexs = {'Mastercard': re.compile('(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                    'Visa': re.compile('(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                    'AMEX': re.compile('(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)')}

    # find all files to check
    doc_files = find_all_files_in_directory(search_dir, excluded_directories, doc_extensions, zip_extensions, mail_extensions, interesting_extensions)
    
    # check each file
    total_docs, doc_pans_found = find_all_pans_in_files([afile for afile in doc_files if not afile.errors and afile.type in ('DOC','ZIP')], pan_regexs, doc_extensions, zip_extensions)
    # check each pst message and attachment
    total_psts, pst_pans_found = find_all_pans_in_psts([afile for afile in doc_files if not afile.errors and afile.type == 'MAIL'], pan_regexs, doc_extensions, zip_extensions)

    pans_found = doc_pans_found + pst_pans_found

    # report findings
    pan_sep = '\n\t'
    pan_report = 'PAN Hunt Report - %s\n%s\n' % (time.strftime("%H:%M:%S %d/%m/%Y"), '='*50)
    pan_report += 'Searched %s\nExcluded %s\n' % (search_dir, excluded_directories_string)
    pan_report += 'Searched %s documents. Found %s possible PANs.\n%s\n\n' % (total_docs, pans_found, '='*50)
    
    for afile in sorted([afile for afile in doc_files if afile.pans]):
        pan_header = 'FOUND PANs: %s (%s %s)' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))
        print colorama.Fore.RED + pan_header
        pan_report += pan_header + '\n'
        pan_list = '\t' + pan_sep.join([pan.__repr__(mask_pans) for pan in afile.pans])
        print colorama.Fore.YELLOW + pan_list
        pan_report += pan_list + '\n\n'
    
    if len([afile for afile in doc_files if afile.type == 'OTHER']) <> 0:
        pan_report += 'Interesting Files to check separately:\n'
    for afile in sorted([afile for afile in doc_files if afile.type == 'OTHER']):
        pan_report += '%s (%s %s)\n' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))

    pan_report = unicode2ascii(pan_report)
    pan_report += '\n%s' % (get_text_hash(pan_report))

    print colorama.Fore.WHITE + 'Report written to %s' % output_file
    write_file(output_file, pan_report)