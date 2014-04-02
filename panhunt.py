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
import filehunt
import pst
import platform

########## CLASSES ######################


class PANFile(filehunt.AFile):
    """ PANFile: class for a file that can check itself for PANs"""

    def __init__(self, filename, file_dir):
        
        filehunt.AFile.__init__(self, filename, file_dir)
        self.pans = []
        #self.type = None # DOC, ZIP, MAIL, DB, OTHER


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
                file_text = filehunt.read_file(self.path, 'rb')
                self.check_text_for_pans(file_text, pan_regexs, '')
            except WindowsError:
                self.set_error(sys.exc_info()[1])
            except IOError:
                self.set_error(sys.exc_info()[1])
        return self.pans


    def check_pst_for_pans(self, pan_regexs, doc_extensions, zip_extensions):
        """ Searches a pst file for PANs in messages and attachments using regular expressions"""

        all_extensions = doc_extensions + zip_extensions

        pbar_widgets = ['PAN Hunt %s: ' % filehunt.unicode2ascii(self.filename), progressbar.Percentage(), ' ', progressbar.Bar(marker = progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' PANs:0')]
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
        except pst.PSTException:
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
                    self.check_zip_for_pans(nested_zf, pan_regexs, doc_extensions, zip_extensions, os.path.join(sub_path, filehunt.decode_zip_filename(file_in_zip)))
                except: #RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            else: #normal doc
                try:
                    file_text = zf.open(file_in_zip).read()
                    self.check_text_for_pans(file_text, pan_regexs, os.path.join(sub_path, filehunt.decode_zip_filename(file_in_zip)))
                except: # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])     


    def check_text_for_pans(self, text, pan_regexs, sub_path):
        """Uses regular expressions to check for PANs in text"""

        for brand, regex in pan_regexs.items():
            pans = regex.findall(text)
            if pans:
                for pan in pans:
                    if PAN.is_valid_luhn_checksum(pan):
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


    @staticmethod
    def is_valid_luhn_checksum(pan):
        """ from wikipedia: http://en.wikipedia.org/wiki/Luhn_algorithm"""

        pan = re.sub('[^\d]','', pan)

        def digits_of(n):
            return [int(d) for d in str(n)]

        digits = digits_of(pan)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = 0
        checksum += sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d*2))
        
        return checksum % 10 == 0
        


################ MODULE FUNCTIONS #################



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

    if type(text) is unicode:
        encoded_text = text.encode('utf-8')
    else:
        encoded_text = text
    return hashlib.sha512(encoded_text+'PAN').hexdigest()


def add_hash_to_file(text_file):

    text = filehunt.read_unicode_file(text_file)
    hash_check = get_text_hash(text)

    text += os.linesep + get_text_hash(text)
    filehunt.write_unicode_file(text_file, text)


def check_file_hash(text_file):
    
    text_output = filehunt.read_unicode_file(text_file)
    hash_pos = text_output.rfind(os.linesep)
    hash_in_file =  text_output[hash_pos+len(os.linesep):]
    hash_check = get_text_hash(text_output[:hash_pos])
    if hash_in_file == hash_check:
        print colorama.Fore.GREEN + 'Hashes OK'
    else:
        print colorama.Fore.RED + 'Hashes Not OK'
    print colorama.Fore.WHITE + hash_in_file +'\n' + hash_check


def output_report(search_dir, excluded_directories_string, doc_files, total_docs, pans_found, output_file):

    pan_sep = u'\n\t'
    pan_report = u'PAN Hunt Report - %s\n%s\n' % (time.strftime("%H:%M:%S %d/%m/%Y"), '='*100)
    pan_report += u'Searched %s\nExcluded %s\n' % (search_dir, excluded_directories_string)
    pan_report += u'Command: %s\n' % (' '.join(sys.argv))
    pan_report += u'Uname: %s\n' % (' | '.join(platform.uname()))
    pan_report += u'Searched %s documents. Found %s possible PANs.\n%s\n\n' % (total_docs, pans_found, '='*100)
    
    for afile in sorted([afile for afile in doc_files if afile.pans]):
        pan_header = u'FOUND PANs: %s (%s %s)' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))
        print colorama.Fore.RED + filehunt.unicode2ascii(pan_header)
        pan_report += pan_header + '\n'
        pan_list = u'\t' + pan_sep.join([pan.__repr__(mask_pans) for pan in afile.pans])
        print colorama.Fore.YELLOW + filehunt.unicode2ascii(pan_list)
        pan_report += pan_list + '\n\n'
    
    if len([afile for afile in doc_files if afile.type == 'OTHER']) <> 0:
        pan_report += u'Interesting Files to check separately:\n'
    for afile in sorted([afile for afile in doc_files if afile.type == 'OTHER']):
        pan_report += u'%s (%s %s)\n' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))

    pan_report = pan_report.replace('\n', os.linesep)

    print colorama.Fore.WHITE + 'Report written to %s' % filehunt.unicode2ascii(output_file)
    filehunt.write_unicode_file(output_file, pan_report)
    add_hash_to_file(output_file)



################ MAIN #################


if __name__ == "__main__":

    colorama.init()

    # defaults
    search_dir = u'C:\\'
    output_file = u'pans_found_%s.txt' % time.strftime("%Y-%m-%d-%H%M%S")
    excluded_directories_string = u'C:\\Windows,C:\\Program Files,C:\\Program Files (x86)'
    doc_extensions_string =  u'.doc,.xls,.xml,.txt,.csv'
    zip_extensions_string = u'.docx,.xlsx,.zip'
    
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
    
    search_dir = unicode(args.search)
    output_file = unicode(args.outfile)
    excluded_directories_string = unicode(args.exclude)
    doc_extensions_string = unicode(args.docfiles)
    zip_extensions_string = unicode(args.zipfiles)
    mask_pans = not args.unmask

    excluded_directories = [exc_dir.lower() for exc_dir in excluded_directories_string.split(',')]

    search_extensions = {}
    search_extensions['DOC'] = doc_extensions_string.split(',')
    search_extensions['ZIP'] = zip_extensions_string.split(',')
    search_extensions['MAIL'] = [u'.pst']
    search_extensions['OTHER'] = [u'.ost', u'.accdb', u'.mdb'] # checks for existence of files that can't be checked automatically
    # TO DO: how about network drives, other databases?

    pan_regexs = {'Mastercard': re.compile('(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                    'Visa': re.compile('(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                    'AMEX': re.compile('(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)')}

    # find all files to check
    doc_files = filehunt.find_all_files_in_directory(PANFile, search_dir, excluded_directories, search_extensions)

    # check each file
    total_docs, doc_pans_found = find_all_pans_in_files([afile for afile in doc_files if not afile.errors and afile.type in ('DOC','ZIP')], pan_regexs, search_extensions['DOC'], search_extensions['ZIP'])
    # check each pst message and attachment
    total_psts, pst_pans_found = find_all_pans_in_psts([afile for afile in doc_files if not afile.errors and afile.type == 'MAIL'], pan_regexs, search_extensions['DOC'], search_extensions['ZIP'])

    pans_found = doc_pans_found + pst_pans_found

    # report findings
    output_report(search_dir, excluded_directories_string, doc_files, total_docs, pans_found, output_file)