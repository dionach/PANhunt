#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# PANhunt: search directories and sub directories for documents with PANs
# By BB

import argparse
import configparser
import hashlib
import io
import os
import platform
import re
import sys
import time
import zipfile
from datetime import datetime
from typing import Any, Optional

import colorama
import progressbar

import msmsg  # MS-MSG files
import panutils
import pst

TEXT_FILE_SIZE_LIMIT: int = 1073741824  # 1Gb

app_version = '1.3'

# defaults
defaults: dict[str, str] = {
    'search_dir': 'C:\\',
    'output_file': 'panhunt_%s.txt' % time.strftime("%Y-%m-%d-%H%M%S"),
    'excluded_directories_string': 'C:\\Windows,C:\\Program Files,C:\\Program Files (x86)',
    'text_extensions_string': '.doc,.xls,.xml,.txt,.csv,.log',
    'zip_extensions_string': '.docx,.xlsx,.zip',
    'special_extensions_string': '.msg',
    'mail_extensions_string': '.pst',
    # checks for existence of files that can't be checked automatically
    'other_extensions_string': '.ost,.accdb,.mdb',
    'excluded_pans_string': '',
    'config_file': 'panhunt.ini'
}
search_dir: str = defaults['search_dir']
output_file = defaults['output_file']
excluded_directories_string = defaults['excluded_directories_string']
text_extensions_string = defaults['text_extensions_string']
zip_extensions_string = defaults['zip_extensions_string']
special_extensions_string = defaults['special_extensions_string']
mail_extensions_string = defaults['mail_extensions_string']
other_extensions_string = defaults['other_extensions_string']
excluded_pans_string = defaults['excluded_pans_string']
config_file = defaults['config_file']

excluded_directories = None
excluded_pans: list[str] = []
search_extensions = {}

pan_regexs = {'Mastercard': re.compile(r'(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
              'Visa': re.compile(r'(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'),
              'AMEX': re.compile(r'(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)')}


###################################################################################################################################
#   ____ _
#  / ___| | __ _ ___ ___  ___  ___
# | |   | |/ _` / __/ __|/ _ \/ __|
# | |___| | (_| \__ \__ \  __/\__ \
#  \____|_|\__,_|___/___/\___||___/
#
###################################################################################################################################

class PANFile():
    """ PANFile: class for a file that can check itself for PANs"""

    def __init__(self, filename, file_dir) -> None:
        self.filename: str = filename
        self.dir: str = file_dir
        self.path: str = os.path.join(self.dir, self.filename)
        self.root, self.ext = os.path.splitext(self.filename)
        self.errors: list = []
        self.type = None
        self.matches: list = []

    def check_text_regexs(self, text, regexs, sub_path) -> None:
        """Uses regular expressions to check for PANs in text"""

        for brand, regex in list(regexs.items()):
            pans = regex.findall(text)
            if pans:
                for pan in pans:
                    if PAN.is_valid_luhn_checksum(pan) and not PAN.is_excluded(pan):
                        self.matches.append(
                            PAN(self.path, sub_path, brand, pan))

    def __cmp__(self, other: 'PANFile') -> bool:

        return self.path.lower() == other.path.lower()

    def set_file_stats(self) -> None:

        try:
            stat = os.stat(self.path)
            self.size = stat.st_size
            self.accessed = self.dtm_from_ts(stat.st_atime)
            self.modified = self.dtm_from_ts(stat.st_mtime)
            self.created = self.dtm_from_ts(stat.st_ctime)
        except WindowsError:
            self.size = -1
            self.set_error(sys.exc_info()[1])

    def dtm_from_ts(self, ts) -> Optional[datetime]:

        try:
            return datetime.fromtimestamp(ts)
        except ValueError:
            if ts == -753549904:
                # Mac OSX "while copying" thing
                return datetime(1946, 2, 14, 8, 34, 56)

            self.set_error(sys.exc_info()[1])

    def set_error(self, error_msg) -> None:

        self.errors.append(error_msg)
        print(colorama.Fore.RED + panutils.unicode2ascii('ERROR %s on %s' %
              (error_msg, self.path)) + colorama.Fore.WHITE)

    def check_regexs(self, regexs, search_extensions) -> Any:
        """Checks the file for matching regular expressions: if a ZIP then each file in the ZIP (recursively) or the text in a document"""

        if self.type == 'ZIP':
            try:
                if zipfile.is_zipfile(self.path):
                    zf = zipfile.ZipFile(self.path)
                    self.check_zip_regexs(zf, regexs, search_extensions, '')
                else:
                    self.set_error('Invalid ZIP file')
            except IOError:
                self.set_error(sys.exc_info()[1])
            except Exception:
                self.set_error(sys.exc_info()[1])

        elif self.type == 'TEXT':
            try:
                file_text = panutils.read_ascii_file(self.path, 'rb')
                self.check_text_regexs(file_text, regexs, '')
            # except WindowsError:
            #    self.set_error(sys.exc_info()[1])
            except IOError:
                self.set_error(sys.exc_info()[1])
            except Exception:
                self.set_error(sys.exc_info()[1])

        elif self.type == 'SPECIAL':
            if panutils.get_ext(self.path) == '.msg':
                try:
                    msg = msmsg.MSMSG(self.path)
                    if msg.validMSG:
                        self.check_msg_regexs(
                            msg, regexs, search_extensions, '')
                    else:
                        self.set_error('Invalid MSG file')
                except IOError:
                    self.set_error(sys.exc_info()[1])
                except Exception:
                    self.set_error(sys.exc_info()[1])

        return self.matches

    def check_pst_regexs(self, regexs, search_extensions, hunt_type, gauge_update_function=None):
        """ Searches a pst file for regular expressions in messages and attachments using regular expressions"""

        all_extensions = search_extensions['TEXT'] + \
            search_extensions['ZIP'] + search_extensions['SPECIAL']

        if not gauge_update_function:
            pbar_widgets = ['%s Hunt %s: ' % (hunt_type, panutils.unicode2ascii(self.filename)), progressbar.Percentage(), ' ', progressbar.Bar(
                marker=progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' %ss:0' % hunt_type)]
            pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()
        else:
            gauge_update_function(caption='%s Hunt: ' % hunt_type)

        try:
            apst = pst.PST(self.path)
            if apst.header.validPST:

                total_messages = apst.get_total_message_count()
                total_attachments = apst.get_total_attachment_count()
                total_items = total_messages + total_attachments
                items_completed = 0

                for folder in apst.folder_generator():
                    for message in apst.message_generator(folder):
                        if message.Subject:
                            message_path = os.path.join(
                                folder.path, message.Subject)
                        else:
                            message_path = os.path.join(
                                folder.path, '[NoSubject]')
                        if message.Body:
                            self.check_text_regexs(
                                message.Body, regexs, message_path)
                        if message.HasAttachments:
                            for subattachment in message.subattachments:
                                if panutils.get_ext(subattachment.Filename) in search_extensions['TEXT'] + search_extensions['ZIP']:
                                    attachment = message.get_attachment(
                                        subattachment)
                                    self.check_attachment_regexs(
                                        attachment, regexs, search_extensions, message_path)
                                items_completed += 1
                        items_completed += 1
                        if not gauge_update_function:
                            pbar_widgets[6] = progressbar.FormatLabel(
                                ' %ss:%s' % (hunt_type, len(self.matches)))
                            pbar.update(items_completed * 100.0 / total_items)
                        else:
                            gauge_update_function(
                                value=items_completed * 100.0 / total_items)

            apst.close()

        except IOError:
            self.set_error(sys.exc_info()[1])
        except pst.PSTException:
            self.set_error(sys.exc_info()[1])

        if not gauge_update_function:
            pbar.finish()

        return self.matches

    def check_attachment_regexs(self, attachment, regexs, search_extensions, sub_path):
        """for PST and MSG attachments, check attachment for valid extension and then regexs"""

        attachment_ext = panutils.get_ext(attachment.Filename)
        if attachment_ext in search_extensions['TEXT']:
            if attachment.data:
                self.check_text_regexs(attachment.data, regexs, os.path.join(
                    sub_path, attachment.Filename))

        if attachment_ext in search_extensions['ZIP']:
            if attachment.data:
                try:
                    memory_zip = io.StringIO()
                    memory_zip.write(attachment.data)
                    zip_file = zipfile.ZipFile(memory_zip.read())
                    self.check_zip_regexs(zip_file, regexs, search_extensions, os.path.join(
                        sub_path, attachment.Filename))
                    memory_zip.close()
                except RuntimeError:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])

    def check_msg_regexs(self, msg, regexs, search_extensions, sub_path):

        if msg.Body:
            self.check_text_regexs(msg.Body, regexs, sub_path)
        if msg.attachments:
            for attachment in msg.attachments:
                self.check_attachment_regexs(
                    attachment, regexs, search_extensions, sub_path)

    def check_zip_regexs(self, zf, regexs, search_extensions, sub_path):
        """Checks a zip file for valid documents that are then checked for regexs"""

        all_extensions = search_extensions['TEXT'] + \
            search_extensions['ZIP'] + search_extensions['SPECIAL']

        files_in_zip = [file_in_zip for file_in_zip in zf.namelist(
        ) if panutils.get_ext(file_in_zip) in all_extensions]
        for file_in_zip in files_in_zip:
            # nested zip file
            if panutils.get_ext(file_in_zip) in search_extensions['ZIP']:
                try:
                    memory_zip = io.StringIO()
                    memory_zip.write(zf.open(file_in_zip).read())
                    nested_zf = zipfile.ZipFile(memory_zip.read())
                    self.check_zip_regexs(nested_zf, regexs, search_extensions, os.path.join(
                        sub_path, panutils.decode_zip_filename(file_in_zip)))
                    memory_zip.close()
                except RuntimeError:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            # normal doc
            elif panutils.get_ext(file_in_zip) in search_extensions['TEXT']:
                try:
                    file_text = zf.open(file_in_zip).read()
                    self.check_text_regexs(file_text, regexs, os.path.join(
                        sub_path, panutils.decode_zip_filename(file_in_zip)))
                except RuntimeError:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            else:  # SPECIAL
                try:
                    if panutils.get_ext(file_in_zip) == '.msg':
                        memory_msg = io.StringIO()
                        memory_msg.write(zf.open(file_in_zip).read())
                        msg: msmsg.MSMSG = msmsg.MSMSG(memory_msg.read())
                        if msg.validMSG:
                            self.check_msg_regexs(msg, regexs, search_extensions, os.path.join(
                                sub_path, panutils.decode_zip_filename(file_in_zip)))
                        memory_msg.close()
                except RuntimeError:  # RuntimeError
                    self.set_error(sys.exc_info()[1])


class PAN:
    """PAN: A class for recording PANs, their brand and where they were found"""

    pan: str
    path: str
    sub_path: str
    brand: str

    def __init__(self, path: str, sub_path: str, brand: str, pan: str) -> None:

        self.path, self.sub_path, self.brand, self.pan = path, sub_path, brand, pan

    def __repr__(self, mask_pan=True) -> str:

        if mask_pan:
            pan_out: str = self.get_masked_pan()
        else:
            pan_out = self.pan
        return '%s %s:%s' % (self.sub_path, self.brand, pan_out)

    def get_masked_pan(self) -> str:
        return re.sub(r'\d', '*', self.pan[:-4]) + self.pan[-4:]

    @staticmethod
    def is_excluded(pan) -> bool:
        global excluded_pans

        for excluded_pan in excluded_pans:
            if pan == excluded_pan:
                return True
        return False

    @staticmethod
    def is_valid_luhn_checksum(pan: str) -> bool:
        """ from wikipedia: https://en.wikipedia.org/wiki/Luhn_algorithm"""

        safe_pan: str = re.sub(r'[^\d]', '', pan)

        def digits_of(n) -> list[int]:
            return [int(d) for d in str(n)]

        digits: list[int] = digits_of(safe_pan)
        odd_digits: list[int] = digits[-1::-2]
        even_digits: list[int] = digits[-2::-2]
        checksum: int = 0
        checksum += sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))

        return checksum % 10 == 0


###################################################################################################################################
#  __  __           _       _        _____                 _   _
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################

# TODO: Move related functions to panutils

def get_text_hash(text: str | bytes) -> str:
    encoded_text: bytes

    if isinstance(text, str):
        encoded_text = text.encode('utf-8')
    else:
        encoded_text = text

    return hashlib.sha512(encoded_text + 'PAN'.encode('utf-8')).hexdigest()


def add_hash_to_file(text_file) -> None:

    text: str = panutils.read_unicode_file(text_file)
    hash_check: str = get_text_hash(text)

    text += os.linesep + hash_check
    panutils.write_unicode_file(text_file, text)


def check_file_hash(text_file) -> None:

    text_output: str = panutils.read_unicode_file(text_file)
    hash_pos: int = text_output.rfind(os.linesep)
    hash_in_file: str = text_output[hash_pos + len(os.linesep):]
    hash_check: str = get_text_hash(text_output[:hash_pos])
    if hash_in_file == hash_check:
        print(colorama.Fore.GREEN + 'Hashes OK')
    else:
        print(colorama.Fore.RED + 'Hashes Not OK')
    print(colorama.Fore.WHITE + hash_in_file + '\n' + hash_check)


def output_report(search_dir: str, excluded_directories_string: str, all_files: list, total_files_searched: int, pans_found: int, output_file: str, mask_pans: bool) -> None:

    pan_sep: str = '\n\t'
    pan_report: str = 'PAN Hunt Report - %s\n%s\n' % (
        time.strftime("%H:%M:%S %d/%m/%Y"), '=' * 100)
    pan_report += 'Searched %s\nExcluded %s\n' % (
        search_dir, excluded_directories_string)
    pan_report += 'Command: %s\n' % (' '.join(sys.argv))
    pan_report += 'Uname: %s\n' % (' | '.join(platform.uname()))
    pan_report += 'Searched %s files. Found %s possible PANs.\n%s\n\n' % (
        total_files_searched, pans_found, '=' * 100)

    for afile in sorted([afile for afile in all_files if afile.matches]):
        pan_header: str = 'FOUND PANs: %s (%s %s)' % (
            afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))
        print(colorama.Fore.RED + panutils.unicode2ascii(pan_header))
        pan_report += pan_header + '\n'
        pan_list: str = '\t' + \
            pan_sep.join([pan.__repr__(mask_pans) for pan in afile.matches])
        print(colorama.Fore.YELLOW +
              panutils.unicode2ascii(pan_list))
        pan_report += pan_list + '\n\n'

    if len([afile for afile in all_files if afile.type == 'OTHER']) != 0:
        pan_report += 'Interesting Files to check separately:\n'
    for afile in sorted([afile for afile in all_files if afile.type == 'OTHER']):
        pan_report += '%s (%s %s)\n' % (afile.path,
                                        afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))

    pan_report = pan_report.replace('\n', os.linesep)

    print(colorama.Fore.WHITE +
          f'Report written to {panutils.unicode2ascii(output_file)}')
    panutils.write_unicode_file(output_file, pan_report)
    add_hash_to_file(output_file)


def load_config_file() -> None:

    global config_file, defaults, search_dir, output_file, excluded_directories_string, text_extensions_string, zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, mask_pans, excluded_pans_string

    if not os.path.isfile(config_file):
        return

    config: configparser.ConfigParser = configparser.ConfigParser()
    config.read(config_file)
    defaultConfig = {}
    for nvp in config.items('DEFAULT'):
        defaultConfig[nvp[0]] = nvp[1]

    if 'search' in defaultConfig and search_dir == defaults['search_dir']:
        search_dir = defaultConfig['search']
    if 'exclude' in defaultConfig and excluded_directories_string == defaults['excluded_directories_string']:
        excluded_directories_string = defaultConfig['exclude']
    if 'textfiles' in defaultConfig and text_extensions_string == defaults['text_extensions_string']:
        text_extensions_string = defaultConfig['textfiles']
    if 'zipfiles' in defaultConfig and zip_extensions_string == defaults['zip_extensions_string']:
        zip_extensions_string = defaultConfig['zipfiles']
    if 'specialfiles' in defaultConfig and special_extensions_string == defaults['special_extensions_string']:
        special_extensions_string = defaultConfig['specialfiles']
    if 'mailfiles' in defaultConfig and mail_extensions_string == defaults['mail_extensions_string']:
        mail_extensions_string = defaultConfig['mailfiles']
    if 'otherfiles' in defaultConfig and other_extensions_string == defaults['other_extensions_string']:
        other_extensions_string = defaultConfig['otherfiles']
    if 'outfile' in defaultConfig and output_file == defaults['output_file']:
        output_file = defaultConfig['outfile']
    if 'unmask' in defaultConfig:
        mask_pans = not (defaultConfig['unmask'].upper() == 'TRUE')
    if 'excludepans' in defaultConfig and excluded_pans_string == defaults['excluded_pans_string']:
        excluded_pans_string = defaultConfig['excludepans']


def set_global_parameters() -> None:

    global excluded_directories_string, text_extensions_string, zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_directories, search_extensions, excluded_pans_string, excluded_pans

    excluded_directories = [exc_dir.lower()
                            for exc_dir in excluded_directories_string.split(',')]
    search_extensions['TEXT'] = text_extensions_string.split(',')
    search_extensions['ZIP'] = zip_extensions_string.split(',')
    search_extensions['SPECIAL'] = special_extensions_string.split(',')
    search_extensions['MAIL'] = mail_extensions_string.split(',')
    search_extensions['OTHER'] = other_extensions_string.split(',')
    if len(excluded_pans_string) > 0:
        excluded_pans = excluded_pans_string.split(',')


def hunt_pans(gauge_update_function=None):

    global search_dir, excluded_directories, search_extensions

    # find all files to check
    all_files = find_all_files_in_directory(
        PANFile, search_dir, excluded_directories, search_extensions, gauge_update_function)

    # check each file
    total_docs, doc_pans_found = find_all_regexs_in_files([afile for afile in all_files if not afile.errors and afile.type in (
        'TEXT', 'ZIP', 'SPECIAL')], pan_regexs, search_extensions, 'PAN', gauge_update_function)
    # check each pst message and attachment
    total_psts, pst_pans_found = find_all_regexs_in_psts(
        [afile for afile in all_files if not afile.errors and afile.type == 'MAIL'], pan_regexs, search_extensions, 'PAN', gauge_update_function)

    total_files_searched = total_docs + total_psts
    pans_found = doc_pans_found + pst_pans_found

    return total_files_searched, pans_found, all_files


def find_all_files_in_directory(AFileClass, root_dir, excluded_directories, search_extensions, gauge_update_function=None):
    """Recursively searches a directory for files. search_extensions is a dictionary of extension lists"""

    all_extensions = [ext for ext_list in list(
        search_extensions.values()) for ext in ext_list]

    extension_types = {}
    for ext_type, ext_list in search_extensions.items():
        for ext in ext_list:
            extension_types[ext] = ext_type

    if not gauge_update_function:
        pbar_widgets = ['Doc Hunt: ', progressbar.Percentage(), ' ', progressbar.Bar(
            marker=progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' Docs:0')]
        pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()
    else:
        gauge_update_function(caption='Doc Hunt: ')

    doc_files = []
    root_dir_dirs = None
    root_items_completed = 0
    docs_found = 0

    for root, sub_dirs, files in os.walk(root_dir):
        sub_dirs[:] = [check_dir for check_dir in sub_dirs if os.path.join(
            root, check_dir).lower() not in excluded_directories]
        if not root_dir_dirs:
            root_dir_dirs = [os.path.join(root, sub_dir)
                             for sub_dir in sub_dirs]
            root_total_items: int = len(root_dir_dirs) + len(files)
        if root in root_dir_dirs:
            root_items_completed += 1
            if not gauge_update_function:
                pbar_widgets[6] = progressbar.FormatLabel(
                    ' Docs:%s' % docs_found)
                pbar.update(root_items_completed * 100.0 / root_total_items)
            else:
                gauge_update_function(
                    value=root_items_completed * 100.0 / root_total_items)
        for filename in files:
            if root == root_dir:
                root_items_completed += 1
            afile = AFileClass(filename, root)  # AFile or PANFile
            if afile.ext.lower() in all_extensions:
                afile.set_file_stats()
                afile.type = extension_types[afile.ext.lower()]
                if afile.type in ('TEXT', 'SPECIAL') and afile.size > TEXT_FILE_SIZE_LIMIT:
                    afile.type = 'OTHER'
                    afile.set_error('File size {1} over limit of {0} for checking'.format(
                        panutils.size_friendly(TEXT_FILE_SIZE_LIMIT), afile.size_friendly()))
                doc_files.append(afile)
                if not afile.errors:
                    docs_found += 1
                if not gauge_update_function:
                    pbar_widgets[6] = progressbar.FormatLabel(
                        ' Docs:%s' % docs_found)
                    pbar.update(root_items_completed *
                                100.0 / root_total_items)
                else:
                    gauge_update_function(
                        value=root_items_completed * 100.0 / root_total_items)

    if not gauge_update_function:
        pbar.finish()

    return doc_files


def find_all_regexs_in_files(text_or_zip_files, regexs, search_extensions, hunt_type, gauge_update_function=None) -> tuple[int, int]:
    """ Searches files in doc_files list for regular expressions"""

    if not gauge_update_function:
        pbar_widgets = ['%s Hunt: ' % hunt_type, progressbar.Percentage(), ' ', progressbar.Bar(
            marker=progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' %ss:0' % hunt_type)]
        pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()
    else:
        gauge_update_function(caption='%s Hunt: ' % hunt_type)

    total_files = len(text_or_zip_files)
    files_completed = 0
    matches_found = 0

    for afile in text_or_zip_files:
        matches = afile.check_regexs(regexs, search_extensions)
        matches_found += len(matches)
        files_completed += 1
        if not gauge_update_function:
            pbar_widgets[6] = progressbar.FormatLabel(
                ' %ss:%s' % (hunt_type, matches_found))
            pbar.update(files_completed * 100.0 / total_files)
        else:
            gauge_update_function(value=files_completed * 100.0 / total_files)

    if not gauge_update_function:
        pbar.finish()

    return total_files, matches_found


def find_all_regexs_in_psts(pst_files, regexs, search_extensions, hunt_type, gauge_update_function=None) -> tuple[int, int]:
    """ Searches psts in pst_files list for regular expressions in messages and attachments"""

    total_psts: int = len(pst_files)
    psts_completed = 0
    matches_found = 0

    for afile in pst_files:
        matches = afile.check_pst_regexs(
            regexs, search_extensions, hunt_type, gauge_update_function)
        matches_found += len(matches)
        psts_completed += 1

    return total_psts, matches_found


###################################################################################################################################
#  __  __       _
# |  \/  | __ _(_)_ __
# | |\/| |/ _` | | '_ \
# | |  | | (_| | | | | |
# |_|  |_|\__,_|_|_| |_|
#
###################################################################################################################################


if __name__ == "__main__":

    colorama.init()

    # Command Line Arguments
    arg_parser: argparse.ArgumentParser = argparse.ArgumentParser(prog='panhunt', description='PAN Hunt v%s: search directories and sub directories for documents containing PANs.' % (
        app_version), formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument(
        '-s', dest='search', default=search_dir, help='base directory to search in')
    arg_parser.add_argument('-x', dest='exclude', default=excluded_directories_string,
                            help='directories to exclude from the search')
    arg_parser.add_argument(
        '-t', dest='textfiles', default=text_extensions_string, help='text file extensions to search')
    arg_parser.add_argument(
        '-z', dest='zipfiles', default=zip_extensions_string, help='zip file extensions to search')
    arg_parser.add_argument('-e', dest='specialfiles',
                            default=special_extensions_string, help='special file extensions to search')
    arg_parser.add_argument(
        '-m', dest='mailfiles', default=mail_extensions_string, help='email file extensions to search')
    arg_parser.add_argument(
        '-l', dest='otherfiles', default=other_extensions_string, help='other file extensions to list')
    arg_parser.add_argument(
        '-o', dest='outfile', default=output_file, help='output file name for PAN report')
    arg_parser.add_argument('-u', dest='unmask', action='store_true',
                            default=False, help='unmask PANs in output')
    arg_parser.add_argument(
        '-C', dest='config', default=config_file, help='configuration file to use')
    arg_parser.add_argument(
        '-X', dest='excludepan', default=excluded_pans_string, help='PAN to exclude from search')
    arg_parser.add_argument('-c', dest='checkfilehash',
                            help=argparse.SUPPRESS)  # hidden argument

    args: argparse.Namespace = arg_parser.parse_args()

    if args.checkfilehash:
        check_file_hash(args.checkfilehash)
        sys.exit()

    search_dir = str(args.search)
    output_file = str(args.outfile)
    excluded_directories_string = str(args.exclude)
    text_extensions_string = str(args.textfiles)
    zip_extensions_string = str(args.zipfiles)
    special_extensions_string = str(args.specialfiles)
    mail_extensions_string = str(args.mailfiles)
    other_extensions_string = str(args.otherfiles)
    mask_pans = not args.unmask
    excluded_pans_string = str(args.excludepan)
    config_file = str(args.config)
    load_config_file()

    set_global_parameters()

    total_files_searched, pans_found, all_files = hunt_pans()

    # report findings
    output_report(search_dir, excluded_directories_string, all_files,
                  total_files_searched, pans_found, output_file, mask_pans)
