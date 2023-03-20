#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# filehunt: general file searching library for use by PANhunt and PassHunt
# By BB

import datetime
import io
import os
import sys
import zipfile
from typing import Any, Optional

import colorama
import progressbar

import msmsg  # MS-MSG files
import panutils
import pst  # MS-PST files

TEXT_FILE_SIZE_LIMIT: int = 1073741824  # 1Gb

###################################################################################################################################
#   ____ _
#  / ___| | __ _ ___ ___  ___  ___
# | |   | |/ _` / __/ __|/ _ \/ __|
# | |___| | (_| \__ \__ \  __/\__ \
#  \____|_|\__,_|___/___/\___||___/
#
###################################################################################################################################


class AFile:
    """ AFile: class for a file that can search itself"""

    def __init__(self, filename: str, file_dir: str) -> None:

        self.filename: str = filename
        self.dir: str = file_dir
        self.path: str = os.path.join(self.dir, self.filename)
        self.root, self.ext = os.path.splitext(self.filename)
        self.errors: list = []
        self.type = None
        self.matches: list = []

    def __cmp__(self, other: 'AFile') -> bool:

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

    def dtm_from_ts(self, ts) -> Optional[datetime.datetime]:

        try:
            return datetime.datetime.fromtimestamp(ts)
        except ValueError:
            if ts == -753549904:
                # Mac OSX "while copying" thing
                return datetime.datetime(1946, 2, 14, 8, 34, 56)

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


###################################################################################################################################
#  __  __           _       _        _____                 _   _
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################


def find_all_files_in_directory(AFileClass, root_dir, excluded_directories, search_extensions, gauge_update_function=None):
    """Recursively searches a directory for files. search_extensions is a dictionary of extension lists"""

    global TEXT_FILE_SIZE_LIMIT

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


def find_all_regexs_in_files(text_or_zip_files, regexs, search_extensions, hunt_type, gauge_update_function=None):
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


def find_all_regexs_in_psts(pst_files, regexs, search_extensions, hunt_type, gauge_update_function=None):
    """ Searches psts in pst_files list for regular expressions in messages and attachments"""

    total_psts = len(pst_files)
    psts_completed = 0
    matches_found = 0

    for afile in pst_files:
        matches = afile.check_pst_regexs(
            regexs, search_extensions, hunt_type, gauge_update_function)
        matches_found += len(matches)
        psts_completed += 1

    return total_psts, matches_found
