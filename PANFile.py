import io
import os
import sys
import zipfile
from datetime import datetime
from typing import Any, Optional

import colorama
import progressbar

import msmsg
import panutils
import pst
from PAN import PAN


class PANFile:
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
