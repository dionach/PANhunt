import io
import os
import sys
import zipfile
from datetime import datetime
from typing import Any, Optional

import msmsg
import panutils
import pst
from config import PANHuntConfigSingleton
from PAN import PAN
from patterns import CardPatternSingleton
from pbar import FileSubbar


class PANFile:
    """ PANFile: class for a file that can check itself for PANs"""

    filename: str
    dir: str
    path: str
    root: str
    ext: str
    filetype: Optional[str]
    errors: Optional[list]
    matches: list[PAN]
    size: int
    accessed: datetime
    modified: datetime
    created: datetime

    def __init__(self, filename: str, file_dir: str) -> None:
        self.filename = filename
        self.dir = file_dir
        self.path = os.path.join(self.dir, self.filename)
        self.root, self.ext = os.path.splitext(self.filename)
        self.errors = []
        self.filetype = None
        self.matches = []

    def __cmp__(self, other: 'PANFile') -> bool:

        return self.path.lower() == other.path.lower()

    def set_file_stats(self) -> None:

        try:
            stat: os.stat_result = os.stat(self.path)
            self.size = stat.st_size
            self.accessed = self.dtm_from_ts(stat.st_atime)
            self.modified = self.dtm_from_ts(stat.st_mtime)
            self.created = self.dtm_from_ts(stat.st_ctime)
        except WindowsError:
            self.size = -1
            self.set_error(sys.exc_info()[1])

    def dtm_from_ts(self, ts: float) -> datetime:

        try:
            return datetime.fromtimestamp(ts)
        except ValueError as ve:
            if ts == -753549904:
                # Mac OSX "while copying" thing
                return datetime(1946, 2, 14, 8, 34, 56)
            else:
                raise Exception() from ve

            # self.set_error(sys.exc_info()[1])

    # TODO: Use a general error logging and display mechanism
    def set_error(self, error_msg) -> None:
        pass
        # self.errors.append(error_msg)
        # print(colorama.Fore.RED + panutils.unicode2ascii('ERROR %s on %s' %
        #       (error_msg, self.path)) + colorama.Fore.WHITE)

    def check_regexs(self) -> Any:
        """Checks the file for matching regular expressions: if a ZIP then each file in the ZIP (recursively) or the text in a document"""

        if self.filetype == 'ZIP':
            try:
                if zipfile.is_zipfile(self.path):
                    zf = zipfile.ZipFile(self.path)
                    self.check_zip_regexs(zf, '')
                else:
                    self.set_error('Invalid ZIP file')
            except IOError:
                self.set_error(sys.exc_info()[1])
            except Exception:
                self.set_error(sys.exc_info()[1])

        elif self.filetype == 'TEXT':
            try:
                # file_text: str = panutils.read_ascii_file(self.path)

                with open(self.path, 'r', encoding='ascii') as f:
                    file_text = f.read()
                    self.check_text_regexs(file_text, '')
            # except WindowsError:
            #    self.set_error(sys.exc_info()[1])
            except IOError:
                self.set_error(sys.exc_info()[1])
            except Exception:
                self.set_error(sys.exc_info()[1])

        elif self.filetype == 'SPECIAL':
            if panutils.get_ext(self.path) == '.msg':
                try:
                    msg = msmsg.MSMSG(self.path)
                    if msg.validMSG:
                        self.check_msg_regexs(msg, '')
                    else:
                        self.set_error('Invalid MSG file')
                except IOError:
                    self.set_error(sys.exc_info()[1])
                except Exception:
                    self.set_error(sys.exc_info()[1])

        return self.matches

    def check_text_regexs(self, text: str, sub_path: str) -> None:
        """Uses regular expressions to check for PANs in text"""

        for brand, regex in CardPatternSingleton().instance.brands():
            pans: list[str] = regex.findall(text)
            if pans:
                for pan in pans:
                    if PAN.is_valid_luhn_checksum(pan) and not PAN.is_excluded(pan, PANHuntConfigSingleton.instance().excluded_pans):
                        self.matches.append(
                            PAN(self.path, sub_path, brand, pan))

    def check_pst_regexs(self, hunt_type: str) -> list[PAN]:
        """ Searches a pst file for regular expressions in messages and attachments using regular expressions"""
        # TODO: Move UI related code to main method of panhunt.py
        with FileSubbar(hunt_type, self.filename) as sub_pbar:

            try:
                pst_file = pst.PST(self.path)
                if pst_file.header.validPST:

                    total_messages: int = pst_file.get_total_message_count()
                    total_attachments: int = pst_file.get_total_attachment_count()
                    total_items: int = total_messages + total_attachments
                    items_completed = 0

                    for folder in pst_file.folder_generator():
                        for message in pst_file.message_generator(folder):
                            if message.Subject:
                                message_path: str = os.path.join(
                                    folder.path, message.Subject)
                            else:
                                message_path = os.path.join(
                                    folder.path, '[NoSubject]')
                            if message.Body:
                                self.check_text_regexs(
                                    message.Body, message_path)
                            if message.HasAttachments:
                                for subattachment in message.subattachments:
                                    if panutils.get_ext(subattachment.Filename) in PANHuntConfigSingleton.instance().search_extensions['TEXT'] + PANHuntConfigSingleton.instance().search_extensions['ZIP']:
                                        attachment = message.get_attachment(
                                            subattachment)
                                        # We already checked there is an attachment, this is to suppress type checkers
                                        if attachment:
                                            self.check_attachment_regexs(
                                                attachment, message_path)
                                    items_completed += 1
                            items_completed += 1
                            sub_pbar.update(items_found=len(
                                self.matches), items_total=total_items, items_completed=items_completed)

                pst_file.close()

            except IOError:
                self.set_error(sys.exc_info()[1])
            except pst.PSTException:
                self.set_error(sys.exc_info()[1])

        return self.matches

    def check_attachment_regexs(self, attachment: pst.Attachment | msmsg.Attachment, sub_path: str) -> None:
        """for PST and MSG attachments, check attachment for valid extension and then regexs"""

        attachment_ext: str = panutils.get_ext(attachment.Filename)
        if attachment_ext in PANHuntConfigSingleton.instance().search_extensions['TEXT']:
            if attachment.BinaryData:
                # TODO: Check if utf-8 is okay or we need ascii
                self.check_text_regexs(attachment.BinaryData.decode('utf-8'), os.path.join(
                    sub_path, attachment.Filename))

        if attachment_ext in PANHuntConfigSingleton.instance().search_extensions['ZIP']:
            if attachment.BinaryData:
                try:
                    memory_zip = io.StringIO()
                    # TODO: Check if utf-8 is okay or we need ascii
                    memory_zip.write(attachment.BinaryData.decode('utf-8'))
                    zip_file = zipfile.ZipFile(memory_zip.read())
                    self.check_zip_regexs(zip_file, os.path.join(
                        sub_path, attachment.Filename))
                    memory_zip.close()
                except RuntimeError:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])

    def check_msg_regexs(self, msg: msmsg.MSMSG, sub_path: str) -> None:

        if msg.Body:
            self.check_text_regexs(msg.Body, sub_path)
        if msg.attachments:
            for attachment in msg.attachments:
                self.check_attachment_regexs(
                    attachment, sub_path)

    def check_zip_regexs(self, zf: zipfile.ZipFile, sub_path: str) -> None:
        """Checks a zip file for valid documents that are then checked for regexs"""

        all_extensions = PANHuntConfigSingleton.instance().search_extensions['TEXT'] + \
            PANHuntConfigSingleton(
        ).instance.search_extensions['ZIP'] + PANHuntConfigSingleton.instance().search_extensions['SPECIAL']

        files_in_zip = [file_in_zip for file_in_zip in zf.namelist(
        ) if panutils.get_ext(file_in_zip) in all_extensions]
        for file_in_zip in files_in_zip:
            # nested zip file
            if panutils.get_ext(file_in_zip) in PANHuntConfigSingleton.instance().search_extensions['ZIP']:
                try:
                    memory_zip = io.StringIO()
                    memory_zip.write(panutils.decode_zip_text(
                        zf.open(file_in_zip).read()))
                    nested_zf = zipfile.ZipFile(memory_zip.read())
                    self.check_zip_regexs(nested_zf, os.path.join(
                        sub_path, panutils.decode_zip_filename(file_in_zip)))
                    memory_zip.close()
                except RuntimeError:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            # normal doc
            elif panutils.get_ext(file_in_zip) in PANHuntConfigSingleton.instance().search_extensions['TEXT']:
                try:
                    file_text = panutils.decode_zip_text(
                        zf.open(file_in_zip).read())
                    self.check_text_regexs(file_text, os.path.join(
                        sub_path, panutils.decode_zip_filename(file_in_zip)))
                except RuntimeError:  # RuntimeError: # e.g. zip needs password
                    self.set_error(sys.exc_info()[1])
            else:  # SPECIAL
                try:
                    if panutils.get_ext(file_in_zip) == '.msg':
                        memory_msg = io.StringIO()
                        memory_msg.write(panutils.decode_zip_text(
                            zf.open(file_in_zip).read()))
                        msg: msmsg.MSMSG = msmsg.MSMSG(memory_msg.read())
                        if msg.validMSG:
                            self.check_msg_regexs(msg, os.path.join(
                                sub_path, panutils.decode_zip_filename(file_in_zip)))
                        memory_msg.close()
                except RuntimeError:  # RuntimeError
                    self.set_error(sys.exc_info()[1])
