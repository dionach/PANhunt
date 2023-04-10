#! /usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# PANhunt: search directories and sub directories for documents with PANs
# By BB
#
# Contributors: Zafer Balkan, 2023


import argparse
import hashlib
import locale
import logging
from math import log
import os
import platform
import sys
import time
from typing import Final, Optional

import colorama

import panutils
from config import PANHuntConfigSingleton
from exceptions import PANHuntException
from PAN import PAN
from PANFile import PANFile
from pbar import FileProgressbar, MainProgressbar

TEXT_FILE_SIZE_LIMIT: Final[int] = 1073741824  # 1Gb

app_version = '1.3'


###################################################################################################################################
#  __  __           _       _        _____                 _   _
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################

class Hunter:

    pbar: MainProgressbar

    def hunt_pans(self) -> tuple[int, int, list[PANFile]]:

        # find all files to check
        all_files: list[PANFile] = self.__find_all_files_in_search_directory()

        # check each file
        total_docs, doc_pans_found = self.__find_all_regexs_in_files([pan_file for pan_file in all_files if not pan_file.errors and pan_file.filetype in (
            'TEXT', 'ZIP', 'SPECIAL')], 'PAN')
        # check each pst message and attachment
        total_psts, pst_pans_found = self.__find_all_regexs_in_psts(
            [pan_file for pan_file in all_files if not pan_file.errors and pan_file.filetype == 'MAIL'], 'PAN')

        total_files_searched: int = total_docs + total_psts
        pans_found: int = doc_pans_found + pst_pans_found

        return total_files_searched, pans_found, all_files

    def output_report(self, all_files: list[PANFile], total_files_searched: int, pans_found: int) -> None:

        pan_sep: str = '\n\t'
        pan_report: str = 'PAN Hunt Report - %s\n%s\n' % (
            time.strftime("%H:%M:%S %d/%m/%Y"), '=' * 100)
        pan_report += 'Searched %s\nExcluded %s\n' % (
            PANHuntConfigSingleton.instance().search_dir, ','.join(PANHuntConfigSingleton.instance().excluded_directories))
        pan_report += 'Command: %s\n' % (' '.join(sys.argv))
        pan_report += 'Uname: %s\n' % (' | '.join(platform.uname()))
        pan_report += 'Searched %s files. Found %s possible PANs.\n%s\n\n' % (
            total_files_searched, pans_found, '=' * 100)

        for pan_file in sorted([pan_file for pan_file in all_files if pan_file.matches], key=lambda x: x.filename):
            pan_header: str = f"FOUND PANs: {pan_file.path} ({panutils.size_friendly(pan_file.size)} {pan_file.modified.strftime('%d/%m/%Y')})"

            print(colorama.Fore.RED + panutils.unicode_to_ascii(pan_header))
            pan_report += pan_header + '\n'
            pan_list: str = '\t' + \
                pan_sep.join([pan.get_masked_pan()
                              for pan in pan_file.matches])
            print(colorama.Fore.YELLOW +
                  panutils.unicode_to_ascii(pan_list))
            pan_report += pan_list + '\n\n'

        if len([pan_file for pan_file in all_files if pan_file.filetype == 'OTHER']) != 0:
            pan_report += 'Interesting Files to check separately:\n'
        for pan_file in sorted([afile for afile in all_files if afile.filetype == 'OTHER'], key=lambda x: x.filename):
            pan_report += '%s (%s %s)\n' % (pan_file.path,
                                            panutils.size_friendly(pan_file.size), pan_file.modified.strftime('%d/%m/%Y'))

        pan_report = pan_report.replace('\n', os.linesep)

        print(colorama.Fore.WHITE +
              f'Report written to {panutils.unicode_to_ascii(PANHuntConfigSingleton.instance().output_file)}')

        with open(PANHuntConfigSingleton.instance().output_file, encoding='utf-8', mode='w') as f:
            f.write(pan_report)

        self.__append_hash(PANHuntConfigSingleton.instance().output_file)

    def check_file_hash(self, text_file: str) -> None:

        with open(text_file, encoding='utf-8', mode='r') as f:
            text_output: str = f.read()

        hash_pos: int = text_output.rfind(os.linesep)
        hash_in_file: str = text_output[hash_pos + len(os.linesep):]
        hash_check: str = self.__get_text_hash(text_output[:hash_pos])
        if hash_in_file == hash_check:
            print(colorama.Fore.GREEN + 'Hashes OK')
        else:
            print(colorama.Fore.RED + 'Hashes Not OK')
        print(colorama.Fore.WHITE + hash_in_file + '\n' + hash_check)

    def __find_all_files_in_search_directory(self) -> list[PANFile]:
        """Recursively searches a directory for files. search_extensions is a dictionary of extension lists"""

        all_extensions: list[str] = [ext for ext_list in list(
            PANHuntConfigSingleton.instance().search_extensions.values()) for ext in ext_list]

        extension_types: dict[str, str] = {}
        for ext_type, ext_list in PANHuntConfigSingleton.instance().search_extensions.items():
            for ext in ext_list:
                extension_types[ext] = ext_type

        self.pbar = MainProgressbar()
        # TODO: move progressbar update methods here
        self.pbar.create('Doc')

        doc_files: list[PANFile] = []
        root_dir_dirs: Optional[list[str]] = None
        root_items_completed = 0
        docs_found = 0

        root_total_items: int = 0
        for root, sub_ds, files in os.walk(PANHuntConfigSingleton.instance().search_dir):
            sub_dirs: list[str] = [check_dir for check_dir in sub_ds if os.path.join(
                root, check_dir)
                .lower() not in PANHuntConfigSingleton.instance().excluded_directories]
            if not root_dir_dirs:
                root_dir_dirs = [os.path.join(root, sub_dir)
                                 for sub_dir in sub_dirs]
                root_total_items = len(root_dir_dirs) + len(files)
            if root in root_dir_dirs:
                root_items_completed += 1
                self.pbar.update(
                    hunt_type='Doc',
                    items_found=docs_found,
                    items_total=root_total_items,
                    items_completed=root_items_completed)

            for filename in files:
                if root == PANHuntConfigSingleton.instance().search_dir:
                    root_items_completed += 1
                pan_file = PANFile(filename, root)
                if pan_file.ext.lower() in all_extensions:
                    pan_file.set_file_stats()
                    pan_file.filetype = extension_types[pan_file.ext.lower()]
                    if pan_file.filetype in ('TEXT', 'SPECIAL') and pan_file.size > TEXT_FILE_SIZE_LIMIT:
                        pan_file.filetype = 'OTHER'
                        pan_file.set_error(
                            f'File size {panutils.size_friendly(pan_file.size)} over limit of {panutils.size_friendly(TEXT_FILE_SIZE_LIMIT)} for checking')
                    doc_files.append(pan_file)
                    if not pan_file.errors:
                        docs_found += 1
                    self.pbar.update(
                        hunt_type='Doc',
                        items_found=docs_found,
                        items_total=root_total_items,
                        items_completed=root_items_completed)

        self.pbar.finish()

        return doc_files

    def __find_all_regexs_in_files(self, text_or_zip_files: list[PANFile], hunt_type: str) -> tuple[int, int]:
        """ Searches files in doc_files list for regular expressions"""

        # TODO: Create a separate FileProgressbar here
        self.pbar.create(hunt_type=hunt_type)

        total_files: int = len(text_or_zip_files)
        files_completed = 0
        matches_found = 0

        for pan_file in text_or_zip_files:
            matches: list[PAN] = pan_file.check_regexs(excluded_pans_list=PANHuntConfigSingleton.instance().excluded_pans,
                                                       search_extensions=PANHuntConfigSingleton.instance().search_extensions)
            matches_found += len(matches)
            files_completed += 1
            self.pbar.update(
                hunt_type=hunt_type, items_found=matches_found, items_total=total_files, items_completed=files_completed)

        self.pbar.finish()

        return total_files, matches_found

    def __find_all_regexs_in_psts(self, pst_files: list[PANFile], hunt_type: str) -> tuple[int, int]:
        """ Searches psts in pst_files list for regular expressions in messages and attachments"""

        total_psts: int = len(pst_files)
        psts_completed = 0
        matches_found = 0

        for file in pst_files:

            with FileProgressbar(hunt_type, file.filename) as sub_pbar:
                for completed, total_items in file.check_pst_regexs(
                        excluded_pans_list=PANHuntConfigSingleton.instance().excluded_pans,
                        search_extensions=PANHuntConfigSingleton.instance().search_extensions):

                    sub_pbar.update(items_found=len(file.matches),
                                    items_total=total_items, items_completed=completed)
                matches_found += len(file.matches)
                psts_completed += 1
        return total_psts, matches_found

    def __append_hash(self, text_file: str) -> None:

        with open(text_file, encoding='utf-8', mode='r') as f:
            text: str = f.read()

        hash_check: str = self.__get_text_hash(text)

        text += os.linesep + hash_check

        with open(text_file, encoding='utf-8', mode='w') as f:
            f.write(text)

    def __get_text_hash(self, text: str | bytes) -> str:
        encoded_text: bytes

        if isinstance(text, str):
            encoded_text = text.encode('utf-8')
        else:
            encoded_text = text

        return hashlib.sha512(encoded_text + 'PAN'.encode('utf-8')).hexdigest()


###################################################################################################################################
#  __  __       _
# |  \/  | __ _(_)_ __
# | |\/| |/ _` | | '_ \
# | |  | | (_| | | | | |
# |_|  |_|\__,_|_|_| |_|
#
###################################################################################################################################


def main() -> None:
    application_path: str = '.'
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    elif __file__:
        application_path = os.path.dirname(__file__)
    logging.basicConfig(filename=os.path.join(application_path, 'PANhunt.log'),
                        encoding='utf-8',
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)

    excepthook = logging.error
    logging.info('Starting')

    colorama.init()

    # Command Line Arguments
    arg_parser: argparse.ArgumentParser = argparse.ArgumentParser(prog='panhunt', description='PAN Hunt v%s: search directories and sub directories for documents containing PANs.' % (
        app_version), formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument(
        '-s', dest='search', help='base directory to search in')
    arg_parser.add_argument('-x', dest='exclude',
                            help='directories to exclude from the search')
    arg_parser.add_argument(
        '-t', dest='text_files', help='text file extensions to search')
    arg_parser.add_argument(
        '-z', dest='zip_files', help='zip file extensions to search')
    arg_parser.add_argument('-e', dest='special_files',
                            help='special file extensions to search')
    arg_parser.add_argument(
        '-m', dest='mail_files', help='email file extensions to search')
    arg_parser.add_argument(
        '-l', dest='other_files', help='other file extensions to list')
    arg_parser.add_argument(
        '-o', dest='outfile', help='output file name for PAN report')
    arg_parser.add_argument('-u', dest='unmask', action='store_true',
                            default=False, help='unmask PANs in output')
    arg_parser.add_argument(
        '-C', dest='config', help='configuration file to use')
    arg_parser.add_argument(
        '-X', dest='exclude_pan', help='PAN to exclude from search')
    arg_parser.add_argument('-c', dest='check_file_hash',
                            help=argparse.SUPPRESS)  # hidden argument

    args: argparse.Namespace = arg_parser.parse_args()

    hunter = Hunter()
    if args.check_file_hash:
        hunter.check_file_hash(args.check_file_hash)
        sys.exit()

    search_dir = str(args.search)
    output_file = str(args.outfile)
    excluded_directories_string = str(args.exclude)
    text_extensions_string = str(args.text_files)
    zip_extensions_string = str(args.zip_files)
    special_extensions_string = str(args.special_files)
    mail_extensions_string = str(args.mail_files)
    other_extensions_string = str(args.other_files)
    mask_pans: bool = not args.unmask
    excluded_pans_string = str(args.exclude_pan)
    config_file = str(args.config)

    # The singleton is initiated at the first call with the hardcoded default values.
    # If exists, read the config file
    if config_file != 'None':
        PANHuntConfigSingleton.instance().from_file(
            config_file=config_file)

    # Finally, read the CLI parameters as they override the default and config file values
    PANHuntConfigSingleton.instance().from_args(search_dir=search_dir,
                                                output_file=output_file,
                                                mask_pans=mask_pans,
                                                excluded_directories_string=excluded_directories_string,
                                                text_extensions_string=text_extensions_string,
                                                zip_extensions_string=zip_extensions_string,
                                                special_extensions_string=special_extensions_string,
                                                mail_extensions_string=mail_extensions_string,
                                                other_extensions_string=other_extensions_string,
                                                excluded_pans_string=excluded_pans_string)

    total_files_searched, pans_found, all_files = hunter.hunt_pans()

    # report findings
    hunter.output_report(all_files,
                         total_files_searched, pans_found)


if __name__ == "__main__":
    try:
        main()
        logging.info('Exiting')
    except KeyboardInterrupt:
        print('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        logging.info('Exiting')
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
