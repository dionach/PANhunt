#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# PANhunt: search directories and sub directories for documents with PANs
# By BB

import os, sys, zipfile, re, datetime, io, argparse, time, hashlib, unicodedata, platform
import colorama
import configparser
import progressbar
import filehunt

app_version = '1.2'

# defaults
defaults = {
    'search_dir': 'C:\\',
    'output_file': 'panhunt_%s.txt' % time.strftime("%Y-%m-%d-%H%M%S"),
    'excluded_directories_string': 'C:\\Windows,C:\\Program Files,C:\\Program Files (x86)',
    'text_extensions_string':  '.doc,.xls,.xml,.txt,.csv,.log',
    'zip_extensions_string': '.docx,.xlsx,.zip',
    'special_extensions_string': '.msg',
    'mail_extensions_string': '.pst',
    'other_extensions_string': '.ost,.accdb,.mdb', # checks for existence of files that can't be checked automatically
    'excluded_pans_string': '',
    'config_file': 'panhunt.ini'
}
search_dir = defaults['search_dir']
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
excluded_pans = []
search_extensions = {}

pan_regexs = {'Mastercard': re.compile('(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                'Visa': re.compile('(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                'AMEX': re.compile('(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)')}


###################################################################################################################################
#   ____ _                         
#  / ___| | __ _ ___ ___  ___  ___ 
# | |   | |/ _` / __/ __|/ _ \/ __|
# | |___| | (_| \__ \__ \  __/\__ \
#  \____|_|\__,_|___/___/\___||___/
#                                  
###################################################################################################################################


class PANFile(filehunt.AFile):
    """ PANFile: class for a file that can check itself for PANs"""

    def __init__(self, filename, file_dir):
        
        filehunt.AFile.__init__(self, filename, file_dir)
        #self.type = None # DOC, ZIP, MAIL, SPECIAL, OTHER  


    def check_text_regexs(self, text, regexs, sub_path):
        """Uses regular expressions to check for PANs in text"""

        for brand, regex in list(regexs.items()):
            pans = regex.findall(text)
            if pans:
                for pan in pans:
                    if PAN.is_valid_luhn_checksum(pan) and not PAN.is_excluded(pan):
                        self.matches.append(PAN(self.path, sub_path, brand, pan))


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
    def is_excluded(pan):
        global excluded_pans
        
        for excluded_pan in excluded_pans:
            if pan == excluded_pan:
                return True
        return False
        
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
        


###################################################################################################################################
#  __  __           _       _        _____                 _   _                 
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___ 
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################       


def get_text_hash(text):

    if type(text) is str:
        encoded_text = text.encode('utf-8')
    else:
        encoded_text = text
    return hashlib.sha512(encoded_text+'PAN'.encode('utf-8')).hexdigest()


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
        sys.stdout.buffer.write(colorama.Fore.GREEN.encode('ascii','ignore') + 'Hashes OK\n'.encode('ascii','ignore'))
    else:
        sys.stdout.buffer.write(colorama.Fore.RED.encode('ascii','ignore') + 'Hashes Not OK\n'.encode('ascii','ignore'))
    sys.stdout.buffer.write(colorama.Fore.WHITE.encode('ascii','ignore') + hash_in_file +'\n' + hash_check)


def output_report(search_dir, excluded_directories_string, all_files, total_files_searched, pans_found, output_file, mask_pans):

    pan_sep = u'\n\t'
    pan_report = u'PAN Hunt Report - %s\n%s\n' % (time.strftime("%H:%M:%S %d/%m/%Y"), '='*100)
    pan_report += u'Searched %s\nExcluded %s\n' % (search_dir, excluded_directories_string)
    pan_report += u'Command: %s\n' % (' '.join(sys.argv))
    pan_report += u'Uname: %s\n' % (' | '.join(platform.uname()))
    pan_report += u'Searched %s files. Found %s possible PANs.\n%s\n\n' % (total_files_searched, pans_found, '='*100)
    
    for afile in sorted([afile for afile in all_files if afile.matches]):
        pan_header = 'FOUND PANs: %s (%s %s)' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))
        sys.stdout.buffer.write(colorama.Fore.RED.encode('ascii','ignore') + filehunt.unicode2ascii(pan_header) + '\n'.encode('ascii','ignore'))
        pan_report += pan_header + '\n'
        pan_list = '\t' + pan_sep.join([pan.__repr__(mask_pans) for pan in afile.matches])
        sys.stdout.buffer.write(colorama.Fore.YELLOW.encode('ascii','ignore') + filehunt.unicode2ascii(pan_list) + '\n'.encode('ascii','ignore'))
        pan_report += pan_list + '\n\n'
    
    if len([afile for afile in all_files if afile.type == 'OTHER']) <> 0:
        pan_report += u'Interesting Files to check separately:\n'
    for afile in sorted([afile for afile in all_files if afile.type == 'OTHER']):
        pan_report += '%s (%s %s)\n' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))

    pan_report = pan_report.replace('\n', os.linesep)

    sys.stdout.buffer.write(colorama.Fore.WHITE.encode('ascii','ignore') + 'Report written to '.encode('ascii','ignore') + filehunt.unicode2ascii(output_file) + '\n'.encode('ascii','ignore'))
    filehunt.write_unicode_file(output_file, pan_report)
    add_hash_to_file(output_file)

def load_config_file():
  
    global config_file, defaults, search_dir, output_file, excluded_directories_string, text_extensions_string, zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, mask_pans, excluded_pans_string

    if not os.path.isfile(config_file):
        return
      
    config = ConfigParser.ConfigParser()
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
    
def set_global_parameters():

    global excluded_directories_string, text_extensions_string, zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_directories, search_extensions, excluded_pans_string, excluded_pans

    excluded_directories = [exc_dir.lower() for exc_dir in excluded_directories_string.split(',')]    
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
    all_files = filehunt.find_all_files_in_directory(PANFile, search_dir, excluded_directories, search_extensions, gauge_update_function)

    # check each file
    total_docs, doc_pans_found = filehunt.find_all_regexs_in_files([afile for afile in all_files if not afile.errors and afile.type in ('TEXT','ZIP','SPECIAL')], pan_regexs, search_extensions, 'PAN', gauge_update_function)
    # check each pst message and attachment
    total_psts, pst_pans_found = filehunt.find_all_regexs_in_psts([afile for afile in all_files if not afile.errors and afile.type == 'MAIL'], pan_regexs, search_extensions, 'PAN', gauge_update_function)

    total_files_searched = total_docs + total_psts
    pans_found = doc_pans_found + pst_pans_found

    return total_files_searched, pans_found, all_files


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
    arg_parser = argparse.ArgumentParser(prog='panhunt', description='PAN Hunt v%s: search directories and sub directories for documents containing PANs.' % (app_version), formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-s', dest='search', default=search_dir, help='base directory to search in')
    arg_parser.add_argument('-x', dest='exclude', default=excluded_directories_string, help='directories to exclude from the search')
    arg_parser.add_argument('-t', dest='textfiles', default=text_extensions_string, help='text file extensions to search')
    arg_parser.add_argument('-z', dest='zipfiles', default=zip_extensions_string, help='zip file extensions to search')
    arg_parser.add_argument('-e', dest='specialfiles', default=special_extensions_string, help='special file extensions to search')
    arg_parser.add_argument('-m', dest='mailfiles', default=mail_extensions_string, help='email file extensions to search')
    arg_parser.add_argument('-l', dest='otherfiles', default=other_extensions_string, help='other file extensions to list')
    arg_parser.add_argument('-o', dest='outfile', default=output_file, help='output file name for PAN report')
    arg_parser.add_argument('-u', dest='unmask', action='store_true', default=False, help='unmask PANs in output')
    arg_parser.add_argument('-C', dest='config', default=config_file, help='configuration file to use')
    arg_parser.add_argument('-X', dest='excludepan', default=excluded_pans_string, help='PAN to exclude from search')
    arg_parser.add_argument('-c', dest='checkfilehash', help=argparse.SUPPRESS) # hidden argument

    args = arg_parser.parse_args()    
    
    if args.checkfilehash:
        check_file_hash(args.checkfilehash)
        sys.exit()

    search_dir = unicode(args.search)
    output_file = unicode(args.outfile)
    excluded_directories_string = unicode(args.exclude)
    text_extensions_string = unicode(args.textfiles)    
    zip_extensions_string = unicode(args.zipfiles)
    special_extensions_string = unicode(args.specialfiles)
    mail_extensions_string = unicode(args.mailfiles)
    other_extensions_string = unicode(args.otherfiles)
    mask_pans = not args.unmask
    excluded_pans_string = str(args.excludepan)
    config_file = str(args.config)
    load_config_file()
        
    set_global_parameters()

    total_files_searched, pans_found, all_files = hunt_pans()

    # report findings
    output_report(search_dir, excluded_directories_string, all_files, total_files_searched, pans_found, output_file, mask_pans)