import configparser
import os
import time
from typing import Optional


class PANHuntConfigSingleton:
    search_dir: str = 'C:\\'
    config_file: str = 'panhunt.ini'
    output_file: str = f'panhunt_{time.strftime("%Y-%m-%d-%H%M%S")}.txt'
    mask_pans: bool = False
    excluded_directories: list[str] = ['C:\\Windows',
                                       'C:\\Program Files', 'C:\\Program Files(x86)']
    search_extensions: dict[str, list[str]] = {
        'TEXT': ['.doc', '.xls', '.xml', '.txt', '.csv', '.log'],
        'ZIP': ['.docx', '.xlsx', '.zip'],
        'SPECIAL': ['.msg'],
        'MAIL': ['.pst'],
        'OTHER': ['.ost', '.accdb', '.mdb']
    }
    excluded_pans: list[str] = []

    def __new__(cls) -> 'PANHuntConfigSingleton':
        if not hasattr(cls, 'instance'):
            cls.instance = super(PANHuntConfigSingleton, cls).__new__(cls)
        return cls.instance

    def __init__(self,
                 search_dir: Optional[str] = None,
                 output_file: Optional[str] = None,
                 mask_pans: bool = False,
                 excluded_directories_string: Optional[str] = None,
                 text_extensions_string: Optional[str] = None,
                 zip_extensions_string: Optional[str] = None,
                 special_extensions_string: Optional[str] = None,
                 mail_extensions_string: Optional[str] = None,
                 other_extensions_string: Optional[str] = None,
                 excluded_pans_string: Optional[str] = None) -> None:

        if search_dir:
            self.search_dir = search_dir

        if output_file:
            self.output_file = output_file

        self.mask_pans = mask_pans

        if excluded_directories_string:
            self.excluded_directories.extend([exc_dir.lower()
                                              for exc_dir in excluded_directories_string.split(',')])
        if text_extensions_string:
            self.search_extensions['TEXT'] = text_extensions_string.split(',')
        if zip_extensions_string:
            self.search_extensions['ZIP'] = zip_extensions_string.split(',')
        if special_extensions_string:
            self.search_extensions['SPECIAL'] = special_extensions_string.split(
                ',')
        if mail_extensions_string:
            self.search_extensions['MAIL'] = mail_extensions_string.split(',')
        if other_extensions_string:
            self.search_extensions['OTHER'] = other_extensions_string.split(
                ',')
        if excluded_pans_string and len(excluded_pans_string) > 0:
            self.excluded_pans = excluded_pans_string.split(',')

    @staticmethod
    def from_args(search_dir: Optional[str] = None,
                  output_file: Optional[str] = None,
                  mask_pans: bool = False,
                  excluded_directories_string: Optional[str] = None,
                  text_extensions_string: Optional[str] = None,
                  zip_extensions_string: Optional[str] = None,
                  special_extensions_string: Optional[str] = None,
                  mail_extensions_string: Optional[str] = None,
                  other_extensions_string: Optional[str] = None,
                  excluded_pans_string: Optional[str] = None) -> 'PANHuntConfigSingleton':
        """If any parameter is provided, it overwrites the previous value
        """

        c = PANHuntConfigSingleton()

        PANHuntConfigSingleton.__create(search_dir, output_file, mask_pans, excluded_directories_string, text_extensions_string,
                                        zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_pans_string, c)

        return c

    @staticmethod
    def from_file(config_file: Optional[str]) -> 'PANHuntConfigSingleton':
        """If a config file provided and it has specific values, they overwrite the previous values

        Args:
            config_file (Optional[str]): Path to config file in INI format
        """

        if config_file is None:
            return PANHuntConfigSingleton()

        if not os.path.isfile(config_file):
            return PANHuntConfigSingleton()

        c = PANHuntConfigSingleton()

        config: configparser.ConfigParser = configparser.ConfigParser()
        config.read(config_file)
        config_from_file: dict = {}

        for nvp in config.items('DEFAULT'):
            config_from_file[nvp[0]] = nvp[1]

        search_dir: Optional[str] = None
        if 'search' in config_from_file:
            search_dir = str(config_from_file['search'])

        excluded_directories_string: Optional[str] = None
        if 'exclude' in config_from_file:
            excluded_directories_string = str(config_from_file['exclude'])

        text_extensions_string: Optional[str] = None
        if 'textfiles' in config_from_file:
            text_extensions_string = str(config_from_file['textfiles'])

        zip_extensions_string: Optional[str] = None
        if 'zipfiles' in config_from_file:
            zip_extensions_string = str(config_from_file['zipfiles'])

        special_extensions_string: Optional[str] = None
        if 'specialfiles' in config_from_file:
            special_extensions_string = str(config_from_file['specialfiles'])

        mail_extensions_string: Optional[str] = None
        if 'mailfiles' in config_from_file:
            mail_extensions_string = str(config_from_file['mailfiles'])

        other_extensions_string: Optional[str] = None
        if 'otherfiles' in config_from_file:
            other_extensions_string = str(config_from_file['otherfiles'])

        output_file: Optional[str] = None
        if 'outfile' in config_from_file:
            output_file = str(config_from_file['outfile'])

        mask_pans: bool = False
        if 'unmask' in config_from_file:
            mask_pans = not (config_from_file['unmask'].upper() == 'TRUE')

        excluded_pans_string: Optional[str] = None
        if 'excludepans' in config_from_file:
            excluded_pans_string = str(config_from_file['excludepans'])

        PANHuntConfigSingleton.__create(search_dir, output_file, mask_pans, excluded_directories_string, text_extensions_string,
                                        zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_pans_string, c)

        return c

    @staticmethod
    def __create(search_dir, output_file, mask_pans, excluded_directories_string, text_extensions_string, zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_pans_string, c):
        if search_dir:
            c.search_dir = search_dir

        if output_file:
            c.output_file = output_file

        c.mask_pans = mask_pans

        if excluded_directories_string:
            c.excluded_directories = [exc_dir.lower()
                                      for exc_dir in excluded_directories_string.split(',')]
        if text_extensions_string:
            c.search_extensions['TEXT'] = text_extensions_string.split(',')
        if zip_extensions_string:
            c.search_extensions['ZIP'] = zip_extensions_string.split(',')
        if special_extensions_string:
            c.search_extensions['SPECIAL'] = special_extensions_string.split(
                ',')
        if mail_extensions_string:
            c.search_extensions['MAIL'] = mail_extensions_string.split(',')
        if other_extensions_string:
            c.search_extensions['OTHER'] = other_extensions_string.split(
                ',')
        if excluded_pans_string and len(excluded_pans_string) > 0:
            c.excluded_pans = excluded_pans_string.split(',')
