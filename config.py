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
    json_path: Optional[str] = None

    # Here is the core of the singleton
    __instance: Optional['PANHuntConfigSingleton'] = None

    @staticmethod
    def instance() -> "PANHuntConfigSingleton":
        """ Static access method. """
        if PANHuntConfigSingleton.__instance is None:
            PANHuntConfigSingleton.__instance = PANHuntConfigSingleton()
        return PANHuntConfigSingleton.__instance

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
                 excluded_pans_string: Optional[str] = None,
                 json_path: Optional[str] = None) -> None:

        if search_dir:
            self.search_dir = search_dir

        if output_file:
            self.output_file = f'{output_file}_{time.strftime("%Y-%m-%d-%H%M%S")}.txt'

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
        if json_path:
            self.json_path = f'{json_path}_{time.strftime("%Y-%m-%d-%H%M%S")}'

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
                  excluded_pans_string: Optional[str] = None,
                  json_path: Optional[str] = None) -> None:
        """If any parameter is provided, it overwrites the previous value
        """

        PANHuntConfigSingleton.instance().update(search_dir, output_file, mask_pans, excluded_directories_string, text_extensions_string,
                                                 zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_pans_string, json_path)

    @staticmethod
    def from_file(config_file: str) -> None:
        """If a config file provided and it has specific values, they overwrite the previous values

        Args:
            config_file (Optional[str]): Path to config file in INI format
        """

        if not os.path.isfile(config_file):
            raise ValueError("Invalid configuration file.")

        config_from_file: dict = PANHuntConfigSingleton.parse_file(config_file)

        search_dir: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='search')
        excluded_directories_string: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='exclude')
        text_extensions_string: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='textfiles')
        zip_extensions_string: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='zipfiles')
        special_extensions_string: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='specialfiles')
        mail_extensions_string: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='mailfiles')
        other_extensions_string: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='otherfiles')
        output_file: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='outfile')
        mask_pans: Optional[bool] = PANHuntConfigSingleton.check_masked(
            config_from_file)
        excluded_pans_string: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='excludepans')
        json_path: Optional[str] = PANHuntConfigSingleton.try_parse(
            config_from_file=config_from_file, property='json')

        PANHuntConfigSingleton.instance().update(search_dir, output_file, mask_pans, excluded_directories_string, text_extensions_string,
                                                 zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_pans_string, json_path)

    @staticmethod
    def parse_file(config_file):
        config: configparser.ConfigParser = configparser.ConfigParser()
        config.read(config_file)
        config_from_file: dict = {}

        for nvp in config.items('DEFAULT'):
            config_from_file[nvp[0]] = nvp[1]
        return config_from_file

    @staticmethod
    def check_masked(config_from_file) -> Optional[bool]:
        mask_pans: Optional[bool] = None
        if 'unmask' in config_from_file:
            mask_pans = not (config_from_file['unmask'].upper() == 'TRUE')
        return mask_pans

    @staticmethod
    def try_parse(config_from_file: dict, property: str) -> Optional[str]:
        if property in config_from_file:
            return str(config_from_file[property])
        return None

    @staticmethod
    def update(search_dir: Optional[str], output_file: Optional[str], mask_pans: Optional[bool], excluded_directories_string: Optional[str], text_extensions_string: Optional[str], zip_extensions_string: Optional[str], special_extensions_string: Optional[str], mail_extensions_string: Optional[str], other_extensions_string: Optional[str], excluded_pans_string: Optional[str],
               json_path: Optional[str]) -> None:

        conf: PANHuntConfigSingleton = PANHuntConfigSingleton.instance()
        if search_dir and search_dir != 'None':
            conf.search_dir = search_dir

        if output_file and output_file != 'None':
            conf.output_file = output_file

        if mask_pans:
            conf.mask_pans = mask_pans

        if excluded_directories_string and excluded_directories_string != 'None':
            conf.excluded_directories = [exc_dir.lower()
                                         for exc_dir in excluded_directories_string.split(',')]
        if text_extensions_string and text_extensions_string != 'None':
            conf.search_extensions['TEXT'] = text_extensions_string.split(',')
        if zip_extensions_string and zip_extensions_string != 'None':
            conf.search_extensions['ZIP'] = zip_extensions_string.split(',')
        if special_extensions_string and special_extensions_string != 'None':
            conf.search_extensions['SPECIAL'] = special_extensions_string.split(
                ',')
        if mail_extensions_string and mail_extensions_string != 'None':
            conf.search_extensions['MAIL'] = mail_extensions_string.split(',')
        if other_extensions_string and other_extensions_string != 'None':
            conf.search_extensions['OTHER'] = other_extensions_string.split(
                ',')
        if excluded_pans_string and excluded_pans_string != excluded_pans_string and len(excluded_pans_string) > 0:
            conf.excluded_pans = excluded_pans_string.split(',')

        if json_path:
            conf.json_path = f'{json_path}_{time.strftime("%Y-%m-%d-%H%M%S")}'
