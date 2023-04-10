import logging


class PANHuntException(BaseException):
    def __init__(self, message) -> None:
        logging.error(message)
