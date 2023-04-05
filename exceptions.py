
class MSGException(BaseException):
    msg: str

    def __init__(self, msg) -> None:
        self.msg = msg
        print(self.msg)

    def __str__(self) -> str:
        return self.msg


class PSTException(BaseException):
    msg: str

    def __init__(self, msg) -> None:
        self.msg = msg
        print(self.msg)

    def __str__(self) -> str:
        return self.msg
