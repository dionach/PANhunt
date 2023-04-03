import progressbar

import panutils


class ProgressbarSingleton:

    pbar: progressbar.ProgressBar

    def __new__(cls) -> 'ProgressbarSingleton':
        if not hasattr(cls, 'instance'):
            cls.instance = super(ProgressbarSingleton, cls).__new__(cls)
        return cls.instance

    def create(self, hunt_type: str) -> None:
        pbar_widgets: list = ['%s Hunt: ' % hunt_type, progressbar.Percentage(), ' ', progressbar.Bar(
            marker=progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' %ss:0' % hunt_type)]
        self.pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()

    def update(self, hunt_type: str, items_found: int, items_total: int, items_completed: int) -> None:
        self.pbar.widgets[6] = progressbar.FormatLabel(
            ' %ss:%s' % (hunt_type, items_found))
        self.pbar.update(items_completed * 100.0 / items_total)

    def finish(self) -> None:
        self.pbar.finish()


class SimpleSubbar:

    pbar: progressbar.ProgressBar
    title: str

    def __init__(self, title: str) -> None:
        self.title = title
        self.__create__()

    def __enter__(self) -> 'SimpleSubbar':
        self.__create__()
        return self

    def __create__(self) -> None:
        pbar_widgets: list = [self.title, progressbar.Percentage(), ' ', progressbar.Bar(
            marker=progressbar.RotatingMarker()), ' ', progressbar.ETA()]
        self.pbar = progressbar.ProgressBar(widgets=pbar_widgets).start()

    def update(self, value: float) -> None:
        self.pbar.update(value)

    def finish(self) -> None:
        self.pbar.finish()

    def __del__(self) -> None:
        self.finish()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.finish()


class FileSubbar:

    pbar: progressbar.ProgressBar
    filename: str
    hunt_type: str

    def __init__(self, hunt_type: str, filename: str) -> None:
        self.hunt_type = hunt_type
        self.filename = filename
        self.__create__()

    def __enter__(self) -> 'FileSubbar':
        self.__create__()
        return self

    def __create__(self) -> None:
        pbar_widgets: list = ['%s Hunt %s: ' % (self.hunt_type, panutils.unicode2ascii(self.filename)), progressbar.Percentage(), ' ', progressbar.Bar(
            marker=progressbar.RotatingMarker()), ' ', progressbar.ETA(), progressbar.FormatLabel(' %ss:0' % self.hunt_type)]
        self.pbar = progressbar.ProgressBar(
            widgets=pbar_widgets).start()

    def update(self, items_found: int, items_total: int, items_completed: int) -> None:
        self.pbar.widgets[6] = progressbar.FormatLabel(
            ' %ss:%s' % (self.hunt_type, items_found))
        self.pbar.update(items_completed * 100.0 / items_total)

    def finish(self) -> None:
        self.pbar.finish()

    def __del__(self) -> None:
        self.finish()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.finish()
