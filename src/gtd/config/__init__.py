from gtd.config.handler import Handler


class Config:
    def __init__(self):
        self.handlers: list[Handler] = []
