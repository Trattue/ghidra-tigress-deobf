from gtd.config.function import Function
from gtd.config.handler import Handler


class Config:
    def __init__(self, handlers: list[Handler], functions: list[Function]):
        self.handlers = handlers
        self.functions = functions
