from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations


class Config:
    def __init__(
        self,
        locations: Locations,
        handlers: list[Handler],
        functions: list[Function] = [],
    ):
        self.locations = locations
        self.handlers = handlers
        self.functions = functions
