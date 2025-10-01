from enum import Enum


class Platform(str, Enum):
    SENSOR = "sensor"


UnitOfTime = Enum("UnitOfTime", {"MILLISECONDS": "milliseconds"})
