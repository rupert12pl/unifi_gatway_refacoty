from builtins import Warning
from typing import Optional, Type

from .exceptions import InsecureRequestWarning

def disable_warnings(category: Optional[Type[Warning]] = ...) -> None: ...
