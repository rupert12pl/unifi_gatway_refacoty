from typing import Any, Callable, Dict, Optional, TypeVar, Union

T = TypeVar("T")

def callback(func: Callable[..., T]) -> Callable[..., T]:
    """A decorator to mark a function as a callback."""
    return func

class HomeAssistant:
    """Home Assistant class."""
    data: Dict[str, Any]
    bus: EventBus
    config_entries: Any

    def async_create_task(self, target: Union[Callable[..., Any], Any]) -> None: ...
    async def async_add_executor_job(self, target: Callable[..., T], *args: Any) -> T: ...
    def async_register_integration(self, integration: Any) -> None: ...

class EventBus:
    """Event bus for Home Assistant."""
    def fire(self, event_type: str, event_data: Optional[Dict[str, Any]] = None) -> None: ...
    def async_fire(self, event_type: str, event_data: Optional[Dict[str, Any]] = None) -> None: ...