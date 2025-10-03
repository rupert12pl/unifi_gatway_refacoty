from __future__ import annotations

from typing import Any, Iterable, Sequence

class Retry:
    total: int
    connect: int
    read: int
    backoff_factor: float
    status_forcelist: Sequence[int] | None
    allowed_methods: Iterable[str] | None

    def __init__(
        self,
        total: int = ...,
        connect: int = ...,
        read: int = ...,
        backoff_factor: float = ...,
        status_forcelist: Sequence[int] | None = ...,
        allowed_methods: Iterable[str] | None = ...,
        raise_on_status: bool = ...,
        respect_retry_after_header: bool = ...,
    ) -> None: ...

    def new(self, **kwargs: Any) -> Retry: ...
