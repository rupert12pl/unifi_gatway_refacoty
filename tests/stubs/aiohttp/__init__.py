class ClientError(Exception):
    pass


class ClientTimeout:
    def __init__(self, total=None, connect=None, sock_read=None) -> None:
        self.total = total
        self.connect = connect
        self.sock_read = sock_read


class ClientResponse:
    def __init__(
        self, status: int = 200, headers: dict[str, str] | None = None, body: str = ""
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self._body = body

    async def __aenter__(self) -> "ClientResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def text(self) -> str:
        return self._body


class ClientSession:
    def __init__(self, timeout: ClientTimeout | None = None) -> None:
        self.timeout = timeout
        self.headers: dict[str, str] = {}
        self.closed = False

    async def __aenter__(self) -> "ClientSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, *args, **kwargs):
        raise NotImplementedError

    async def request(self, *args, **kwargs):
        raise NotImplementedError

    async def close(self) -> None:
        self.closed = True
