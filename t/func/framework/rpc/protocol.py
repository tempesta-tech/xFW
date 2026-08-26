# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import json
from dataclasses import asdict, dataclass, field
from typing import Any

TYPE_ASYNC = "async"
TYPE_DEF = "def"
TYPE_ATTR = "attr"
TYPE_NEW = "new"
TYPE_SHUTDOWN = "shutdown"

SENTINEL_LOOP = "$loop"
SENTINEL_CLICKHOUSE = "$clickhouse_client"

FRAME_END = "\n"


@dataclass
class RpcRequest:
    id: int
    type: str
    target: str = ""
    name: str = ""
    params: list[Any] = field(default_factory=list)
    kwargs: dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        return (json.dumps(asdict(self), ensure_ascii=False) + FRAME_END).encode()

    @classmethod
    def decode(cls, data: str) -> "RpcRequest":
        payload = json.loads(data)
        return cls(
            id=int(payload["id"]),
            type=payload["type"],
            target=payload.get("target") or "",
            name=payload.get("name") or "",
            params=payload.get("params") or [],
            kwargs=payload.get("kwargs") or {},
        )


@dataclass
class RpcResponse:
    id: int
    result: Any = None
    error: str = None

    def encode(self) -> bytes:
        return (json.dumps(asdict(self), ensure_ascii=False) + FRAME_END).encode()

    @classmethod
    def decode(cls, data: str) -> "RpcResponse":
        payload = json.loads(data)
        return cls(
            id=int(payload["id"]),
            result=payload.get("result"),
            error=payload.get("error"),
        )


def encode_result(res: Any) -> Any:
    """
    JSON-serialize a return value when possible, otherwise stringify it.
    """
    if res is None or isinstance(res, (str, int, float, bool)):
        return res

    if isinstance(res, tuple):
        res = list(res)

    if isinstance(res, (list, dict)):
        try:
            json.dumps(res)
            return res
        except TypeError:
            return str(res)

    return str(res)
