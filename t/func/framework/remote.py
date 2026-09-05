# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import inspect
import os
import time
import typing

from config import TestingModel
from framework.rpc.client import RpcClient
from framework.rpc.protocol import (
    SENTINEL_CLICKHOUSE,
    SENTINEL_LOOP,
    TYPE_ASYNC,
    TYPE_ATTR,
    TYPE_DEF,
    TYPE_NEW,
)


class RemoteCommandExecutingError(Exception):
    """
    The error raised when a remote command execution fails.
    """


class RemotePythonInterpreter:
    """
    Base wrapper class that proxies local method calls to a remote machine
    via the RPC client.

    Overrides __getattribute__ to intercept method calls. Each call is
    sent as a structured request (id, type, name, params) and the reply
    is matched by id.

    Only simple types (int, str, bool, None) are supported
    as arguments and return values.
    """

    remote_methods = ()
    _simple_types = (str, int, float, bool, type(None))

    def __init__(
        self,
        *args,
        original_local_class=typing.Any,
        rpc_connection: RpcClient = None,
        working_dir: str = None,
        python_path: str = None,
        **kwargs,
    ) -> None:
        self.args = args
        self.kwargs = kwargs
        self.kwargs.pop("testing_model")

        self.logger = self.kwargs["logger"]

        self.original_class = original_local_class
        self.original_class.__init__ = self.patched_init
        self.original_obj = self.original_class(*self.args, **self.kwargs)
        self.original_class.__getattribute__ = self.patched_getattribute()

        self.working_dir = working_dir
        self.python_path = python_path
        self.remote_process = False
        self.rpc_connection = rpc_connection
        self.remote_var = f"obj_{original_local_class.__name__}_{os.urandom(2).hex()}"
        self.remote_class_name = original_local_class.__name__

    def get_new_obj(self):
        """
        тут надо создавать новое подключение и обьект на удаленной стороне
        """
        return self.original_obj

    async def exec_remote_cmd(
        self,
        req_type: str,
        name: str,
        params: list = None,
        kwargs: dict = None,
        target: str = None,
    ) -> typing.Any:
        """
        Send a structured call to the RPC server.
        """
        target = self.remote_var if target is None else target
        self.logger.info(f"exec type={req_type} target={target} name={name}")
        start_at = time.time()
        output = self.read_output(
            await self.rpc_connection.call_async(
                req_type, target=target, name=name, params=params, kwargs=kwargs
            )
        )
        waited_time = time.time() - start_at
        self.logger.debug(f"output=`{output}`, waited = {waited_time:.3f}s")
        return output

    def exec_remote_cmd_sync(
        self,
        req_type: str,
        name: str,
        params: list = None,
        kwargs: dict = None,
        target: str = None,
    ) -> typing.Any:
        """
        Send a structured call to the RPC server from synchronous code.
        """
        target = self.remote_var if target is None else target
        self.logger.info(f"exec type={req_type} target={target} name={name}")
        start_at = time.time()
        output = self.read_output(
            self.rpc_connection.call_sync(
                req_type, target=target, name=name, params=params, kwargs=kwargs
            )
        )
        waited_time = time.time() - start_at
        self.logger.debug(f"output=`{output}`, waited = {waited_time:.3f}s")
        return output

    def __remote_call_method(self, method_name: str) -> typing.Any:
        """
        Wraps the called method with RPC execution.
        """

        def wrapper(*args, **kwargs) -> typing.Any:
            params, call_kwargs = self.collect_params(args, kwargs)
            return self.exec_remote_cmd_sync(
                TYPE_DEF, method_name, params=params, kwargs=call_kwargs
            )

        return wrapper

    def __remote_call_coroutine(self, method_name: str) -> typing.Any:
        """
        Wraps the called method with RPC execution.
        """

        async def wrapper(*args, **kwargs) -> typing.Any:
            params, call_kwargs = self.collect_params(args, kwargs)
            return await self.exec_remote_cmd(
                TYPE_ASYNC, method_name, params=params, kwargs=call_kwargs
            )

        return wrapper

    def __remote_call_attribute(self, method_name: str) -> typing.Any:
        """
        Fetch a remote attribute or property from synchronous code.
        """
        return self.exec_remote_cmd_sync(TYPE_ATTR, method_name)

    def patched_init(self, *_, **__):
        pass

    def patched_getattribute(self):
        """
        Wrap methods, properties and instance attributes with a remote call.
        """

        def wrapper(obj, item: str):
            target = inspect.getattr_static(self.original_class, item, None)

            if inspect.iscoroutinefunction(target):
                return self.__remote_call_coroutine(item)

            if isinstance(target, (classmethod, staticmethod)) or inspect.isroutine(target):
                return self.__remote_call_method(item)

            return self.__remote_call_attribute(item)

        return wrapper

    def read_output(self, result: typing.Any):
        """
        Converts the RPC reply to the corresponding Python type.
        If an error was returned, raises it.
        """
        if result is None:
            self.logger.debug("response is None")
            return None

        if isinstance(result, bool):
            self.logger.debug("response is bool")
            return result

        if isinstance(result, (int, float, list, dict)):
            self.logger.debug(f"response is {type(result).__name__}")
            return result

        if not isinstance(result, str):
            return result

        if not result:
            self.logger.debug("no response")
            return None

        if result == "None":
            self.logger.debug("response is None")
            return None

        if result.isnumeric():
            self.logger.debug("response is numeric")
            return int(result)

        if result in {"False", "True"}:
            self.logger.debug("response is bool")
            return result == "True"

        if "Traceback" in result:
            if "TimeoutError" in result:
                raise TimeoutError("Remote command executed with timeout on RPC server side")

            raise RemoteCommandExecutingError(result)

        self.logger.debug("response is str")
        return result

    async def create_remote_object(self):
        """
        Create the instance of the class on the remote machine
        """

        self.logger.info(f"rpc current event loop id = {id(asyncio.get_running_loop())}")
        params, kwargs = self.collect_params(
            (),
            self.kwargs,
            add_event_loop=True,
            add_testing_model=TestingModel.machine_local,
            add_clickhouse="xfw" in self.remote_class_name.lower(),
        )
        await self.exec_remote_cmd(
            TYPE_NEW, self.remote_class_name, params=params, kwargs=kwargs, target=self.remote_var
        )
        self.remote_process = True

    @classmethod
    def collect_params(
        cls,
        args: tuple,
        kwargs: dict,
        add_event_loop: bool = False,
        add_testing_model: int = None,
        add_clickhouse: bool = False,
    ) -> tuple[list, dict]:
        """
        Collect JSON-serializable *args and **kwargs for an RPC call.
        """
        params = [arg for arg in args if isinstance(arg, cls._simple_types)]
        call_kwargs = {k: v for k, v in kwargs.items() if isinstance(v, cls._simple_types)}

        if add_event_loop:
            call_kwargs["loop"] = SENTINEL_LOOP

        if add_testing_model is not None:
            call_kwargs["testing_model"] = int(add_testing_model)

        if add_clickhouse:
            call_kwargs["clickhouse_client"] = SENTINEL_CLICKHOUSE

        return params, call_kwargs
