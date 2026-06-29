# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import asyncio
import typing
import time
import os
from config import TestingModel
from framework.rpc.client import RpcClient


class RemoteCommandExecutingError(Exception):
    """
    The error raised when a remote command execution fails.
    """


class RemotePythonInterpreter:
    """
    Base wrapper class that proxies local method calls to a remote machine
    via the RPC client.

    Overrides __getattribute__ to intercept method calls. If the method name
    is listed in `remote_methods`, it wraps the call with `remote_call`.

    Only simple types (int, str, bool, None) are supported
    as arguments and return values.

    Multiline commands are allowed and must end with the delimiter '>>>'.

    The remote execution result is automatically converted back to a simple
    Python type before being returned.
    """
    remote_methods = ()

    def __init__(
            self,
            *args,
            rpc_connection: RpcClient = None,
            working_dir: str = None,
            python_path: str = None,
            **kwargs
    ) -> None:
        self.kwargs = kwargs
        self.logger = self.kwargs.pop('logger')
        self.kwargs.pop('testing_model')

        self.timeout = self.kwargs.get('timeout')
        self.working_dir = working_dir
        self.python_path = python_path
        self.remote_process = False
        self.rpc_connection = rpc_connection
        self.remote_var = f'obj_{self.__class__.__name__}_{os.urandom(2).hex()}'
        self.remote_class_name = self.__class__.__name__.replace('Remote', '')

    async def exec_remote_cmd(self, cmd: str) -> typing.Optional[str]:
        """
        Send the 'cmd' to the RPC-Server for executing
        """
        self.logger.info(f'exec command: {cmd}' )
        cmd = f"{cmd}<<<"
        self.rpc_connection.writer.write(cmd.encode())
        await self.rpc_connection.writer.drain()

        start_at = time.time()
        output = None

        try:
            output = await self.read_output()
        except TimeoutError:
            ...
        finally:
            waited_time = time.time() - start_at
            self.logger.debug(f'output=`{output}`, waited = {waited_time:.3f}s, timeout={self.timeout}')

        return output

    def remote_call(self, method_name: str) -> typing.Any:
        """
        Wraps the called method with RPC execution.
        """
        async def wrapper(*args, **kwargs):
            params = self.create_method_params(args, kwargs)

            if not self.remote_process:
                await self.create_process()

            return await self.exec_remote_cmd(
                f'await {self.remote_var}.{method_name}({params})',
            )

        return wrapper

    def __getattribute__(self, item):
        """
        Checks whether the called method is listed in `remote_methods`
        and, if so, wraps it with `remote_call`.
        """
        remote_methods = object.__getattribute__(self, 'remote_methods')
        remote_call = object.__getattribute__(self, 'remote_call')

        if item not in remote_methods:
            return object.__getattribute__(self, item)

        return remote_call(item)

    async def read_output(self):
        """
        Reads the reply from the RPC server.
        If an error was returned, raises it.
        If simple data was returned, converts it to the corresponding Python type.
        """
        try:
            response = await asyncio.wait_for(
                self.rpc_connection.reader.readuntil(b'>>>'),
                timeout=self.timeout
            )

            if not response:
                self.logger.debug('no response')
                return None

            result = response.decode()[:-3]

            if result == 'None':
                self.logger.debug('response is None')
                return None

            if result.isnumeric():
                self.logger.debug('response is numeric')
                return int(result)

            if result in {'False', 'True'}:
                self.logger.debug('response is bool')
                return result == 'True'

            if 'Traceback' in result:
                if 'TimeoutError' in result:
                    raise TimeoutError('Remote command executed with timeout on RPC server side')

                raise RemoteCommandExecutingError(result)

            self.logger.debug('response is str')
            return result

        except asyncio.TimeoutError:
            self.logger.debug(f'response timeout: {self.timeout}')
            return None

    async def create_process(self):
        """
        Create the instance of the class on the remote machine
        """
        params = self.create_method_params(
            (),
            self.kwargs,
            add_event_loop=True,
            add_testing_model=TestingModel.machine_local,
        )
        await self.exec_remote_cmd(f'{self.remote_var} = {self.remote_class_name}({params})')
        self.remote_process = True

    @staticmethod
    def create_method_params(args: tuple, kwargs: dict, add_event_loop: bool = False, add_testing_model: int = None) -> str:
        """
        Creates a string representation of the method's *args and **kwargs for execution.
        """
        params = ''
        args_formatters = {
            str: '"""{v}"""'
        }
        kwargs_formatters = {
            str: '{k}="""{v}"""',
        }

        first_time = True

        for arg in args:
            formatter = args_formatters.get(arg.__class__, '{v}')

            if first_time:
                params += formatter.format(v=arg)
                first_time = False
            else:
                params += ','
                params += formatter.format(v=arg)

        first_time = True

        for k, v in kwargs.items():
            formatter = kwargs_formatters.get(v.__class__, '{k}={v}')

            if first_time:
                params += formatter.format(k=k, v=v)
                first_time = False
            else:
                params += ','
                params += formatter.format(k=k, v=v)

        if add_event_loop:
            params += ',loop=loop'

        if add_testing_model:
            params += f',testing_model={add_testing_model}'

        return params

    async def run_start(self):
        """
        Rewrites the `run_start` method to use a shared RPC call for
        all network classes in the user-defined async server.
        """
        await self.create_process()
        self.logger.debug(f'remote process with interpreter created, var = {self.remote_var}')

        await self.exec_remote_cmd(f'await {self.remote_var}.start()')


class RemoteServer(RemotePythonInterpreter):
    """
    Base remote server class for all user-defined servers.
    Defines the list of high-level RPC commands and overrides the `receive` method.
    """
    remote_methods = [
        'run_stop',
        'start',
        'stop',
        'restart',

        # tcp / udp
        'receive_message',
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def receive(self, *_, **__) -> typing.Optional[str]:
        return await self.exec_remote_cmd(f'await {self.remote_var}.receive()')
