# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import ipaddress
import typing
import datetime
import os
import logging
from dataclasses import dataclass

from clickhouse_connect.driver.exceptions import DatabaseError, OperationalError
from clickhouse_connect import get_async_client
from clickhouse_connect.driver import AsyncClient
from framework.utils import retry_on_failure


@dataclass
class LogRecord:
    timestamp: datetime.datetime
    address: ipaddress.IPv6Address
    reason: int
    packets: int
    bytes: int
    dropped_events: int


@dataclass
class ClickhouseClient:
    host: str
    http_port: int
    binary_port: int
    user: str
    password: str
    database: str
    table: str
    logger: logging.Logger = None
    client: AsyncClient = None
    was_connected: bool = False

    async def connect(self):
        try:
            self.client = await get_async_client(
                host=self.host,
                port=self.http_port,
                username=self.user,
                password=self.password,
                database=self.database,
            )
            self.was_connected = True
            self.logger.debug(f'connected to clickhouse db. Using table {self.table}')

        except OperationalError as e:
            raise ConnectionError('Can not connect to Clickhouse') from e

    @classmethod
    def gen_new_table_name(cls) -> str:
        return f'escudo_test_{os.urandom(2).hex()}'

    @staticmethod
    def __build_log_record(db_record) -> LogRecord:
        return LogRecord(
            timestamp=db_record[0],
            address=db_record[1],
            reason=db_record[2],
            packets=db_record[3],
            bytes=db_record[4],
            dropped_events=db_record[5],
        )

    async def records_delete(self) -> None:
        """
        Delete all log records
        """
        if not await self.table_exists():
            return

        await self.client.command(f"delete from {self.table} where true")
        self.logger.debug('removed all records from the table')

    async def records_count(self) -> int:
        """
        Count all the log records
        """
        try:
            res = await self.client.query(f"select count(1) from {self.table}")
            return res.result_rows[0][0]
        except DatabaseError as e:
            assert "Unknown table" in str(e)
            return 0

    async def records_all(self) -> typing.List[LogRecord]:
        """
        Read all the log records
        """
        results = await self.client.query(
            f"""
            select * 
            from {self.table}
            """,
        )
        return list(
            map(
                lambda x: self.__build_log_record(x),
                results.result_rows,
            )
        )

    async def records_last(self) -> typing.Optional[LogRecord]:
        """
        Read the data of tfw_logger daemon file
        """
        records = await self.records_all()

        if not records:
            return None

        return records[-1]

    async def table_exists(self) -> bool:
        """
        Check if table already created
        """
        return await self.client.command(f"exists table {self.table}") == 1

    async def table_drop(self) -> str:
        """
        Drop the access log table if exists to clear the logs and
        prevent an errors while tests work with the different
        table schemas
        """
        self.logger.debug(f'dropped the table {self.table}')
        return await self.client.command(f"drop table if exists {self.table}")

    @retry_on_failure(AssertionError)
    async def wait_for_number_of_records(self, expected_records_n: int, msg: str = "") -> None:
        """
        We should use the `wait` method instead of the usual `records_all`
        because there may be a race condition between clickhouse and python.
        """
        records = await self.records_all()
        assert len(records) == expected_records_n, msg or f"Current number of records: {len(records)}"
