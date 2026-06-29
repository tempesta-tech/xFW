# SPDX-FileCopyrightText: (c) 2026 Tempesta Technologies, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import sys


__loggers = dict()


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    global __loggers

    logger = __loggers.get(name)

    if logger:
        return logger

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    handler = logging.StreamHandler(sys.stdout)

    if level == logging.DEBUG:
        handler.setFormatter(
            logging.Formatter("[%(asctime)s][%(levelname)-8s][%(name)-10s][%(filename)s:%(lineno)d]: %(message)s")
        )
    else:
        handler.setFormatter(
            logging.Formatter("[%(asctime)s][%(levelname)-8s][%(name)-10s]: %(message)s")
        )
    logger.addHandler(handler)
    __loggers[name] = logger

    return __loggers[name]
