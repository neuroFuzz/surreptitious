# coding=utf-8
__author__ = 'Peter Wang'
__license__ = 'BSD'
__version__ = '0.5.0'

from .exceptions import Empty, Full  # noqa
from .queue import Queue  # noqa

try:
    from .pdict import PDict  # noqa
    from .sqlqueue import SQLiteQueue, FIFOSQLiteQueue, FILOSQLiteQueue, \
        UniqueQ  # noqa
    from .sqlackqueue import SQLiteAckQueue, UniqueAckQ
except ImportError:
    import logging

    log = logging.getLogger(__name__)
    log.info("No sqlite3 module found, sqlite3 based queues are not available")

__all__ = ["Queue", "SQLiteQueue", "FIFOSQLiteQueue", "FILOSQLiteQueue",
           "UniqueQ", "PDict", "SQLiteAckQueue", "UniqueAckQ", "Empty", "Full",
           "__author__", "__license__", "__version__"]
