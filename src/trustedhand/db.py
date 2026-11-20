"""DynamoDB access helpers and time helpers."""
import datetime
import functools
import time

import boto3

from . import config
from .rules import ist  # noqa: F401  (re-exported for handlers)

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


@functools.lru_cache(maxsize=None)
def ddb():
    return boto3.resource("dynamodb")


@functools.lru_cache(maxsize=None)
def client():
    return boto3.client("dynamodb")


@functools.lru_cache(maxsize=None)
def tbl(name):
    return ddb().Table(config.table(name))


def now():
    return int(time.time())


def iso(epoch):
    if epoch is None:
        return None
    return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).isoformat(timespec="seconds")


def today_ist(epoch=None):
    t = datetime.datetime.fromtimestamp(epoch if epoch is not None else time.time(), IST)
    return t.strftime("%Y-%m-%d")


def clear_caches():
    """For tests that swap AWS mocks."""
    ddb.cache_clear()
    client.cache_clear()
    tbl.cache_clear()
