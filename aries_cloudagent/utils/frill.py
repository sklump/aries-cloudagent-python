"""Frills."""

import json

from enum import IntEnum
from pprint import pformat
from time import time
from typing import Any


def ppjson(dumpit: Any, elide_to: int = None) -> str:
    """
    JSON pretty printer, whether already json-encoded or not.

    :param dumpit: object to pretty-print
    :param elide_to: optional maximum sub-component length including ellipses ('...')
    :return: json pretty-print
    """

    def elide(d: dict, elide_to):
        """Recursively elide any component to 256 characters."""
        if not elide_to:
            return d
        for (k, v) in d.items():
            if isinstance(v, dict):
                d[k] = elide(v, elide_to)
            elif isinstance(v, str) and len(v) > elide_to:
                d[k] = f"{v[0:(elide_to-3)]}..."
            elif isinstance(v, list) and len(v) > elide_to:
                d[k] = v[0:(elide_to)]
                d[k][-1] = "..."
        return d

    if elide_to is not None:
        dumpit = json.loads(json.dumps(dumpit))  # alter a copy, not the original
        elide_to = max(elide_to, 3)  # make room for ellipses '...'
    try:
        rv = json.dumps(
            (
                elide(json.loads(dumpit), elide_to)
                if isinstance(dumpit, str)
                else elide(dumpit, elide_to)
            ),
            indent=4,
        )
    except TypeError:
        rv = f"{pformat(dumpit, indent=4, width=120)}"
    return rv


class Stopwatch:
    """Stopwatch class for troubleshooting lags."""

    def __init__(self, digits: int = None):
        """
        Instantiate and start.

        Args: number of fractional decimal digits to retain (default to all) by default
        """

        self._mark = [time()] * 2
        self._digits = digits

    def mark(self, digits: int = None) -> float:
        """
        Return time in seconds since last mark, reset, or construction.

        Args: number of fractional decimal digits to retain (default as constructed)
        """

        self._mark[:] = [self._mark[1], time()]
        rv = self._mark[1] - self._mark[0]

        if digits is not None and digits > 0:
            rv = round(rv, digits)
        elif digits == 0 or self._digits == 0:
            rv = int(rv)
        elif self._digits is not None and self._digits > 0:
            rv = round(rv, self._digits)

        return rv

    def reset(self) -> float:
        """Reset."""

        self._mark = [time()] * 2
        return 0.0


class Ink(IntEnum):
    """Class encapsulating ink colours for logging."""

    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37

    def __call__(self, message: str) -> str:
        """
        Return input message in colour.

        :return: input message in colour
        """

        return "\033[{}m{}\033[0m".format(self.value, message)
