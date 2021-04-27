"""Package-wide code and data."""

from typing import Mapping


def serial(obj):
    """Serialize if need be and return."""
    return obj if obj is None or isinstance(obj, Mapping) else obj.serialize()
