"""
Backends subpackage initializing available routing solutions (e.g., EchoBackend).
"""

from astunnel.backends.base import BaseBackend
from astunnel.backends.echo import EchoBackend

BACKEND_REGISTRY = {
    "echo": EchoBackend,
}


def get_backend_class(name: str):
    """Retrieve backend constructor class by name."""
    return BACKEND_REGISTRY.get(name, BaseBackend)
