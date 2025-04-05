"""This module provides the ``BaseService`` class
to define services.
"""

from abc import ABC

from core.api.request import Request


class BaseService(ABC):
    """Base class for services."""

    request: Request
