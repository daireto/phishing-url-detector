"""This module provides the ``BaseFeatureExtractor`` class
to define feature extractors.
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseFeatureExtractor(ABC):
    """Base class for feature extractors."""

    @abstractmethod
    def extract(self, obj: object, *args, **kwargs) -> dict[str, Any]:
        """Extracts features from an object.

        Parameters
        ----------
        obj : object
            Object to extract features from.

        Returns
        -------
        dict[str, Any]
            Extracted features.
        """
        ...
