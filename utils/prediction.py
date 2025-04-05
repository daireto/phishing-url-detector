import os
import pickle
from abc import ABC, abstractmethod
from typing import Literal, overload

from .func import get_most_recent_file


class PredictionModel(ABC):
    """Prediction model interface."""

    @abstractmethod
    def predict(
        self, X: list[list[int]], **kwargs: object
    ) -> list[Literal[1, 0]]: ...


def load_model(path: str) -> PredictionModel:
    """Loads a pre-trained model.

    Parameters
    ----------
    path : str
        Path to the model file.

    Returns
    -------
    PredictionModel
        Loaded model.
    """
    with open(path, 'rb') as f:
        return pickle.load(f)


@overload
def get_most_recent_model(
    path: str, raise_if_not_found: Literal[True] = True
) -> PredictionModel: ...


@overload
def get_most_recent_model(
    path: str, raise_if_not_found: Literal[False] = False
) -> PredictionModel | None: ...


def get_most_recent_model(
    path: str, raise_if_not_found: bool = True
) -> PredictionModel | None:
    """Gets the most recent model in a directory.

    Parameters
    ----------
    path : str
        Path to the directory.
    raise_if_not_found : bool, optional
        Raises an exception if no model is found, by default True.

    Returns
    -------
    PredictionModel | None
        Most recent model.

    Raises
    ------
    FileNotFoundError
        If no model is found and ``raise_if_not_found`` is True.
    """
    file = get_most_recent_file(path)
    if file is None:
        if raise_if_not_found:
            raise FileNotFoundError(f'no model found in {path!r}')
        return None

    return load_model(os.path.join(path, file))
