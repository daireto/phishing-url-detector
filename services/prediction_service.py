"""URL prediction service."""

from abc import ABC, abstractmethod

from core import I18N
from core.bases.base_service import BaseService
from core.settings import Settings
from dtos.prediction_dto import FeaturesDTO, PredictionResponseDTO
from extractors.url_feature_extractor import IURLFeaturesExtractor


class IPredictionService(BaseService, ABC):
    """URL prediction service interface."""

    @abstractmethod
    def predict(self, url: str) -> PredictionResponseDTO:
        """Predicts whether the provided URL is a phishing website.

        Parameters
        ----------
        url : str
            URL to predict.

        Returns
        -------
        PredictionResponseDTO
            Prediction result.
        """
        ...


class PredictionService(IPredictionService):
    """URL prediction service."""

    def __init__(self, t: I18N, ft_extractor: IURLFeaturesExtractor) -> None:
        self.t = t
        self.ft_extractor = ft_extractor

    def predict(self, url: str) -> PredictionResponseDTO:
        features = self.ft_extractor.extract(url)
        X = [list(features.values())]
        result = Settings.prediction.model.predict(X)[0]
        return PredictionResponseDTO(
            url=url, phishing=bool(result), features=FeaturesDTO(**features)
        )
