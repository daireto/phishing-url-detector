from starlette.concurrency import run_in_threadpool

from core.api.methods import post
from core.api.responses import DTOResponse
from core.bases.base_router import BaseRouter
from dtos.prediction_dto import PredictionRequestDTO, PredictionResponseDTO
from services.prediction_service import IPredictionService


class PredictionRouter(BaseRouter):

    @post('/predict')
    async def create_user(
        self, data: PredictionRequestDTO, service: IPredictionService
    ) -> DTOResponse[PredictionResponseDTO]:
        """Predicts whether the provided URL is a phishing website.

        ### Responses
        200 : DTOResponse[PredictionResponseDTO]
            Prediction result.
        """
        prediction = await run_in_threadpool(service.predict, data.url)
        return DTOResponse(prediction)
