import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.routing import Mount
from starlette.routing import Route as StarletteRoute
from starlette.staticfiles import StaticFiles
from starlette_di import DependencyInjectionMiddleware, ServiceCollection

from core import logger
from core.api.route import Route
from core.i18n import I18N
from core.settings import Settings
from extractors.url_feature_extractor import IURLFeaturesExtractor
from lib.apispec import StarletteAPISpec
from middlewares import middlewares
from routers import routers
from services.prediction_service import IPredictionService, PredictionService

services = ServiceCollection()
services.add_transient(I18N)
services.add_singleton(IURLFeaturesExtractor, Settings.url_features_extractor)
services.add_scoped(IPredictionService, PredictionService)
service_provider = services.build_provider()


async def homepage(request: Request):
    i18n = service_provider.get_service(I18N)
    i18n.locale = request.query_params.get('lang', 'en').lower()
    feature_descriptions = i18n.locales.get(i18n.locale, {}).get('features', {})
    return Settings.templates.TemplateResponse(
        request, 'index.j2', {'t': i18n, 'feature_descriptions': feature_descriptions}
    )


routes = [
    *Route.get_from_routers(routers),
    Mount('/static', app=StaticFiles(directory='static'), name='static'),
    StarletteRoute('/', endpoint=homepage, include_in_schema=False),
]

middlewares = [
    Middleware(
        TrustedHostMiddleware,
        allowed_hosts=Settings.trusted_host.ALLOWED_HOSTS,
    ),
    Middleware(
        CORSMiddleware,
        allow_origins=Settings.cors.ALLOW_ORIGINS,
        allow_methods=Settings.cors.ALLOW_METHODS,
        allow_headers=Settings.cors.ALLOW_HEADERS,
        expose_headers=Settings.cors.EXPOSE_HEADERS,
    ),
    Middleware(
        DependencyInjectionMiddleware, service_provider=service_provider
    ),
    *middlewares,
]

app = Starlette(
    debug=not Settings.server.PROD,
    routes=routes,
    middleware=middlewares,
)

StarletteAPISpec(
    app=app,
    servers=[Settings.get_server_url()],
    title=Settings.api_spec.OPENAPI_TITLE,
    version=Settings.api_spec.OPENAPI_VERSION,
    description=Settings.api_spec.OPENAPI_DESCRIPTION,
    logger=logger,
).mount()

if __name__ == '__main__':
    if not Settings.server.PROD:
        logger.info('Running in development mode')

    uvicorn.run(
        app='main:app',
        port=Settings.server.PORT,
        log_config=Settings.get_logger_conf(),
        reload=not Settings.server.PROD,
    )
