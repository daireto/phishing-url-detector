"""This module provides the ``Settings`` class
to get the configuration of the application.
"""

import os
from dataclasses import dataclass
from typing import Literal

from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, Secret
from starlette.templating import Jinja2Templates

from extractors.url_feature_extractor import URLFeaturesExtractor
from utils.func import check_file_exists
from utils.prediction import PredictionModel, get_most_recent_model

from .definitions import ROOT_DIR

config = Config('.env')
"""Configuration object.

Loads the environment variables in the following order:

1. Environment variables.
2. The ``.env`` file.
3. Default values.
"""


@dataclass
class ServerStatus:
    """Server status."""

    status: Literal['ok', 'error']
    """Server status.

    Default: ``ok``
    """

    message: str
    """Server status message.

    Default: ``Server is running.``
    """


@dataclass
class ServerConfig:
    """Server configuration."""

    HTTP_SCHEMA: str
    """Server schema.

    Default: ``http``
    """

    HOST: str
    """Host name.

    Default: ``localhost``
    """

    PROD: bool
    """Production mode flag.

    Default: ``False``
    """

    PORT: int
    """Port number.

    Default: ``8000``
    """


@dataclass
class APISpecConfig:
    """API spec configuration."""

    OPENAPI_TITLE: str
    """OpenAPI title.

    Default: ``API``
    """

    OPENAPI_DESCRIPTION: str
    """OpenAPI description.

    Default: ``API description``
    """

    OPENAPI_VERSION: str
    """OpenAPI version.

    Default: ``0.0.1``
    """


@dataclass
class TrustedHostConfig:
    """Trusted host configuration."""

    ALLOWED_HOSTS: list[str]
    """Allowed hosts for ``starlette.middleware.trustedhost.TrustedHostMiddleware``.

    Example: ``["localhost", "127.0.0.1", "0.0.0.0"]``

    Default: ``["*"]``
    """


@dataclass
class CorsConfig:
    """CORS configuration."""

    ALLOW_ORIGINS: list[str]
    """Allowed origins for ``starlette.middleware.cors.CORSMiddleware``.

    Example: ``["http://localhost", "http://127.0.0.1", "http://0.0.0.0"]``

    Default: ``["*"]``
    """

    ALLOW_METHODS: list[str]
    """Allowed methods for ``starlette.middleware.cors.CORSMiddleware``.

    Example: ``["GET", "POST", "PUT", "DELETE"]``

    Default: ``["*"]``
    """

    ALLOW_HEADERS: list[str]
    """Allowed headers for ``starlette.middleware.cors.CORSMiddleware``.

    Example: ``["Authorization", "Content-Type"]``

    Default: ``["*"]``
    """

    EXPOSE_HEADERS: list[str]
    """Exposed headers for ``starlette.middleware.cors.CORSMiddleware``.

    Example: ``["Authorization", "Content-Disposition"]``
    """


@dataclass
class LoggerConfig:
    """Logger configuration."""

    LOGGER_CONF_FILE: str
    """Path to the logger configuration file.

    Default: ``logger.conf``
    """

    DEV_LOG_LEVEL: str
    """Development log level.

    Default: ``DEBUG``
    """

    PROD_LOG_LEVEL: str
    """Production log level.

    Default: ``INFO``
    """


@dataclass
class LocaleConfig:
    """Locale configuration."""

    LOCALE_DIR: str
    """Locale directory.

    Default: ``locales``
    """

    DEFAULT_LOCALE: str
    """Default locale.

    Default: ``es``
    """


@dataclass
class PredictionConfig:
    """Prediction configuration."""

    OPR_API_KEY: str
    """Open PageRank API key."""

    model: PredictionModel
    """Prediction model."""


class Settings:
    """Settings for the application."""

    status = ServerStatus(
        status='ok',
        message='Server is running',
    )
    """Server status."""

    server = ServerConfig(
        HTTP_SCHEMA=config('HTTP_SCHEMA', default='http'),
        HOST=config('HOST', default='localhost'),
        PROD=config('PROD', cast=bool, default=False),
        PORT=config('PORT', cast=int, default=8000),
    )
    """Server configuration."""

    api_spec = APISpecConfig(
        OPENAPI_TITLE=config('OPENAPI_TITLE', default='API'),
        OPENAPI_DESCRIPTION=config(
            'OPENAPI_DESCRIPTION', default='API description'
        ),
        OPENAPI_VERSION=config('OPENAPI_VERSION', default='0.0.1'),
    )
    """API spec configuration."""

    trusted_host = TrustedHostConfig(
        ALLOWED_HOSTS=list(
            config('ALLOWED_HOSTS', cast=CommaSeparatedStrings, default='*')
        ),
    )
    """Trusted host configuration."""

    cors = CorsConfig(
        ALLOW_ORIGINS=list(
            config('ALLOW_ORIGINS', cast=CommaSeparatedStrings, default='*')
        ),
        ALLOW_METHODS=list(
            config('ALLOW_METHODS', cast=CommaSeparatedStrings, default='*')
        ),
        ALLOW_HEADERS=list(
            config('ALLOW_HEADERS', cast=CommaSeparatedStrings, default='*')
        ),
        EXPOSE_HEADERS=list(
            config('EXPOSE_HEADERS', cast=CommaSeparatedStrings, default='')
        ),
    )
    """CORS configuration."""

    logger = LoggerConfig(
        LOGGER_CONF_FILE=config('LOGGER_CONF_FILE', default='logger.conf'),
        DEV_LOG_LEVEL=config('DEV_LOG_LEVEL', default='DEBUG'),
        PROD_LOG_LEVEL=config('PROD_LOG_LEVEL', default='INFO'),
    )
    """Logger configuration."""

    locale = LocaleConfig(
        LOCALE_DIR=config('LOCALE_DIR', default='locales'),
        DEFAULT_LOCALE=config('DEFAULT_LOCALE', default='es'),
    )
    """Locale configuration."""

    prediction = PredictionConfig(
        OPR_API_KEY=str(config('OPR_API_KEY', cast=Secret, default='')),
        model=get_most_recent_model('models'),
    )
    """Prediction configuration."""

    templates = Jinja2Templates('templates')
    """Templates."""

    @classmethod
    def get_logger_conf(cls) -> str:
        """Gets the logger configuration.

        Returns
        -------
        str
            Path to the logger configuration file.

        Raises
        ------
        FileNotFoundError
            If the logger configuration file is not found.
        """
        if check_file_exists(
            os.path.join(ROOT_DIR, cls.logger.LOGGER_CONF_FILE)
        ):
            return cls.logger.LOGGER_CONF_FILE

        raise FileNotFoundError(
            f'logger configuration file {cls.logger.LOGGER_CONF_FILE!r} '
            'not found'
        )

    @classmethod
    def get_server_url(cls) -> str:
        """Gets the server URL.

        Returns
        -------
        str
            Server URL.
        """
        return (
            f'{cls.server.HTTP_SCHEMA}://{cls.server.HOST}:{cls.server.PORT}'
        )

    @classmethod
    def url_features_extractor(cls) -> URLFeaturesExtractor:
        """Factory method for the URL features extractor.

        Returns
        -------
        URLFeaturesExtractor
            URL features extractor.
        """
        return URLFeaturesExtractor(cls.prediction.OPR_API_KEY)
