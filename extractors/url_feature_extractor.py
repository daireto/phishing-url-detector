import math
import re
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Literal
from urllib.parse import ParseResult, urlparse

from requests import Response, get
from whois import whois
from whois.parser import WhoisEntry

from core.bases.base_feature_extractor import BaseFeatureExtractor
from utils.enums import StrEnum, auto

_MAX_SAFE_URL_LENGTH = 54
"""Max length of a safe (legitimate) URL."""

_SHORTENING_SERVICES = (
    r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|'
    r'is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|'
    r'su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|'
    r'Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|'
    r'kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|'
    r'adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|'
    r'twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
    r'prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|'
    r'1url\.com|tweez\.me|v\.gd|link\.zip\.net|rebrandly\.com|t2m\.io|bl\.ink|'
    r'shrtco\.de|cutt\.ly|shorte\.link|rb\.gy|soo\.gd|v\.ht|l9\.nu|gg\.gg|'
    r'tny\.im|clck\.ru'
)
"""Shortening service domains."""

_INVISIBLE_IFRAME_REGEX = r'<iframe.*frameBorder.*>'
"""Regex to find invisible iframes."""

_ON_MOUSE_OVER_EVENT_REGEX = (
    r'addEventListener\s*\(\s*[\'"]mouseover[\'"]|onmouseover'
)
"""Regex to find the JavaScript ``onMouseOver`` event."""

_DISABLED_RIGHT_CLICK_REGEX = (
    r'addEventListener\s*\(\s*[\'"]contextmenu[\'"]|oncontextmenu'
)
"""Regex to check if right click is disabled
using the JavaScript ``onContextMenu`` event.
"""

_AVERAGE_MONTH_LENGTH = 30.417
"""Average length of a month in days."""

_RESPONSE_TIMEOUT = (3.05, 5)
"""Timeout for requests to the website."""


@dataclass
class DNSTimestamps:
    creation_date: datetime
    expiration_date: datetime


class URLFeature(StrEnum):

    # Address bar based feature names
    HAS_IP = auto()
    HAS_AT_SYMBOL = auto()
    LONG_URL = auto()
    URL_DEPTH = auto()
    HAS_REDIRECTION = auto()
    HTTPS_IN_DOMAIN = auto()
    SHORT_URL = auto()
    DASH_IN_DOMAIN = auto()

    # Domain based feature names
    NO_DNS_RECORD = auto()
    DOMAIN_AGE_IN_MONTHS = auto()
    DOMAIN_END_IN_MONTHS = auto()

    # Content based feature names
    RESPONSE_STATUS = auto()
    INVISIBLE_IFRAME = auto()
    HAS_MOUSE_OVER = auto()
    DISABLED_RIGHT_CLICK = auto()
    MANY_REDIRECTS = auto()


class URLFeaturesExtractor(BaseFeatureExtractor):
    """Extracts features from a URL."""

    @classmethod
    def extract(cls, url: str) -> dict[str, int]:
        """Extracts features from a URL.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        dict[str, int]
            Extracted features.
        """
        parsed_url = urlparse(url)
        address_bar_features = cls.extract_address_bar_based_features(
            url, parsed_url
        )
        domain_based_features = cls.extract_domain_based_features(parsed_url)
        content_based_features = cls.extract_content_based_features(url)
        return {
            **address_bar_features,
            **domain_based_features,
            **content_based_features,
        }

    @classmethod
    def extract_address_bar_based_features(
        cls, url: str, parsed_url: ParseResult
    ) -> dict[str, int]:
        """Extracts features from
        the address bar of the URL.

        Parameters
        ----------
        url : str
            URL.
        parsed_url : ParseResult
            Parsed URL.

        Returns
        -------
        dict[str, int]
            Extracted features.
        """
        return {
            URLFeature.HAS_IP: cls.has_ip(parsed_url),
            URLFeature.HAS_AT_SYMBOL: cls.has_at_symbol(url),
            URLFeature.LONG_URL: cls.long_url(url),
            URLFeature.URL_DEPTH: cls.get_depth(parsed_url),
            URLFeature.HAS_REDIRECTION: cls.has_redirection(url),
            URLFeature.HTTPS_IN_DOMAIN: cls.https_in_domain(parsed_url),
            URLFeature.SHORT_URL: cls.short_url(url),
            URLFeature.DASH_IN_DOMAIN: cls.dash_in_domain(parsed_url),
        }

    @classmethod
    def extract_domain_based_features(
        cls, parsed_url: ParseResult
    ) -> dict[str, int]:
        """Extracts features from
        the domain part of the URL.

        Parameters
        ----------
        parsed_url : ParseResult
            Parsed URL.

        Returns
        -------
        dict[str, int]
            Extracted features.
        """
        dns_record = cls.get_dns_record(parsed_url)
        if not dns_record:
            return {
                URLFeature.NO_DNS_RECORD: 1,
                URLFeature.DOMAIN_AGE_IN_MONTHS: 0,
                URLFeature.DOMAIN_END_IN_MONTHS: 0,
            }
        dns_timestamps = cls.extract_dns_timestamps(dns_record)
        if not dns_timestamps:
            return {
                URLFeature.NO_DNS_RECORD: 0,
                URLFeature.DOMAIN_AGE_IN_MONTHS: 0,
                URLFeature.DOMAIN_END_IN_MONTHS: 0,
            }
        return {
            URLFeature.NO_DNS_RECORD: 0,
            URLFeature.DOMAIN_AGE_IN_MONTHS: cls.get_domain_age(
                dns_timestamps
            ),
            URLFeature.DOMAIN_END_IN_MONTHS: cls.get_domain_end(
                dns_timestamps.expiration_date
            ),
        }

    @classmethod
    def extract_content_based_features(cls, url: str) -> dict[str, int]:
        """Extracts features from
        the content of the page.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        dict[str, int]
            Extracted features.
        """
        response = cls.fetch_url(url)
        if response is None:
            return {
                URLFeature.RESPONSE_STATUS: 0,
                URLFeature.INVISIBLE_IFRAME: 1,
                URLFeature.HAS_MOUSE_OVER: 1,
                URLFeature.DISABLED_RIGHT_CLICK: 1,
                URLFeature.MANY_REDIRECTS: 0,
            }
        return {
            URLFeature.RESPONSE_STATUS: response.status_code,
            URLFeature.INVISIBLE_IFRAME: cls.has_invisible_iframe(
                response.text
            ),
            URLFeature.HAS_MOUSE_OVER: cls.has_mouse_over(response.text),
            URLFeature.DISABLED_RIGHT_CLICK: cls.disabled_right_click(
                response.text
            ),
            URLFeature.MANY_REDIRECTS: cls.has_many_redirects(
                response.history
            ),
        }

    @classmethod
    def get_dns_record(cls, parsed_url: ParseResult) -> WhoisEntry | None:
        """Gets the DNS record of the
        domain part of the URL.

        Parameters
        ----------
        parsed_url : ParseResult
            Parsed URL.

        Returns
        -------
        WhoisEntry | None
            DNS record if found.
        """
        try:
            return whois(parsed_url.netloc)
        except Exception:
            return None

    @classmethod
    def extract_dns_timestamps(
        cls, dns_record: WhoisEntry
    ) -> DNSTimestamps | None:
        """Extracts DNS record creation and expiration dates.

        Parameters
        ----------
        dns_record : WhoisEntry
            DNS record.

        Returns
        -------
        DNSTimestamps | None
            Creation and expiration dates.
        """
        creation_date = dns_record.creation_date
        expiration_date = dns_record.expiration_date
        if not creation_date or not expiration_date:
            return None
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return DNSTimestamps(creation_date, expiration_date)

    @classmethod
    def fetch_url(cls, url: str) -> Response | None:
        """Fetches the content of the URL.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        Response | None
            Content of the URL.
        """
        try:
            return get(url, verify=False, timeout=_RESPONSE_TIMEOUT)
        except Exception:
            return None

    @classmethod
    def has_ip(cls, parsed_url: ParseResult) -> Literal[1, 0]:
        """Checks for the presence of IP address in
        the domain part of the URL.

        If a URL uses an IP address instead of domain name,
        it could be a phishing website.

        Parameters
        ----------
        parsed_url : ParseResult
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Uses IP address instead of a domain name.
            0: Otherwise.
        """
        try:
            ip_address(parsed_url.netloc)
            return 1
        except Exception:
            return 0

    @classmethod
    def has_at_symbol(cls, url: str) -> Literal[1, 0]:
        """Checks for the presence of ``@`` symbol in the URL.

        Using ``@`` symbol in the URL leads the browser to ignore
        everything preceding the symbol and the real address
        often follows the symbol. If a URL contains this symbol,
        it could be a phishing website.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        Literal[1, 0]
            1: Has ``@`` symbol.
            0: Otherwise.
        """
        return 1 if '@' in url else 0

    @classmethod
    def long_url(cls, url: str) -> Literal[1, 0]:
        """Computes the length of the URL.

        Phishers can use long URL to hide the doubtful part in
        the address bar. If the length of the URL is greater than
        or equal 54 characters then the URL classified as phishing.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        Literal[1, 0]
            1: URL is too long (more than 54 characters).
            0: Otherwise.
        """
        return 1 if len(url) >= _MAX_SAFE_URL_LENGTH else 0

    @classmethod
    def get_depth(cls, parsed_url: ParseResult) -> int:
        """Calculates the number of sub pages
        in the given url based on the ``/``.

        Parameters
        ----------
        parsed_url : ParseResult
            Parsed URL.

        Returns
        -------
        int
            Depth of the URL.
        """
        sub_pages = parsed_url.path.split('/')
        depth = 0
        for sub_page in sub_pages:
            if len(sub_page) != 0:
                depth += 1
        return depth

    @classmethod
    def has_redirection(cls, url: str) -> Literal[1, 0]:
        """Checks the presence and position of ``//`` in the URL.

        The existence of ``//`` within the URL path means that
        the user will be redirected to another website.
        The ``//`` should appear right after the protocol (up to
        sixth position), otherwise. it could be a phishing website.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        Literal[1, 0]
            1: Has ``//`` anywhere apart from right after the protocol.
            0: Otherwise.
        """
        position = url.rfind('//')
        return 1 if position > 6 else 0

    @classmethod
    def https_in_domain(cls, parsed_url: ParseResult) -> Literal[1, 0]:
        """Checks for the presence of ``https``
        in the domain part of the URL.

        The phishers may add the ``https`` token to
        the domain part of a URL in order to trick users.

        Parameters
        ----------
        parsed_url : ParseResult
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Has ``https`` in the domain.
            0: Otherwise.
        """
        return 1 if 'https' in parsed_url.netloc.lower() else 0

    @classmethod
    def short_url(cls, url: str) -> Literal[1, 0]:
        """Checks if URL is shortened.

        URL shortening is one of the most used techniques
        by the phishers to trick users. If a URL is shortened,
        it could be a phishing website.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        Literal[1, 0]
            1: URL is shortened.
            0: Otherwise.
        """
        return 1 if re.search(_SHORTENING_SERVICES, url, re.IGNORECASE) else 0

    @classmethod
    def dash_in_domain(cls, parsed_url: ParseResult) -> Literal[1, 0]:
        """Checks for the presence of ``-`` in the domain part of URL.

        The dash symbol is rarely used in legitimate URLs.
        Phishers tend to add prefixes or suffixes separated by ``-``
        to the domain name so that users feel that they are dealing
        with a legitimate webpage.

        Parameters
        ----------
        parsed_url : ParseResult
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Has ``-`` in the domain.
            0: Otherwise.
        """
        return 1 if '-' in parsed_url.netloc else 0

    @classmethod
    def has_invisible_iframe(cls, response_text: str) -> Literal[1, 0]:
        """Checks for the presence of invisible iframes.

        Phishers can make use of the ``iframe`` HTML tag and make it
        invisible, i.e., without frame borders. In this regard,
        phishers make use of the ``frameBorder`` attribute which causes
        the browser to render a visual delineation.

        Parameters
        ----------
        response_text : str
            Response of the request to the website.

        Returns
        -------
        Literal[1, 0]
            1: Has invisible iframe.
            0: Otherwise.
        """
        if not response_text:
            return 1
        if re.search(_INVISIBLE_IFRAME_REGEX, response_text, re.IGNORECASE):
            return 1
        return 0

    @classmethod
    def has_mouse_over(cls, response_text: str) -> Literal[1, 0]:
        """Check for the presence of the ``onMouseOver`` event.

        Phishers may use the JavaScript ``onMouseOver`` event
        to show a fake URL in the status bar to users.

        Parameters
        ----------
        response_text : str
            Response of the request to the website.

        Returns
        -------
        Literal[1, 0]
            1: Uses the ``onMouseOver`` event.
            0: Otherwise.
        """
        if not response_text:
            return 1
        if re.search(_ON_MOUSE_OVER_EVENT_REGEX, response_text, re.IGNORECASE):
            return 1
        return 0

    @classmethod
    def disabled_right_click(cls, response_text: str) -> Literal[1, 0]:
        """Checks the status of the right click attribute.

        Phishers use JavaScript to disable the right-click function,
        so that users cannot view and save the webpage source code.

        Search for a statement like ``event.button == 2`` is a way to
        check if the right click is disabled.

        Parameters
        ----------
        response_text : str
            Response of the request to the website.

        Returns
        -------
        Literal[1, 0]
            1: Right click is disabled.
            0: Otherwise.
        """
        if not response_text:
            return 1
        if re.search(
            _DISABLED_RIGHT_CLICK_REGEX, response_text, re.IGNORECASE
        ):
            return 1
        return 0

    @classmethod
    def has_many_redirects(cls, history: list[Response]) -> Literal[1, 0]:
        """Checks if the response has more than 2 redirects.

        Legitimate websites use to have two redirects max.
        On the other hand, phishing websites use to have
        at least 4 redirects.

        Parameters
        ----------
        history : list[Response]
            Response history.

        Returns
        -------
        Literal[1, 0]
            1: Has more than 2 redirects.
            0: Otherwise.
        """
        return 1 if len(history) > 2 else 0

    @classmethod
    def get_domain_age(cls, dns_timestamps: DNSTimestamps) -> int:
        """Checks for the age of the domain
        (the difference between expiration time
        and creation time).

        Parameters
        ----------
        dns_timestamps : DNSTimestamps
            Creation and expiration dates.

        Returns
        -------
        int
            Age of the domain in months.
        """
        age = dns_timestamps.expiration_date - dns_timestamps.creation_date
        age_in_months = age.days / _AVERAGE_MONTH_LENGTH
        return math.ceil(age_in_months)

    @classmethod
    def get_domain_end(cls, expiration_date: datetime) -> int:
        """Checks for the end period of the domain
        (the difference between expiration time
        and current time).

        Parameters
        ----------
        expiration_date : datetime
            Expiration date of the domain.

        Returns
        -------
        int
            End period of the domain in months.
        """
        today = datetime.today()
        end_time = expiration_date - today
        end_time_in_months = end_time.days / _AVERAGE_MONTH_LENGTH
        return math.ceil(end_time_in_months)
