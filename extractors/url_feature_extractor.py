import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import ParseResult, urlparse

import dns.resolver
import httpx
import tldextract
from strenum import StrEnum
from tldextract.tldextract import ExtractResult
from whois import whois
from whois.parser import WhoisEntry

_SHORTENING_SERVICES_REGEX = (
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

_SUSPICIOUS_TLD = (
    'accountant',
    'accountants',
    'adult',
    'ae',
    'am',
    'asia',
    'audio',
    'autos',
    'bar',
    'bd',
    'best',
    'bet',
    'bid',
    'bio',
    'bj',
    'blue',
    'buzz',
    'cam',
    'casa',
    'casino',
    'cc',
    'cd',
    'ce.ke',
    'cf',
    'cfd',
    'charity',
    'christmas',
    'click',
    'club',
    'cm',
    'cn',
    'country',
    'cricket',
    'cyou',
    'dad',
    'date',
    'degree',
    'download',
    'earth',
    'email',
    'exposed',
    'faith',
    'fit',
    'fund',
    'futbol',
    'fyi',
    'ga',
    'gdn',
    'ge',
    'gives',
    'go.id',
    'gob.pe',
    'gold',
    'gov.az',
    'gp',
    'gq',
    'guru',
    'haus',
    'help',
    'homes',
    'icu',
    'id',
    'il',
    'in',
    'info',
    'ink',
    'jetzt',
    'k12.pa.us',
    'ke',
    'kim',
    'la',
    'lat',
    'life',
    'link',
    'live',
    'lk',
    'loan',
    'lol',
    'ltd',
    'makeup',
    'me',
    'media',
    'men',
    'ml',
    'mom',
    'monster',
    'mov',
    'mx',
    'ng',
    'ninja',
    'online',
    'or.kr',
    'party',
    'pe',
    'pics',
    'pk',
    'plus',
    'poker',
    'porn',
    'pro',
    'pub',
    'pw',
    'py',
    'quest',
    'racing',
    'realtor',
    'ren',
    'rest',
    'review',
    'rip',
    'rocks',
    'rodeo',
    'rs',
    'ru',
    'run',
    'sa',
    'sa.gov.au',
    'sbs',
    'science',
    'sex',
    'sexy',
    'shop',
    'site',
    'skin',
    'space',
    'stream',
    'su',
    'support',
    'th',
    'tk',
    'tn',
    'tokyo',
    'top',
    'trade',
    'tube',
    'uno',
    'vip',
    'wang',
    'webcam',
    'website',
    'wiki',
    'win',
    'work',
    'world',
    'ws',
    'wtf',
    'xin',
    'xn--*',
    'xn--2scrj9c',
    'xn--5tzm5g',
    'xn--6frz82g',
    'xn--czrs0t',
    'xn--fjq720a',
    'xn--s9brj9c',
    'xn--unup4y',
    'xn--vhquv',
    'xn--xhq521b',
    'xxx',
    'xyz',
    'zip',
    'zone',
    'zw',
)
"""Suspicious TLDs."""

_ABNORMAL_SUBDOMAIN_REGEX = r'^(?:w{2}[^w])|(?:w{3}[^.])|(?:w{4})|(?:\d)'
"""Regex to find abnormal subdomains."""

_PAGE_TITLE_REGEX = r'<title>([^<]+)</title>'
"""Regex to find the title of a page."""

_COPYRIGHT_REGEX = (
    u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})'
)
"""Regex to find the copyright logo."""


@dataclass
class WhoisTimestamps:
    creation_date: datetime | None
    expiration_date: datetime | None


class URLFeature(StrEnum):

    # URL based feature names
    URL_LENGTH = 'url_length'
    DOMAIN_LENGTH = 'domain_length'
    PATH_DEPTH = 'path_depth'
    NB_SUBDOMAINS = 'nb_subdomains'
    HTTPS_IN_HOSTNAME = 'https_in_hostname'
    SHORTENED_URL = 'shortened_url'
    ABNORMAL_SUBDOMAIN = 'abnormal_subdomain'
    SUSPICIOUS_TLD = 'suspicious_tld'
    IS_IP = 'is_ip'
    IS_HTTP = 'is_http'
    HAS_AT = 'has_at'
    HAS_DASH = 'has_dash'
    HAS_DOUBLE_SLASH = 'has_double_slash'
    NB_EQUALS = 'nb_equals'
    NB_QUESTION_MARK = 'nb_question_mark'

    # Domain based feature names
    UNREGISTERED_DOMAIN = 'unregistered_domain'
    DOMAIN_AGE = 'domain_age'
    DOMAIN_END = 'domain_end'
    UNAVAILABLE_DNS_RECORD = 'unavailable_dns_record'
    PAGE_RANK = 'page_rank'

    # Content based feature names
    NB_REDIRECTS = 'nb_redirects'
    NB_EXTERNAL_REDIRECTS = 'nb_external_redirects'
    DOMAIN_NOT_IN_TITLE = 'domain_not_in_title'
    DOMAIN_WITHOUT_COPYRIGHT = 'domain_without_copyright'


class ParsedURL:
    """Parses and extracts information from a URL."""

    url: str
    """The URL itself."""

    parsed_url: ParseResult
    """Parsed URL with ``urllib.parse.urlparse()``."""

    extracted_url: ExtractResult
    """Extracted URL with ``tldextract.extract()``."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.parsed_url = urlparse(url)
        self.extracted_url = tldextract.extract(url)

    @property
    def scheme(self) -> str:
        """Scheme of the URL, e.g. ``http``."""
        return self.parsed_url.scheme or ''

    @property
    def hostname(self) -> str:
        """Hostname of the URL, e.g. ``www.google.com``."""
        return self.parsed_url.hostname or ''

    @property
    def path(self) -> str:
        """Path of the URL, e.g. ``/search?q=python``."""
        return self.parsed_url.path or ''

    @property
    def domain(self) -> str:
        """Domain of the URL, e.g. ``google``."""
        return self.extracted_url.domain

    @property
    def subdomain(self) -> str:
        """Subdomain of the URL, e.g. ``www``."""
        return self.extracted_url.subdomain

    @property
    def suffix(self) -> str:
        """Suffix of the URL, e.g. ``com``."""
        return self.extracted_url.suffix

    @property
    def registered_domain(self) -> str:
        """Registered domain of the URL, e.g. ``google.com``."""
        return self.extracted_url.registered_domain

    @property
    def ipv4(self) -> str:
        """IPv4 if that is what the domain part of the URL is."""
        return self.extracted_url.ipv4

    @property
    def ipv6(self) -> str:
        """IPv6 if that is what the domain part of the URL is."""
        return self.extracted_url.ipv6

    @property
    def is_ip(self) -> bool:
        """Whether the domain part of the URL is an IP address."""
        return self.ipv4 != '' or self.ipv6 != ''


class IURLFeaturesExtractor(ABC):
    """URL features extractor interface."""

    @abstractmethod
    def extract(self, url: str) -> dict[str, int]:
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
        ...


class URLFeaturesExtractor(IURLFeaturesExtractor):
    """Extracts features from a URL."""

    def __init__(self, opr_api_key: str) -> None:
        self.__OPR_API_KEY = opr_api_key

    def extract(self, url: str) -> dict[str, int]:
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
        try:
            response = httpx.get(url, verify=False)
        except httpx.ReadTimeout:
            raise TimeoutError(f'Timeout error for {url!r}')

        parsed_url = ParsedURL(url)
        address_bar_features = self.extract_url_based_features(parsed_url)
        domain_based_features = self.extract_domain_based_features(parsed_url)
        content_based_features = self.extract_content_based_features(
            parsed_url, response
        )
        return {
            **address_bar_features,
            **domain_based_features,
            **content_based_features,
        }

    def extract_url_based_features(
        self, parsed_url: ParsedURL
    ) -> dict[str, int]:
        """Extracts features from the URL itself.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        dict[str, int]
            Extracted features.
        """
        return {
            str(URLFeature.URL_LENGTH): self.url_length(parsed_url.url),
            str(URLFeature.DOMAIN_LENGTH): self.domain_length(parsed_url),
            str(URLFeature.PATH_DEPTH): self.path_depth(parsed_url),
            str(URLFeature.NB_SUBDOMAINS): self.count_subdomains(parsed_url),
            str(URLFeature.HTTPS_IN_HOSTNAME): self.https_in_hostname(
                parsed_url
            ),
            str(URLFeature.SHORTENED_URL): self.shortened_url(parsed_url.url),
            str(URLFeature.ABNORMAL_SUBDOMAIN): self.abnormal_subdomain(
                parsed_url
            ),
            str(URLFeature.SUSPICIOUS_TLD): self.suspicious_tld(parsed_url),
            str(URLFeature.IS_IP): self.is_ip(parsed_url),
            str(URLFeature.IS_HTTP): self.is_http(parsed_url),
            str(URLFeature.HAS_AT): self.has_at(parsed_url),
            str(URLFeature.HAS_DASH): self.has_dash(parsed_url),
            str(URLFeature.HAS_DOUBLE_SLASH): self.has_double_slash(
                parsed_url.url
            ),
            str(URLFeature.NB_EQUALS): self.count_equals(parsed_url),
            str(URLFeature.NB_QUESTION_MARK): self.count_question_mark(
                parsed_url
            ),
        }

    def extract_domain_based_features(
        self, parsed_url: ParsedURL
    ) -> dict[str, int]:
        """Extracts features from the domain part of the URL.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        dict[str, int]
            Extracted features.
        """
        whois_data = self.get_whois_data(parsed_url)
        whois_timestamps = (
            self.extract_whois_timestamps(whois_data)
            if whois_data
            else WhoisTimestamps(None, None)
        )
        unavailable_dns_record = 0 if self.get_dns_record(parsed_url) else 1
        page_rank = self.get_page_rank(parsed_url)

        unregistered_domain = 0
        if not whois_data:
            unregistered_domain = 1

        return {
            str(URLFeature.UNREGISTERED_DOMAIN): unregistered_domain,
            str(URLFeature.DOMAIN_AGE): (
                self.get_domain_age(whois_timestamps.creation_date)
                if whois_timestamps.creation_date
                else 0
            ),
            str(URLFeature.DOMAIN_END): (
                self.get_domain_end(whois_timestamps.expiration_date)
                if whois_timestamps.expiration_date
                else 0
            ),
            str(URLFeature.UNAVAILABLE_DNS_RECORD): unavailable_dns_record,
            str(URLFeature.PAGE_RANK): page_rank,
        }

    def extract_content_based_features(
        self, parsed_url: ParsedURL, response: httpx.Response
    ) -> dict[str, int]:
        """Extracts features from the content of the page.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.
        response : httpx.Response
            Response of the request to the website.

        Returns
        -------
        dict[str, int]
            Extracted features.
        """
        return {
            str(URLFeature.NB_REDIRECTS): self.count_redirects(response),
            str(
                URLFeature.NB_EXTERNAL_REDIRECTS
            ): self.count_external_redirects(response, parsed_url),
            str(URLFeature.DOMAIN_NOT_IN_TITLE): self.domain_not_in_title(
                parsed_url, response
            ),
            str(
                URLFeature.DOMAIN_WITHOUT_COPYRIGHT
            ): self.domain_without_copyright(parsed_url, response),
        }

    def extract_whois_timestamps(
        self, dns_record: WhoisEntry
    ) -> WhoisTimestamps:
        """Extracts WHOIS creation and expiration dates.

        If the creation and expiration dates are lists, the first
        element is taken.

        Parameters
        ----------
        dns_record : WhoisEntry
            DNS record.

        Returns
        -------
        WhoisTimestamps
            Creation and expiration dates.
        """
        creation_date = dns_record.creation_date
        expiration_date = dns_record.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        return WhoisTimestamps(creation_date, expiration_date)

    def get_whois_data(self, parsed_url: ParsedURL) -> WhoisEntry | None:
        """Extracts WHOIS data.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        WhoisEntry | None
            WHOIS data if available.
        """
        try:
            return whois(parsed_url.registered_domain)
        except Exception:
            return None

    def url_length(self, url: str) -> int:
        """Computes the length of the URL.

        Parameters
        ----------
        url : str
            URL.

        Returns
        -------
        int
            Length of the URL.
        """
        return len(url)

    def domain_length(self, parsed_url: ParsedURL) -> int:
        """Computes the length of the domain.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Length of the domain.
        """
        return len(parsed_url.domain)

    def path_depth(self, parsed_url: ParsedURL) -> int:
        """Calculates the number of sub pages in the given url path.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Depth of the path of the URL.
        """
        depth = 0
        for sub_page in parsed_url.path.split('/'):
            if sub_page.strip():
                depth += 1

        return depth

    def count_subdomains(self, parsed_url: ParsedURL) -> int:
        """Counts the number of subdomains in the URL.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Number of subdomains.
        """
        return len(parsed_url.subdomain.split('.'))

    def https_in_hostname(self, parsed_url: ParsedURL) -> Literal[1, 0]:
        """Checks for the presence of ``https`` in the hostname.

        The phishers may add the ``https`` token to the hostname in
        order to trick users into believing that they are dealing with
        a secure website.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Has ``https`` in the domain.
            0: Otherwise.
        """
        return 1 if 'https' in parsed_url.hostname else 0

    def shortened_url(self, url: str) -> Literal[1, 0]:
        """Checks if URL is shortened by a URL shortening service.

        URL shortening is one of the most used techniques by the
        phishers to trick users. If a URL is shortened, it could
        be a phishing website.

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
        return (
            1
            if re.search(_SHORTENING_SERVICES_REGEX, url, re.IGNORECASE)
            else 0
        )

    def abnormal_subdomain(self, parsed_url: ParsedURL) -> Literal[1, 0]:
        """Checks for the presence of an abnormal subdomain.

        Abnormal subdomains are those that start with ``ww`` or ``www``
        followed by any character other than ``w`` or dot (``.``)
        respectively.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Has abnormal subdomain.
            0: Otherwise.
        """
        return (
            1
            if re.match(
                _ABNORMAL_SUBDOMAIN_REGEX, parsed_url.subdomain, re.IGNORECASE
            )
            else 0
        )

    def suspicious_tld(self, parsed_url: ParsedURL) -> Literal[1, 0]:
        """Checks if the TLD is suspicious.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: TLD is suspicious.
            0: Otherwise.
        """
        return 1 if parsed_url.suffix in _SUSPICIOUS_TLD else 0

    def is_http(self, parsed_url: ParsedURL) -> Literal[1, 0]:
        """Checks if the URL uses the unsecure ``http`` protocol.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Uses ``http`` protocol.
            0: Otherwise.
        """
        return 1 if parsed_url.scheme == 'http' else 0

    def is_ip(self, parsed_url: ParsedURL) -> Literal[1, 0]:
        """Checks if the hostname is an IP address.

        If a URL uses an IP address instead of domain name,
        it could be a phishing website.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Uses IP address instead of a domain name.
            0: Otherwise.
        """
        return 1 if parsed_url.is_ip else 0

    def has_at(self, parsed_url: ParsedURL) -> Literal[1, 0]:
        """Whether the URL contains at symbol (``@``).

        Using at symbol in the URL leads the browser to ignore
        everything preceding the at symbol and the real address often
        follows the symbol. Some modern browsers block this behavior.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Has ``@`` symbol.
            0: Otherwise.
        """
        return 1 if '@' in parsed_url.url else 0

    def has_dash(self, parsed_url: ParsedURL) -> Literal[1, 0]:
        """Whether the hostname contains dash symbol (``-``).

        If a URL has dash symbol in the hostname, the user might be
        tricked into believing that it is a subdomain of a legitimate
        domain. So, it could be a phishing website.

        .. note::
            The presence of one dash symbol in the hostname is often
            referred to as "prefix suffix".

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        Literal[1, 0]
            1: Has ``-`` symbol.
            0: Otherwise.
        """
        return 1 if '-' in parsed_url.hostname else 0

    def has_double_slash(self, url: str) -> Literal[1, 0]:
        """Whether the URL has double slash (``//``).

        The existence of ``//`` within the URL path means that the user
        will be redirected to another website. The ``//`` should appear
        right after the protocol (up to sixth position), otherwise, it
        could be a phishing website.

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

    def count_equals(self, parsed_url: ParsedURL) -> int:
        """Counts the number of equal (``=``) in the URL.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Number of equal (``=``) in the URL.
        """
        return parsed_url.url.count('=')

    def count_question_mark(self, parsed_url: ParsedURL) -> int:
        """Counts the number of question mark (``?``) in the URL.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Number of question mark (``?``) in the URL.
        """
        return parsed_url.url.count('?')

    def count_redirects(self, response: httpx.Response) -> int:
        """Counts the number of redirects.

        Parameters
        ----------
        response : httpx.Response
            Response of the request to the website.

        Returns
        -------
        int
            Number of redirects.
        """
        return len(response.history)

    def count_external_redirects(
        self, response: httpx.Response, parsed_url: ParsedURL
    ) -> int:
        """Counts the number of external redirects.

        Parameters
        ----------
        response : httpx.Response
            Response of the request to the website.
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Number of external redirects.
        """
        external_redirects = 0
        for redirect in response.history:
            host = redirect.url.raw_host.decode().lower()
            if host.endswith(parsed_url.registered_domain):
                external_redirects += 1

        return external_redirects

    def domain_not_in_title(
        self, parsed_url: ParsedURL, response: httpx.Response
    ) -> Literal[1, 0]:
        """Whether the domain is not present in the title of the page.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.
        html_content : str
            HTML content of the page.

        Returns
        -------
        Literal[1, 0]
            1: Domain is not present in the title of the page.
            0: Otherwise.
        """
        title = self._extract_html_title(response)
        return 0 if parsed_url.domain.lower() in title.lower() else 1

    def domain_without_copyright(
        self, parsed_url: ParsedURL, response: httpx.Response
    ) -> Literal[1, 0]:
        """Whether the domain is not present in the copyright logo.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.
        response : httpx.Response
            Response of the request to the website.

        Returns
        -------
        Literal[1, 0]
            1: Domain is not present in the copyright logo.
            0: Otherwise.
        """
        match = re.search(_COPYRIGHT_REGEX, response.text)
        if not match:
            return 0

        try:
            copyright_ = response.text[
                match.span()[0] - 50 : match.span()[0] + 50
            ]
            return 0 if parsed_url.domain.lower() in copyright_.lower() else 1
        except Exception:
            return 0

    def get_domain_age(self, creation_date: datetime) -> int:
        """Checks for the age of the domain (the difference between
        creation time and current time).

        Parameters
        ----------
        creation_date : datetime
            Creation date of the domain.

        Returns
        -------
        int
            Age of the domain in days.
        """
        return abs((datetime.now() - creation_date).days)

    def get_domain_end(self, expiration_date: datetime) -> int:
        """Checks for the end period of the domain (the difference
        between expiration time and current time).

        Parameters
        ----------
        expiration_date : datetime
            Expiration date of the domain.

        Returns
        -------
        int
            End period of the domain in days.
        """
        return abs((expiration_date - datetime.now()).days)

    def get_dns_record(
        self, parsed_url: ParsedURL
    ) -> dns.resolver.Answer | None:
        """Extracts DNS record.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        dns.resolver.Answer | None
            DNS record if available.
        """
        try:
            return dns.resolver.resolve(parsed_url.registered_domain, 'NS')
        except Exception:
            return None

    def get_page_rank(self, parsed_url: ParsedURL) -> int:
        """Extracts Google PageRank.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Google PageRank.
        """
        result = self._get_page_rank_option_1(parsed_url)
        if result == -1:
            result = self._get_page_rank_option_2(parsed_url)

        return result if result != -1 else 0

    def _get_page_rank_option_1(self, parsed_url: ParsedURL) -> int:
        """Gets Google PageRank from Open PageRank API.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Google PageRank.
        """
        if not self.__OPR_API_KEY:
            return -1

        try:
            response = httpx.get(
                'https://openpagerank.com/api/v1.0/getPageRank',
                params={'domains[0]': parsed_url.registered_domain},
                headers={'API-OPR': self.__OPR_API_KEY},
            )
            response.raise_for_status()

            return response.json()['response'][0]['page_rank_integer']
        except (httpx.HTTPError, KeyError, IndexError):
            return -1

    def _get_page_rank_option_2(self, parsed_url: ParsedURL) -> int:
        """Gets Google PageRank from checkpagerank.net.

        Parameters
        ----------
        parsed_url : ParsedURL
            Parsed URL.

        Returns
        -------
        int
            Google PageRank.
        """
        try:
            response = httpx.post(
                'https://www.checkpagerank.net/index.php',
                data={'name': parsed_url.registered_domain},
            )
            response.raise_for_status()

            pattern = r'Google PageRank: <span[^>]*>(\d+)/10</span>'
            match = re.search(pattern, response.text)
            return int(match.group(1)) if match else 0
        except (httpx.HTTPError, ValueError):
            return -1

    def _extract_html_title(self, response: httpx.Response) -> str:
        """Extracts the title of the page.

        Parameters
        ----------
        response : httpx.Response
            Response of the request to the website.

        Returns
        -------
        str
            Title of the page.
        """
        match = re.search(_PAGE_TITLE_REGEX, response.text, re.IGNORECASE)
        return match.group(1) if match else ''
