from pydantic import Field, field_validator

from core.bases.base_dto import BaseRequestDTO, BaseResponseDTO


class FeaturesDTO(BaseResponseDTO):
    url_length: int = Field(title='URL Length', description='URL length')
    domain_length: int = Field(title='Domain Length', description='Domain length')
    path_depth: int = Field(title='Path Depth', description='Path depth')
    nb_subdomains: int = Field(title='Number of Subdomains', description='Number of subdomains')
    https_in_hostname: int = Field(
        title='HTTPS in Hostname', description='Whether HTTPS is in the hostname'
    )
    shortened_url: int = Field(
        title='Shortened URL', description='Whether the URL is shortened'
    )
    abnormal_subdomain: int = Field(
        title='Abnormal Subdomain', description='Whether the subdomain is abnormal'
    )
    suspicious_tld: int = Field(
        title='Suspicious TLD', description='Whether the TLD is suspicious'
    )
    is_ip: int = Field(title='IP', description='Whether the URL is an IP address')
    is_http: int = Field(title='HTTP', description='Whether the URL is HTTP')
    has_at: int = Field(title='@', description='Whether the URL has @')
    has_dash: int = Field(title='-', description='Whether the URL has -')
    has_double_slash: int = Field(
        title='Double Slash', description='Whether the URL has double slash'
    )
    nb_equals: int = Field(title='=', description='Number of =')
    nb_question_mark: int = Field(title='?', description='Number of ?')
    unregistered_domain: int = Field(
        title='Unregistered Domain', description='Whether the domain is unregistered'
    )
    domain_age: int = Field(title='Domain Age', description='Domain age')
    domain_end: int = Field(title='Domain End', description='Domain end')
    unavailable_dns_record: int = Field(
        title='Unavailable DNS Record', description='Whether the DNS record is unavailable'
    )
    page_rank: int = Field(title='PageRank', description='Google PageRank')
    nb_redirects: int = Field(title='Number of Redirects', description='Number of redirects')
    nb_external_redirects: int = Field(
        title='Number of External Redirects', description='Number of external redirects'
    )
    domain_not_in_title: int = Field(
        title='Domain Not in Title', description='Whether the domain is not in the title'
    )
    domain_without_copyright: int = Field(
        title='Domain Without Copyright', description='Whether the domain is not in the copyright'
    )


class PredictionRequestDTO(BaseRequestDTO):
    url: str = Field(title='URL', description='URL to predict')

    @field_validator('url')
    def url_lower(cls, v: str):
        if not v.startswith('http'):
            raise ValueError('URL must start with http or https')
        return v


class PredictionResponseDTO(BaseResponseDTO):
    url: str = Field(title='URL', description='Predicted URL')
    phishing: bool = Field(
        title='Phishing', description='Whether the URL is phishing'
    )
    features: FeaturesDTO = Field(
        title='Features', description='Extracted features'
    )
