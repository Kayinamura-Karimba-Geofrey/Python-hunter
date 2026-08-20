"""Built-in Secret Detectors Package."""

from python_hunter.detectors.secrets.pyh_secret_001_generic_api_key import PYHSecret001GenericAPIKey
from python_hunter.detectors.secrets.pyh_secret_002_generic_access_token import PYHSecret002GenericAccessToken
from python_hunter.detectors.secrets.pyh_secret_003_private_key import PYHSecret003PrivateKey
from python_hunter.detectors.secrets.pyh_secret_004_jwt import PYHSecret004JWT
from python_hunter.detectors.secrets.pyh_secret_005_database_url import PYHSecret005DatabaseURL
from python_hunter.detectors.secrets.pyh_secret_006_aws_credentials import PYHSecret006AWSCredentials
from python_hunter.detectors.secrets.pyh_secret_007_github_token import PYHSecret007GitHubToken
from python_hunter.detectors.secrets.pyh_secret_008_generic_password import PYHSecret008GenericPassword
from python_hunter.detectors.secrets.pyh_secret_009_dotenv import PYHSecret009Dotenv
from python_hunter.detectors.secrets.pyh_secret_010_high_entropy import PYHSecret010HighEntropy
from python_hunter.detectors.secrets.pyh_secret_011_gcp_api_key import PYHSecret011GCPAPIKey
from python_hunter.detectors.secrets.pyh_secret_012_slack_webhook import PYHSecret012SlackWebhook
from python_hunter.detectors.secrets.pyh_secret_013_stripe_key import PYHSecret013StripeKey
from python_hunter.detectors.secrets.pyh_secret_014_private_key_pem import PYHSecret014PrivateKeyPEM
from python_hunter.detectors.secrets.pyh_secret_015_db_connection_url import PYHSecret015DatabaseConnectionURL
from python_hunter.domain.secrets.registry import SecretDetectorRegistry


def create_default_secret_registry() -> SecretDetectorRegistry:
    """Instantiate and register all default built-in secret detectors in priority order."""
    registry = SecretDetectorRegistry()
    registry.register(PYHSecret006AWSCredentials())
    registry.register(PYHSecret007GitHubToken())
    registry.register(PYHSecret011GCPAPIKey())
    registry.register(PYHSecret012SlackWebhook())
    registry.register(PYHSecret013StripeKey())
    registry.register(PYHSecret014PrivateKeyPEM())
    registry.register(PYHSecret015DatabaseConnectionURL())
    registry.register(PYHSecret003PrivateKey())
    registry.register(PYHSecret004JWT())
    registry.register(PYHSecret005DatabaseURL())
    registry.register(PYHSecret009Dotenv())
    registry.register(PYHSecret001GenericAPIKey())
    registry.register(PYHSecret002GenericAccessToken())
    registry.register(PYHSecret008GenericPassword())
    registry.register(PYHSecret010HighEntropy())
    return registry


__all__ = [
    "PYHSecret001GenericAPIKey",
    "PYHSecret002GenericAccessToken",
    "PYHSecret003PrivateKey",
    "PYHSecret004JWT",
    "PYHSecret005DatabaseURL",
    "PYHSecret006AWSCredentials",
    "PYHSecret007GitHubToken",
    "PYHSecret008GenericPassword",
    "PYHSecret009Dotenv",
    "PYHSecret010HighEntropy",
    "PYHSecret011GCPAPIKey",
    "PYHSecret012SlackWebhook",
    "PYHSecret013StripeKey",
    "PYHSecret014PrivateKeyPEM",
    "PYHSecret015DatabaseConnectionURL",
    "create_default_secret_registry",
]
