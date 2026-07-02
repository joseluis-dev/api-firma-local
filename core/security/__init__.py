"""Re-exports for security subpackage."""
from .pairing import (  # noqa: F401
    PairingManager,
    PairingRequest,
    PairingToken,
    pairing_manager,
    SCOPE_HEALTH,
    SCOPE_CERT_LIST,
    SCOPE_PDF_SIGN,
    ALL_SCOPES,
)
