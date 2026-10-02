"""HTTP contract checks using the existing browser payloads and security headers."""
import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from localapi.api import routes
from localapi.core.config_store import UserConfig, config_store
from localapi.core.errors import PinInvalidError, TimeoutError_, UserCancelledError
from localapi.core.schemas import CertificateInfo, CertificadosResponse, FirmarPdfResponse
from localapi.core.security import deps
from localapi.core.security import pairing as pairing_module
from localapi.core.security.pairing import PairingManager, PairingToken, SCOPE_CERT_LIST, SCOPE_PDF_SIGN


ORIGIN = "http://localhost:5173"
PDF_BASE64 = "JVBERi0xLjQK"
PDF_HASH = "a" * 64


def headers(bearer):
    return {
        "Origin": ORIGIN,
        "Authorization": f"Bearer {bearer}",
        "X-LocalAPI-Timestamp": str(int(time.time())),
        "X-LocalAPI-Request-Id": str(uuid4()),
    }


def signing_payload(placement):
    return {
        "documentoBase64": PDF_BASE64,
        "documentoSha256": PDF_HASH,
        "certificadoId": "Signing Certificate",
        "expectedCedula": "1234567890",
        "metadataBase64": "e30=",
        "pinMode": "LOCAL_PROMPT",
        "firma": {"razon": "Approved", "tipoEstampado": "QR", **placement},
    }


@pytest.fixture
def frontend_client(monkeypatch, tmp_path):
    from localapi import app as app_module

    monkeypatch.setattr(config_store, "_data", UserConfig(dev_mode=True))
    pairing = PairingManager(path=tmp_path / "pairing.json")
    pending = pairing.request_pairing(ORIGIN, [SCOPE_CERT_LIST, SCOPE_PDF_SIGN])
    bearer = pairing.approve_request(pending.request_id).token
    monkeypatch.setattr(deps, "pairing_manager", pairing)
    monkeypatch.setattr(routes, "pairing_manager", pairing)
    monkeypatch.setattr(app_module, "pairing_manager", pairing)
    monkeypatch.setattr(deps, "_known_nonces", {})
    monkeypatch.setattr(routes, "ask_signature_confirmation", lambda **kwargs: True)
    now = datetime.now(timezone.utc)

    class Service:
        last_signature_request = None
        failure = None

        def list_certificates(self, **kwargs):
            return CertificadosResponse(certificados=[CertificateInfo(
                id="Signing Certificate", cedula="1234567890", subject="CN=Test Signer",
                issuer="CN=Test CA", serial="01", validFrom=now, validTo=now,
                provider="PKCS11", tokenLabel="Test Token", displayName="Test Signer",
                shortName="Test Signer", type="SIGNING", isCa=False,
                hasPrivateKey=True, signable=True,
            )])

        def sign_pdf(self, **kwargs):
            self.last_signature_request = kwargs
            if self.failure:
                raise self.failure
            return FirmarPdfResponse(
                documentoFirmadoBase64=PDF_BASE64, documentoOriginalSha256=PDF_HASH,
                certificado={
                    "cedula": "1234567890", "serial": "01", "subject": "CN=Test Signer",
                    "issuer": "CN=Test CA", "validFrom": now, "validTo": now,
                },
                firmaLocal={"provider": "PKCS11", "driver": "PKCS11", "algorithm": "SHA512withTOKEN", "signedAt": now},
            )

    service = Service()
    monkeypatch.setattr(routes, "token_service", service)

    async def loopback(scope, receive, send):
        if scope.get("type") == "http":
            scope = {**scope, "client": ("127.0.0.1", 50000)}
        await app_module.app(scope, receive, send)

    with TestClient(loopback, base_url="http://127.0.0.1:44113", raise_server_exceptions=False) as client:
        yield client, bearer, service


@pytest.mark.parametrize("placement", [
    {"pagina": "1", "llx": "120", "lly": "180", "ancho": "200", "alto": "70"},
    {"page": 1, "rectangulo": {"lowerLeftX": 320, "lowerLeftY": 110, "upperRightX": 490, "upperRightY": 174}},
    {"page": "1", "ubicacion": {"origin": "TOP_LEFT", "x": "100", "y": "200", "width": "170", "height": "64", "pageHeight": "842"}},
])
def test_existing_signing_payloads_and_response_shape(frontend_client, placement):
    client, bearer, service = frontend_client
    response = client.post("/api/v1/firmar/pdf", headers=headers(bearer), json=signing_payload(placement))
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == ORIGIN
    body = response.json()
    assert set(body) == {"documentoFirmadoBase64", "documentoOriginalSha256", "certificado", "firmaLocal"}
    assert set(body["certificado"]) == {"cedula", "serial", "subject", "issuer", "validFrom", "validTo"}
    assert set(body["firmaLocal"]) == {"provider", "driver", "algorithm", "signedAt"}
    assert body["documentoFirmadoBase64"] == PDF_BASE64
    assert body["documentoOriginalSha256"] == PDF_HASH
    request = service.last_signature_request
    assert request["pin_mode"] == "LOCAL_PROMPT" and request["inline_pin"] is None
    assert request["metadata_b64"] == "e30="
    assert request["firma_params"] == signing_payload(placement)["firma"]


def test_existing_certificate_list_payload_and_fields(frontend_client):
    client, bearer, service = frontend_client
    response = client.post("/api/v1/certificados", headers=headers(bearer), json={
        "provider": "AUTO", "tipoKeyStoreProvider": "TOKEN", "pinMode": "LOCAL_PROMPT",
        "expectedCedula": "1234567890",
    })
    assert response.status_code == 200
    assert set(response.json()) == {"certificados"}
    certificate = response.json()["certificados"][0]
    assert set(certificate) == {
        "id", "cedula", "subject", "issuer", "serial", "validFrom", "validTo", "provider", "tokenLabel",
        "displayName", "shortName", "type", "isCa", "hasPrivateKey", "signable",
    }
    assert certificate["id"] == "Signing Certificate" and certificate["signable"] is True


@pytest.mark.parametrize("error,status,code", [
    (PinInvalidError("Invalid PIN"), 403, "PIN_INVALID"),
    (UserCancelledError("Cancelled"), 400, "USER_CANCELLED"),
    (TimeoutError_("Timed out"), 504, "TIMEOUT"),
])
def test_existing_signing_error_contract(frontend_client, error, status, code):
    client, bearer, service = frontend_client
    service.failure = error
    response = client.post("/api/v1/firmar/pdf", headers=headers(bearer), json=signing_payload({}))
    assert response.status_code == status
    assert response.headers["Access-Control-Allow-Origin"] == ORIGIN
    assert response.json() == {"code": code, "message": error.message, "details": []}


def test_bearer_and_replay_headers_still_required(frontend_client):
    client, bearer, service = frontend_client
    payload = signing_payload({})
    response = client.post("/api/v1/firmar/pdf", headers={"Origin": ORIGIN}, json=payload)
    assert response.status_code == 401 and response.json()["code"] == "AUTH_REQUIRED"
    response = client.post("/api/v1/firmar/pdf", headers={"Origin": ORIGIN, "Authorization": f"Bearer {bearer}"}, json=payload)
    assert response.status_code == 400
    request_headers = headers(bearer)
    assert client.post("/api/v1/firmar/pdf", headers=request_headers, json=payload).status_code == 200
    response = client.post("/api/v1/firmar/pdf", headers=request_headers, json=payload)
    assert response.status_code == 409 and response.json()["code"] == "REPLAY_DETECTED"


def test_signing_preflight_accepts_existing_browser_headers(frontend_client):
    client, bearer, service = frontend_client
    response = client.options("/api/v1/firmar/pdf", headers={
        "Origin": ORIGIN, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type,Authorization,X-LocalAPI-Timestamp,X-LocalAPI-Request-Id",
    })
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == ORIGIN


def test_pairing_status_only_reports_current_authorizations(frontend_client, monkeypatch):
    client, bearer, service = frontend_client
    manager = deps.pairing_manager
    now = 1_700_000_000
    monkeypatch.setattr(pairing_module, "_now_ts", lambda: now)

    def token(name, issued_at, expires_at, revoked=False):
        return PairingToken(
            token=f"secret-{name}", origin=f"https://{name}.salcedo.gob.ec",
            installation_id=manager.installation_id, scopes=[SCOPE_CERT_LIST],
            issued_at=issued_at, expires_at=expires_at, revoked=revoked,
        )

    valid = token("valid", now - 10, now + 10)
    just_issued = token("new", now, now + 60)
    all_tokens = [
        valid, just_issued, token("expired", now - 100, now - 1),
        token("boundary", now - 100, now), token("future", now + 1, now + 100),
        token("revoked", now - 10, now + 10, revoked=True),
    ]
    manager._data.tokens = all_tokens
    response = client.get("/api/v1/pairing/status", headers={"Origin": ORIGIN})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"installationId", "requirePairing", "devMode", "allowedOrigins", "activeTokens"}
    assert body["activeTokens"] == [
        {
            "origin": current.origin, "scopes": current.scopes,
            "issuedAt": current.issued_at, "expiresAt": current.expires_at, "revoked": False,
        }
        for current in [valid, just_issued]
    ]
    assert manager.list_tokens() == all_tokens  # Keep historical records for revocation/auditing.
    assert "secret-" not in response.text  # The status endpoint never exposes Bearers.


@pytest.mark.parametrize("endpoint", ["/api/v1/certificados", "/api/v1/firmar/pdf"])
def test_expired_bearer_can_repair_and_retry_using_existing_contract(frontend_client, monkeypatch, endpoint):
    client, bearer, service = frontend_client
    manager = deps.pairing_manager
    expired = manager.list_tokens()[0]
    monkeypatch.setattr(pairing_module, "_now_ts", lambda: expired.expires_at)
    manager.set_approval_callback(lambda origin, scopes: True)
    calls = []
    method = "sign_pdf" if endpoint.endswith("/firmar/pdf") else "list_certificates"
    original = getattr(service, method)

    def record_call(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(service, method, record_call)
    payload = signing_payload({}) if method == "sign_pdf" else {"provider": "AUTO", "pinMode": "LOCAL_PROMPT"}
    response = client.post(endpoint, headers=headers(bearer), json=payload)
    assert response.status_code == 401
    assert response.json() == {"code": "TOKEN_EXPIRED", "message": "Token expirado.", "details": []}
    assert response.headers["Access-Control-Allow-Origin"] == ORIGIN
    assert calls == []  # Rejected before hardware, PIN or document signing.

    repaired = client.post("/api/v1/pairing/request", headers={"Origin": ORIGIN}, json={
        "origin": ORIGIN, "scopes": [SCOPE_CERT_LIST, SCOPE_PDF_SIGN],
    })
    assert repaired.status_code == 200
    authorization = repaired.json()
    assert authorization["status"] == "approved"
    assert authorization["token"] != bearer
    assert authorization["expiresAt"] > expired.expires_at
    retry = client.post(endpoint, headers=headers(authorization["token"]), json=payload)
    assert retry.status_code == 200
    assert len(calls) == 1
