"""Smoke test contra la API local levantada.

Levanta uvicorn en un thread y dispara las 3 endpoints del contrato.
Cubre los caminos de exito y los principales errores.
"""
from __future__ import annotations

import base64
import hashlib
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent))

from localapi.app import app  # noqa: E402
from localapi.config import settings  # noqa: E402


def make_pdf() -> bytes:
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 144]>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n"
        b"0000000009 00000 n \n0000000056 00000 n \n0000000111 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
    )
    return body


class ServerThread(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=settings.port,
            log_level="warning",
        )
        self.server = uvicorn.Server(self.config)

    def run(self) -> None:  # type: ignore[override]
        self.server.run()


def wait_for_server(base: str, t: ServerThread, timeout: float = 10.0) -> bool:
    t.start()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base}/health", timeout=1.0)
            if r.status_code in {200, 503}:
                return True
        except Exception:
            time.sleep(0.2)
    return False


def section(title: str) -> None:
    print(f"\n== {title} ==")


def main() -> int:
    base = f"http://127.0.0.1:{settings.port}/api/v1"
    t = ServerThread()
    if not wait_for_server(base, t):
        print("Servidor no arranco.")
        return 1

    try:
        section("/health")
        r = httpx.get(f"{base}/health", timeout=5.0)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "ok"
        assert "PDF_PADES_TOKEN" in body["capabilities"]
        assert any(p["id"] == "SAFENET" and p["installed"] for p in body["providers"])
        assert any(p["id"] == "PCSC" and p["installed"] for p in body["providers"])
        installed_ids = [p["id"] for p in body["providers"] if p["installed"]]
        print("OK", body["status"], "installed=", installed_ids)

        section("/certificados (MOCK, sin PIN)")
        r = httpx.post(
            f"{base}/certificados",
            json={"provider": "MOCK", "pinMode": "NONE", "expectedCedula": "1804724555"},
            timeout=5.0,
        )
        assert r.status_code == 200, r.text
        certs = r.json()["certificados"]
        assert len(certs) == 1
        assert certs[0]["cedula"] == "1804724555"
        print("OK", certs[0]["id"], "cedula=", certs[0]["cedula"])

        section("/firmar/pdf (exitoso)")
        pdf = make_pdf()
        sha = hashlib.sha256(pdf).hexdigest()
        r = httpx.post(
            f"{base}/firmar/pdf",
            json={
                "documentoBase64": base64.b64encode(pdf).decode("ascii"),
                "documentoSha256": sha,
                "certificadoId": "alias-demo-1",
                "expectedCedula": "1804724555",
                "firma": {
                    "formatoDocumento": "pdf",
                    "pagina": "1",
                    "tipoEstampado": "QR",
                    "razon": "Test",
                    "llx": "120",
                    "lly": "180",
                },
                "pinMode": "NONE",
            },
            timeout=10.0,
        )
        assert r.status_code == 200, r.text
        resp = r.json()
        assert resp["documentoOriginalSha256"] == sha
        assert resp["firmaLocal"]["provider"] == "MOCK"
        assert len(resp["documentoFirmadoBase64"]) > 100
        print("OK provider=", resp["firmaLocal"]["provider"], "alg=", resp["firmaLocal"]["algorithm"])

        section("/firmar/pdf -> INVALID_INPUT (hash no coincide)")
        r = httpx.post(
            f"{base}/firmar/pdf",
            json={
                "documentoBase64": base64.b64encode(pdf).decode("ascii"),
                "documentoSha256": "0" * 64,
                "certificadoId": "alias-demo-1",
                "expectedCedula": "1804724555",
                "firma": {"pagina": "1", "llx": "0", "lly": "0"},
                "pinMode": "NONE",
            },
            timeout=5.0,
        )
        assert r.status_code == 400, r.text
        assert r.json()["code"] == "INVALID_INPUT"
        print("OK code=INVALID_INPUT")

        section("/firmar/pdf -> INVALID_PDF (no es PDF)")
        r = httpx.post(
            f"{base}/firmar/pdf",
            json={
                "documentoBase64": base64.b64encode(b"hola mundo").decode("ascii"),
                "documentoSha256": hashlib.sha256(b"hola mundo").hexdigest(),
                "certificadoId": "alias-demo-1",
                "expectedCedula": "1804724555",
                "firma": {"pagina": "1", "llx": "0", "lly": "0"},
                "pinMode": "NONE",
            },
            timeout=5.0,
        )
        assert r.status_code == 400, r.text
        assert r.json()["code"] == "INVALID_PDF"
        print("OK code=INVALID_PDF")

        section("/firmar/pdf -> CEDULA_MISMATCH")
        r = httpx.post(
            f"{base}/firmar/pdf",
            json={
                "documentoBase64": base64.b64encode(pdf).decode("ascii"),
                "documentoSha256": sha,
                "certificadoId": "alias-demo-1",
                "expectedCedula": "9999999999",
                "firma": {"pagina": "1", "llx": "0", "lly": "0"},
                "pinMode": "NONE",
            },
            timeout=5.0,
        )
        assert r.status_code == 409, r.text
        assert r.json()["code"] == "CEDULA_MISMATCH"
        print("OK code=CEDULA_MISMATCH")

        section("/firmar/pdf -> CERTIFICATE_NOT_FOUND")
        r = httpx.post(
            f"{base}/firmar/pdf",
            json={
                "documentoBase64": base64.b64encode(pdf).decode("ascii"),
                "documentoSha256": sha,
                "certificadoId": "alias-inexistente",
                "expectedCedula": "1804724555",
                "firma": {"pagina": "1", "llx": "0", "lly": "0"},
                "pinMode": "NONE",
            },
            timeout=5.0,
        )
        assert r.status_code == 404, r.text
        assert r.json()["code"] == "CERTIFICATE_NOT_FOUND"
        print("OK code=CERTIFICATE_NOT_FOUND")

        print("\nTodas las pruebas pasaron.")
        return 0
    finally:
        t.server.should_exit = True
        t.join(timeout=3)


if __name__ == "__main__":
    sys.exit(main())
