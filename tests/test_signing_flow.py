"""Signing order, hardware lookup contracts and cryptographic PDF integrity."""
from datetime import datetime, timedelta, timezone
from io import BytesIO
from types import SimpleNamespace

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from localapi.core import token_service as service_module
from localapi.core.crypto_utils import encode_base64, decode_base64, sha256_hex
from localapi.core.drivers import pkcs11_driver as driver_module
from localapi.core.errors import PinInvalidError, TimeoutError_, UserCancelledError
from localapi.core.pdf_signer import PadesParams, prepare_pdf_signature


@pytest.fixture
def signing_material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True).sign(key, hashes.SHA256()))
    writer = PdfFileWriter()
    content = writer.add_object(generic.StreamObject(stream_data=b""))
    writer.insert_page(PageObject(content, (0, 0, 595, 842)))
    output = BytesIO()
    writer.write(output)
    return key, cert.public_bytes(serialization.Encoding.DER), output.getvalue()


def assert_valid_signature(signed, cert_der):
    reader = PdfFileReader(BytesIO(signed))
    assert len(reader.embedded_signatures) == 1
    status = validate_pdf_signature(
        reader.embedded_signatures[0],
        signer_validation_context=ValidationContext(
            trust_roots=[asn1_x509.Certificate.load(cert_der)], allow_fetching=False,
        ),
    )
    assert status.intact and status.valid and status.trusted
    return reader.embedded_signatures[0]


@pytest.mark.parametrize("digest_algorithm", ["SHA256", "SHA384", "SHA512"])
def test_preparation_does_not_sign_and_reserves_real_rsa_size(signing_material, digest_algorithm):
    key, cert_der, pdf = signing_material
    prepared = prepare_pdf_signature(
        pdf_bytes=pdf, certificate_der=cert_der, certificate_chain_der=[cert_der],
        digest_algorithm=digest_algorithm, params=PadesParams(width=110, height=36),
    )
    calls = []

    def sign(data, algorithm):
        calls.append(algorithm)
        return key.sign(data, padding.PKCS1v15(), getattr(hashes, algorithm.upper())())

    signature = assert_valid_signature(prepared.sign(sign), cert_der)
    assert calls == [digest_algorithm.lower()]
    assert len(signature.signer_info["signature"].native) == 384
    rect = signature.sig_field["/Rect"]
    assert (rect[2] - rect[0], rect[3] - rect[1]) == (110, 36)


@pytest.fixture
def fake_token(monkeypatch, signing_material):
    key, cert_der, pdf = signing_material
    events, searches = [], []
    constants = SimpleNamespace(
        Attribute=SimpleNamespace(CLASS="class", LABEL="label", ID="id", VALUE="value"),
        ObjectClass=SimpleNamespace(CERTIFICATE="certificate", PRIVATE_KEY="private_key"),
        Mechanism=SimpleNamespace(SHA512_RSA_PKCS="sha512_rsa_pkcs"),
    )

    class PrivateKey(dict):
        def sign(self, data, mechanism):
            events.append("sign")
            assert mechanism == "sha512_rsa_pkcs"
            return key.sign(data, padding.PKCS1v15(), hashes.SHA512())

    cert = {"class": "certificate", "label": "Signing Certificate", "id": b"\x01", "value": cert_der}
    private_key = PrivateKey({"class": "private_key", "label": "Different key label", "id": b"\x01"})

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_objects(self, attrs):
            searches.append(attrs)
            return iter(obj for obj in [cert, private_key] if all(obj.get(k) == v for k, v in attrs.items()))

    driver = driver_module.Pkcs11Driver("fake.dll")

    def open_session(pin=None):
        events.append("login" if pin else "public_session")
        return Session()

    monkeypatch.setattr(driver_module, "_import_pkcs11", lambda: (None, constants))
    monkeypatch.setattr(driver, "_open_session", open_session)
    monkeypatch.setattr(driver, "is_available", lambda: True)
    monkeypatch.setattr(driver, "get_token_label", lambda: "Test Token")
    return driver, events, searches, cert_der, pdf


def test_pdf_prepared_before_pin_and_only_one_login(monkeypatch, fake_token):
    driver, events, searches, cert_der, pdf = fake_token
    service = service_module.TokenService()
    cache = service_module._CertCache()
    cache._data["PKCS11|Test Token"] = [{
        "id": "Signing Certificate", "signable": True, "shortName": "Test Signer",
        "validFrom": datetime.now(timezone.utc), "validTo": datetime.now(timezone.utc),
    }]
    monkeypatch.setattr(service_module, "_cert_cache", cache)
    monkeypatch.setattr(service_module, "get_driver", lambda *args: driver)

    def prepare(**kwargs):
        result = prepare_pdf_signature(**kwargs)
        events.append("prepared")
        return result

    def capture(*args):
        events.append("pin")
        return "test-pin"

    monkeypatch.setattr(service_module, "prepare_pdf_signature", prepare)
    monkeypatch.setattr(service, "_capture_pin_for_driver", capture)
    result = service.sign_pdf(
        documento_base64=encode_base64(pdf), documento_sha256=sha256_hex(pdf),
        certificado_id="Signing Certificate", provider="SAFENET", tipo="TOKEN",
        pin_mode="LOCAL_PROMPT", inline_pin=None, metadata_b64=None,
        firma_params={"rectangulo": {
            "lowerLeftX": 320, "lowerLeftY": 110, "upperRightX": 490, "upperRightY": 174,
        }}, request_timeout_s=5, sign_timeout_s=5,
    )
    assert events == ["public_session", "prepared", "pin", "login", "sign"]
    assert all(len(search) > 1 for search in searches)
    assert {"class": "private_key", "id": b"\x01"} in searches
    signature = assert_valid_signature(decode_base64(result.documentoFirmadoBase64), cert_der)
    # The viewer's 170x64 selection anchors the 110x36 stamp at the same centre.
    assert tuple(signature.sig_field["/Rect"]) == (350, 124, 460, 160)


def test_private_key_lookup_uses_id_not_certificate_label(fake_token):
    driver, events, searches, cert_der, pdf = fake_token
    assert driver.get_certificate_der("01") == cert_der
    assert {"class": "certificate", "id": b"\x01"} in searches


@pytest.mark.parametrize("key_label", ["Signing Certificate", "Signing Certificate\x00 "])
def test_key_label_fallback_preserves_legacy_tokens(fake_token, key_label):
    driver, events, searches, cert_der, pdf = fake_token
    session = driver._open_session("test-pin")
    objects = list(session.get_objects({}))
    # Some older tokens expose no matching CKA_ID on the key.
    objects[1]["id"] = b"\x02"
    objects[1]["label"] = key_label
    _, constants = driver_module._import_pkcs11()
    private_key, certificate = driver._find_key_and_cert(session, constants, "Signing Certificate")
    assert private_key is objects[1]
    assert certificate["value"] == cert_der


@pytest.mark.parametrize("message,error", [
    ("CKR_FUNCTION_CANCELED", UserCancelledError),
    ("CKR_TIMEOUT", TimeoutError_),
    ("CKR_PIN_INCORRECT", PinInvalidError),
])
def test_token_errors_keep_their_api_codes(message, error):
    with pytest.raises(error):
        driver_module.Pkcs11Driver._map_sign_error(RuntimeError(message))


@pytest.mark.parametrize("params,expected", [
    ({}, (120, 180, 230, 216)),
    ({"llx": 100, "lly": 200, "ancho": 170, "alto": 64}, (130, 214, 240, 250)),
    ({"ubicacion": {"origin": "BOTTOM_LEFT", "x": 100, "y": 200, "width": 170, "height": 64}},
     (130, 214, 240, 250)),
    ({"ubicacion": {"origin": "TOP_LEFT", "x": 100, "y": 200, "width": 170, "height": 64, "pageHeight": 842}},
     (130, 592, 240, 628)),
    ({"x": 100, "y": 200, "width": 170, "height": 64, "pageHeight": 842}, (130, 592, 240, 628)),
])
def test_stamp_size_and_anchor_across_placement_formats(params, expected):
    placement = service_module._resolve_placement(params)
    assert service_module._firmaec_box_centered(placement["box"]) == expected


@pytest.mark.parametrize("name", [
    "Test Signer", "José Luis Yépez García", "Mayra Alejandra Estrella Cepeda",
    "María de los Ángeles Fernández de Córdoba y Villavicencio",
    "A" * 70 + " " + "B" * 70,
])
def test_stamp_text_stays_inside_the_firmaec_size(monkeypatch, name):
    from PIL import Image, ImageDraw
    from localapi.core.stamp_firmaec import render_firmaec_stamp_png

    bounds = []
    draw_text = ImageDraw.ImageDraw.text

    def record_text(draw, xy, text, *args, **kwargs):
        bounds.append(draw.textbbox(xy, text, font=kwargs["font"], anchor=kwargs["anchor"]))
        return draw_text(draw, xy, text, *args, **kwargs)

    monkeypatch.setattr(ImageDraw.ImageDraw, "text", record_text)
    png = render_firmaec_stamp_png(
        signer_name=name, razon="Firmado digitalmente", fecha_iso="2026-10-02T12:00:00.000+00:00",
    )
    image = Image.open(BytesIO(png))
    assert image.size == (440, 144)  # 110 x 36 PDF points at 288 DPI.
    assert bounds
    assert all(144 <= x1 <= x2 < 440 and 0 <= y1 <= y2 < 144 for x1, y1, x2, y2 in bounds)


# ---------------------------------------------------------------------------
# PIN cache bound to the requesting origin
# ---------------------------------------------------------------------------

ORIGIN_A = "https://a.salcedo.gob.ec"
ORIGIN_B = "https://b.salcedo.gob.ec"


@pytest.fixture
def pin_env(monkeypatch):
    """Isolated PIN cache plus a counting ``ask_pin`` that never opens a dialog."""
    import threading
    import time

    cache = service_module._PinCache(ttl_seconds=120)
    monkeypatch.setattr(service_module, "_pin_cache", cache)
    state = SimpleNamespace(prompts=0, active=0, max_active=0, lock=threading.Lock(), delay=0.0)

    def ask_pin(token_label):
        with state.lock:
            state.prompts += 1
            state.active += 1
            state.max_active = max(state.max_active, state.active)
        time.sleep(state.delay)
        with state.lock:
            state.active -= 1
        return "123456"

    monkeypatch.setattr(service_module, "ask_pin", ask_pin)
    driver = SimpleNamespace(provider_id="PKCS11")
    return service_module.TokenService(), driver, cache, state


def test_pin_cache_entries_are_bound_to_origin():
    cache = service_module._PinCache(ttl_seconds=120)
    cache.put("PKCS11|Token", ORIGIN_A, "111111")
    assert cache.get("PKCS11|Token", ORIGIN_A) == "111111"
    assert cache.get("PKCS11|Token", ORIGIN_B) is None
    assert cache.get("OTHER|Token", ORIGIN_A) is None


def test_same_origin_reuses_cached_pin_within_ttl(pin_env):
    service, driver, cache, state = pin_env
    for _ in range(3):
        assert service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", ORIGIN_A) == "123456"
    assert state.prompts == 1


def test_another_origin_must_prompt_again_for_the_same_token(pin_env):
    service, driver, cache, state = pin_env
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", ORIGIN_A)
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", ORIGIN_B)
    assert state.prompts == 2
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", ORIGIN_A)
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", ORIGIN_B)
    assert state.prompts == 2  # each origin keeps its own entry


def test_origin_is_normalized_and_missing_origin_uses_a_fixed_key(pin_env):
    service, driver, cache, state = pin_env
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", ORIGIN_A)
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", ORIGIN_A.upper() + "/")
    assert state.prompts == 1
    # require_pairing disabled: no origin available, behaves like the old token-wide cache.
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token")
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", None)
    service._capture_pin_for_driver("LOCAL_PROMPT", None, driver, "Token", "")
    assert state.prompts == 2


def test_pin_dialogs_stay_serialized_per_token_across_origins(pin_env):
    import threading

    service, driver, cache, state = pin_env
    state.delay = 0.15
    threads = [
        threading.Thread(
            target=service._capture_pin_for_driver,
            args=("LOCAL_PROMPT", None, driver, "Token", origin),
        )
        for origin in (ORIGIN_A, ORIGIN_B)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert state.prompts == 2
    assert state.max_active == 1  # never two PIN dialogs at once for the same token
    assert cache.entry_lock("PKCS11|Token") is cache.entry_lock("PKCS11|Token")


def test_pin_cache_purges_expired_entries_on_get_and_put():
    import time

    cache = service_module._PinCache(ttl_seconds=10)
    stale = time.monotonic() - 100
    cache._data[("T1", ORIGIN_A)] = ("old-1", stale)
    cache._data[("T2", ORIGIN_A)] = ("old-2", stale)
    cache._data[("T3", ORIGIN_A)] = ("old-3", stale)
    assert cache.get("T1", ORIGIN_B) is None
    assert set(cache._data) == set()  # a get() sweeps every expired entry, not only its own
    cache._data[("T4", ORIGIN_A)] = ("old-4", stale)
    cache.put("T5", ORIGIN_A, "fresh")
    assert set(cache._data) == {("T5", ORIGIN_A)}


def test_pin_cache_disabled_when_ttl_is_zero():
    cache = service_module._PinCache(ttl_seconds=0)
    cache.put("T", ORIGIN_A, "111111")
    assert cache.get("T", ORIGIN_A) is None


def test_pin_errors_invalidate_the_token_for_every_origin(monkeypatch):
    cache = service_module._PinCache(ttl_seconds=120)
    monkeypatch.setattr(service_module, "_pin_cache", cache)
    cache.put("PKCS11|Token", ORIGIN_A, "111111")
    cache.put("PKCS11|Token", ORIGIN_B, "222222")
    cache.put("PKCS11|Other", ORIGIN_A, "333333")
    service_module.TokenService._invalidate_pin_on_error(PinInvalidError("bad"), "PKCS11|Token")
    assert cache.get("PKCS11|Token", ORIGIN_A) is None
    assert cache.get("PKCS11|Token", ORIGIN_B) is None
    assert cache.get("PKCS11|Other", ORIGIN_A) == "333333"


def test_sign_pdf_binds_pin_capture_to_the_requesting_origin(monkeypatch, fake_token):
    driver, events, searches, cert_der, pdf = fake_token
    service = service_module.TokenService()
    cache = service_module._CertCache()
    cache._data["PKCS11|Test Token"] = [{
        "id": "Signing Certificate", "signable": True, "shortName": "Test Signer",
        "validFrom": datetime.now(timezone.utc), "validTo": datetime.now(timezone.utc),
    }]
    monkeypatch.setattr(service_module, "_cert_cache", cache)
    monkeypatch.setattr(service_module, "get_driver", lambda *args: driver)
    captured = []

    def capture(*args):
        captured.append(args)
        return "test-pin"

    monkeypatch.setattr(service, "_capture_pin_for_driver", capture)
    placement = {"rectangulo": {"lowerLeftX": 320, "lowerLeftY": 110, "upperRightX": 490, "upperRightY": 174}}
    for origin in (ORIGIN_A, None):
        extra = {} if origin is None else {"origin": origin}
        service.sign_pdf(
            documento_base64=encode_base64(pdf), documento_sha256=sha256_hex(pdf),
            certificado_id="Signing Certificate", provider="SAFENET", tipo="TOKEN",
            pin_mode="LOCAL_PROMPT", inline_pin=None, metadata_b64=None,
            firma_params=placement, request_timeout_s=5, sign_timeout_s=5, **extra,
        )
    assert [args[-1] for args in captured] == [ORIGIN_A, None]
