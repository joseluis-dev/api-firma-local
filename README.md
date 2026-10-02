# localapi

API local de firma con token (PKCS#11 / PCSC) escrita en Python.
Escucha solo en `127.0.0.1:44113` y expone tres endpoints para que el
frontend web orqueste la firma PAdES contra el token fisico del usuario
sin que la clave privada salga del dispositivo.

## Estado

Implementacion de referencia en Python del contrato HTTP descrito en el
documento de diseno. Incluye:

- Driver MOCK para desarrollo y pruebas sin hardware.
- Driver PKCS#11 (`python-pkcs11`) para tokens que exponen un modulo
  estandar (ePass3003, Bit4Id, Safenet, UKC, etc.).
- Driver PCSC (`pyscard`) para smart cards; la firma PAdES real se
  delega al modulo PKCS#11 del fabricante sobre PCSC.
- Firma PAdES con `pyhanko` cuando hay certificado real; fallback con
  trailer para entornos sin pyhanko o mock.
- Dialogo nativo de PIN (tkinter) que nunca envia el PIN al navegador.
- CORS estricto, rate limit, validacion SHA-256, validacion de cedula,
  redaction de logs, timeouts agresivos.
- Cabeceras de seguridad y rechazo de conexiones no loopback.

## Requisitos

- Python **3.11+** (probado con 3.13).
- Windows 10/11, Linux o macOS.
- Opcional: modulo PKCS#11 del fabricante (`.dll`/`.so`/`.dylib`).
- Opcional: `pyscard` para PCSC.
- Opcional: `pyhanko` para firma PAdES real.

## Instalacion

### Windows (recomendado)

```powershell
cd localapi
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

El script:
1. Crea `.venv`.
2. Instala dependencias.
3. Crea `.env` desde `.env.example`.
4. Crea un acceso directo en `shell:startup` para autoinicio al
   iniciar sesion.

### Manual

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux/macOS
pip install -r requirements.txt
cp .env.example .env
```

## Ejecucion

```bash
python -m localapi.main
```

Al arrancar, escucha en `http://127.0.0.1:44113`. Documentacion
interactiva en `http://127.0.0.1:44113/api/v1/docs`.

## Configuracion (.env)

| Variable | Default | Descripcion |
|---|---|---|
| `HOST` | `127.0.0.1` | Solo loopback. |
| `PORT` | `44113` | Puerto TCP. |
| `LOG_LEVEL` | `INFO` | Nivel de log. |
| `REQUEST_TIMEOUT_SECONDS` | `30` | Timeout por operacion. |
| `PIN_MAX_ATTEMPTS` | `3` | Intentos antes de bloquear. |
| `PIN_BACKOFF_SECONDS` | `2` | Espera entre intentos fallidos. |
| `RATE_LIMIT_PER_MINUTE` | `30` | Rate limit por IP loopback. |
| `ALLOWED_ORIGIN` | `http://localhost:3000` | Origen CORS. |
| `DEFAULT_PROVIDER` | `AUTO` | `AUTO`, `MOCK`, `PKCS11`, `PCSC`. |
| `DEFAULT_PIN_MODE` | `LOCAL_PROMPT` | `LOCAL_PROMPT`, `INLINE`, `NONE`. |
| `MOCK_DRIVER` | `true` | Usar driver mock cuando este disponible. |
| `PKCS11_MODULE_PATH` | (vacio) | Ruta al modulo PKCS#11 del fabricante. |
| `PCSC_READER_INDEX` | `0` | Indice del lector PCSC. |

## Endpoints

Todos los request/response son JSON UTF-8.

### `GET /api/v1/health`

```bash
curl http://127.0.0.1:44113/api/v1/health
```

Devuelve `200` con estado y providers, o `503` si no hay driver
compatible.

### `POST /api/v1/certificados`

Lista los certificados del token.

```bash
curl -X POST http://127.0.0.1:44113/api/v1/certificados \
  -H "Content-Type: application/json" \
  -d '{"provider":"AUTO","pinMode":"LOCAL_PROMPT","expectedCedula":"1804724555"}'
```

### `POST /api/v1/firmar/pdf`

Firma un PDF PAdES.

```bash
curl -X POST http://127.0.0.1:44113/api/v1/firmar/pdf \
  -H "Content-Type: application/json" \
  -d @request.json
```

Ejemplo de `request.json`:

```json
{
  "documentoBase64": "JVBERi0xLjQK...",
  "documentoSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "certificadoId": "alias-1",
  "expectedCedula": "1804724555",
  "firma": {
    "formatoDocumento": "pdf",
    "pagina": "1",
    "tipoEstampado": "QR",
    "razon": "Firmado digitalmente",
    "llx": "120",
    "lly": "180"
  },
  "pinMode": "LOCAL_PROMPT"
}
```

El estampado mide **110 x 36 puntos PDF** (38.8 x 12.7 mm), como el
ejemplo de FirmaEC. Si el cliente envia `firma.rectangulo` o dimensiones
de seleccion, se conserva su centro y se aplica ese tamano al sello.

La API lee el certificado publico y prepara el PDF **antes de pedir el
PIN**. Despues se autentica una sola vez para localizar la clave y firmar.
`request_timeout_seconds` limita la preparacion y la captura del PIN por
separado; `sign_timeout_seconds` empieza despues de capturar el PIN.

Para diagnosticar demoras, buscar `Signing timing` en el log. Cada registro
incluye `stage` y `elapsed_ms`. `pin_ready_to_token_sign` mide el intervalo
desde que la API recibe el PIN hasta llamar al token; `token_sign` incluye
la espera de Touch Sense. `token_login` y `key_lookup` permiten localizar
demoras del controlador. Los registros no incluyen el PIN.

#### Compatibilidad con el frontend

La optimizacion de firma conserva endpoints, encabezados, campos JSON y
codigos de error. El frontend puede seguir enviando el mismo payload y
esperando la respuesta de `POST /api/v1/firmar/pdf`; no necesita nuevas
peticiones ni eventos para el PIN o Touch Sense.

El cambio visible es el sello de **110 x 36 puntos**, centrado en la
seleccion enviada. Si el visor dibuja una previsualizacion del sello, puede
ajustarla a esas dimensiones para que coincida con el PDF final. En un
visor con escala `s` pixeles por punto, la previsualizacion mide
`110 * s` por `36 * s` pixeles. Este ajuste visual es opcional para firmar.

#### Autorizacion local y expiracion

El Bearer de emparejamiento autoriza al navegador durante ocho horas. Al
vencer, la API devuelve HTTP `401` con `code=TOKEN_EXPIRED` antes de leer
certificados o solicitar el PIN. La aprobacion de emparejamiento y el PIN
del dispositivo son pasos independientes.

El cliente conserva `expiresAt` en segundos Unix junto al Bearer. Si vence,
solicita nuevamente `/api/v1/pairing/request`, comparte el emparejamiento
entre llamadas concurrentes y reintenta la operacion como maximo una vez
tras aprobarla. La cancelacion debe detener el reintento.

`GET /api/v1/pairing/status` y el contador de la bandeja consideran activos
solo los tokens no revocados con `issuedAt <= ahora < expiresAt`. Los
registros anteriores se conservan para auditoria y revocacion.

## Errores

Todas las respuestas de error siguen:

```json
{ "code": "PIN_INVALID", "message": "PIN del token incorrecto", "details": [] }
```

Codigos: `LOCAL_API_UNAVAILABLE`, `DRIVER_NOT_FOUND`, `TOKEN_NOT_FOUND`,
`TOKEN_LOCKED`, `PIN_REQUIRED`, `PIN_INVALID`, `CERTIFICATE_NOT_FOUND`,
`CEDULA_MISMATCH`, `SIGNATURE_REJECTED`, `INVALID_PDF`, `INVALID_INPUT`,
`TIMEOUT`, `USER_CANCELLED`.

## Politica de PIN

- `LOCAL_PROMPT` (recomendado): la API local muestra su propio dialogo
  tkinter. El PIN nunca viaja al navegador.
- `INLINE`: el PIN viaja en el body. Solo para entornos controlados.
- `NONE`: se asume que el token ya esta desbloqueado.

El PIN **nunca** se loguea. El formatter `SafeLogFormatter` redacta
valores sensibles automaticamente.

## Drivers

| Driver | Uso | Modulos requeridos |
|---|---|---|
| `MOCK` | Desarrollo y pruebas | Ninguno. |
| `PKCS11` | ePass3003, Bit4Id, Safenet, UKC | `python-pkcs11` + DLL del fabricante. |
| `PCSC` | Smart cards contactless | `pyscard`. La firma real se delega al PKCS#11 del fabricante. |

Configurar `PKCS11_MODULE_PATH` con la ruta al modulo del fabricante,
por ejemplo:

- ePass3003: `C:\Windows\System32\ePass3003PKCS11.dll`
- Bit4Id: `C:\Windows\System32\bit4ipki.dll`
- Safenet: `C:\Windows\System32\sstpkcs11.dll`

## Tests

```bash
python -m pytest localapi/tests/test_unit.py -v
python localapi/tests/smoke.py
```

## Estructura

```
localapi/
  app.py                  # FastAPI + middleware
  main.py                 # entry point uvicorn
  config.py               # Settings (pydantic-settings)
  __init__.py             # __version__
  api/
    routes.py             # /api/v1/health, /certificados, /firmar/pdf
  core/
    errors.py             # LocalApiError + codigos
    schemas.py            # Pydantic request/response
    logging_config.py     # logger seguro
    rate_limiter.py       # rate limit en memoria
    pin_dialog.py         # dialogo tkinter
    crypto_utils.py       # base64, sha256, validaciones
    pdf_signer.py         # wrapper pyhanko
    token_service.py      # orquestacion drivers + firma
    drivers/
      base.py             # TokenDriver (abstract)
      mock_driver.py      # MOCK
      pkcs11_driver.py    # PKCS#11
      pcsc_driver.py      # PCSC
      factory.py          # selector segun config
  scripts/
    install.py            # instalador cross-platform
    install.ps1           # instalador Windows
    tray.py               # system tray (opcional)
  tests/
    test_unit.py          # pruebas unitarias
    smoke.py              # smoke test contra uvicorn en thread
  requirements.txt
  .env.example
```

## Checklist de implementacion

- [x] API local escucha solo en `127.0.0.1`.
- [x] CORS configurado al origen del frontend (configurable).
- [x] No loguea PIN, base64, certs.
- [x] Soporte para los providers objetivo via PKCS#11.
- [x] Valida SHA-256 del documento antes de firmar.
- [x] Valida `expectedCedula` antes de firmar.
- [x] Dialogo de PIN nativo (tkinter).
- [x] Bloqueo de token tras 3 intentos fallidos.
- [x] `GET /api/v1/health`, `POST /api/v1/certificados`,
      `POST /api/v1/firmar/pdf`.

## Empaquetado

### Windows (PyInstaller + Inno Setup)

Lee `installer/README.md` para instrucciones completas de build, firma y
publicacion. Resumen rapido:

```powershell
pip install -r requirements-build.txt
python installer/build.py
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" /DMyAppVersion=1.0.0 installer\inno_setup.iss
```

El instalador generado (`installer/output/GadSignLocalAPI-<version>-setup.exe`):
- Instala en `%LOCALAPPDATA%\Programs\GadSign Local API` (sin admin).
- Crea icono de bandeja con `pystray`.
- Soporta actualizaciones in-place con el mismo AppId.
- Conserva configuracion y pairing entre actualizaciones.

### Linux / macOS

- **Linux**: `.desktop` + `systemd --user`, paquete `.deb`/`.rpm`.
- **macOS**: `LaunchAgent` con `LSUIElement=1`, instalador `.pkg`/`.dmg`.
