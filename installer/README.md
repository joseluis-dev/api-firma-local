# GadSign Local API - Guia de instalacion

## Empaquetado Windows (PyInstaller + Inno Setup)

1. Instala dependencias de build en una maquina Windows x64:
   ```
   py -3.13 -m venv .venv-build
   .venv-build\Scripts\python.exe -m pip install -r requirements-build.txt
   ```
   Tambien instala Inno Setup 6.x si no lo tienes:
   ```
   winget install --id JRSoftware.InnoSetup -e
   ```
2. Genera el bundle one-folder:
   ```
   .venv-build\Scripts\python.exe installer/build.py
   ```
   Salida: `installer/dist/GadSignLocalAPI/`.
3. Opcional — firma el ejecutable con signtool:
   ```
   python installer/sign.py installer/dist/GadSignLocalAPI/GadSignLocalAPI.exe --thumbprint <SHA1>
   ```
   Si no tienes certificado, omite este paso. La app funcionara sin firma
   (Windows mostrara "Editor desconocido").
4. Empaqueta con Inno Setup 6.x:
   ```powershell
   & "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" /DMyAppVersion=1.0.1 installer\inno_setup.iss
   ```
   Salida: `installer/output/GadSignLocalAPI-1.0.1-setup.exe`.
   Para firmar tambien el instalador y desinstalador, agrega `/DSignInstaller`
   (requiere certificado configurado).
5. Opcional — firma el instalador:
   ```
   python installer/sign.py installer/output/GadSignLocalAPI-1.0.1-setup.exe --thumbprint <SHA1>
   ```

## Instalador final

El instalador `installer/output/GadSignLocalAPI-<version>-setup.exe`:

- Instala la aplicacion en `%LOCALAPPDATA%\Programs\GadSign Local API`.
- Crea un acceso directo opcional en el escritorio.
- Crea un acceso directo opcional en el inicio de sesion del usuario.
- Lanza `GadSignLocalAPI.exe` al finalizar la instalacion.
- Deja la API escuchando en `http://127.0.0.1:44113` con icono de bandeja.
- Es por usuario y no requiere permisos de administrador.

Los drivers PKCS#11 del fabricante no se empaquetan. Deben estar instalados
en Windows y disponibles en una ruta conocida, por ejemplo
`C:\Windows\System32\eTPKCS11.dll`.

## Autoarranque por usuario alternativo

Equivale a un acceso directo en `shell:startup` pero mas robusto:

```
python -m localapi.scripts.autostart install
python -m localapi.scripts.autostart status
python -m localapi.scripts.autostart remove
```

## Datos persistentes

- Config: `%LOCALAPPDATA%\GadSign\LocalAPI\config.json`
- Pairing: `%LOCALAPPDATA%\GadSign\LocalAPI\pairing.json` (secreto HMAC cifrado con DPAPI en Windows)
- Logs: `%LOCALAPPDATA%\GadSign\LocalAPI\logs\`

## Updates firmados

Publicar un manifest en `https://updates.example.com/manifest.json` con:

```json
{
  "version": "1.0.1",
  "url": "https://updates.example.com/GadSignLocalAPI-1.0.1-setup.exe",
  "sha256": "...",
  "signature": "<RSA-SHA256 sobre el resto del manifest, base64>"
}
```

`installer/update_check.py` valida firma y SHA-256 antes de aplicar.

## Configuracion (config.json)

```json
{
  "host": "127.0.0.1",
  "port": 44113,
  "allowed_origins": ["https://*.salcedo.gob.ec"],
  "dev_mode": false,
  "require_pairing": true,
  "require_user_confirmation": true,
  "pin_cache_ttl_seconds": 120,
  "max_pdf_mb": 25,
  "log_level": "INFO",
  "sign_timeout_seconds": 120,
  "request_timeout_seconds": 30,
  "pkcs11_module_path": "C:\\Windows\\System32\\eTPKCS11.dll",
  "default_provider": "SAFENET",
  "mock_driver": false,
  "pcsc_reader_index": 0
}
```
