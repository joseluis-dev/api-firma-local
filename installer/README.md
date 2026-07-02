# GadSign Local API - Guia de instalacion

## Empaquetado Windows (PyInstaller + Inno Setup)

1. Instala dependencias de build en una build machine:
   ```
   pip install -r requirements.txt pyinstaller
   python installer/make_icon.py
   ```
2. Genera el bundle one-folder:
   ```
   python installer/build.py
   ```
   Salida: `installer/dist/GadSignLocalAPI/`
3. Firma el ejecutable con tu certificado de code signing:
   ```
   python installer/sign.py installer/dist/GadSignLocalAPI/GadSignLocalAPI.exe --pfx codigo.pfx --password *****
   ```
4. Empaqueta con Inno Setup 6.x:
   ```
   iscc installer/inno_setup.iss
   ```
   Salida: `installer/output/GadSignLocalAPI-<version>-setup.exe`
5. Firma el instalador:
   ```
   python installer/sign.py installer/output/GadSignLocalAPI-1.0.0-setup.exe --pfx codigo.pfx --password *****
   ```

## Autoarranque por usuario

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
  "allowedOrigins": ["https://www.salcedo.gob.ec"],
  "devMode": false,
  "requirePairing": true,
  "requireUserConfirmation": true,
  "pinCacheTtlSeconds": 120,
  "maxPdfMb": 25,
  "logLevel": "INFO",
  "signTimeoutSeconds": 120,
  "pkcs11ModulePath": "C:\\Windows\\System32\\eTPKCS11.dll",
  "defaultProvider": "SAFENET"
}
```
