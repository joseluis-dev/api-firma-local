# GadSign Local API - Guia de instalacion

## Empaquetado Windows (PyInstaller + Inno Setup)

1. Instala dependencias de build en una maquina Windows:
   ```
   pip install -r requirements.txt pyinstaller
   ```
   Tambien instala Inno Setup 6.x. En Windows puedes usar:
   ```
   winget install --id JRSoftware.InnoSetup -e
   ```
2. Genera el bundle one-folder:
   ```
   python installer/build.py
   ```
   Salida: `installer/dist/GadSignLocalAPI/`. El script genera
   `resources/gadsign.ico` automaticamente si no existe.
3. Firma el ejecutable con tu certificado de code signing:
   ```
   python installer/sign.py installer/dist/GadSignLocalAPI/GadSignLocalAPI.exe --pfx codigo.pfx --password *****
   ```
4. Empaqueta con Inno Setup 6.x:
   ```
   iscc installer/inno_setup.iss
   ```
   Si `iscc` no esta en el `PATH`, usa:
   ```powershell
   & "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" "installer\inno_setup.iss"
   ```
   Salida: `installer/output/GadSignLocalAPI-<version>-setup.exe`
5. Firma el instalador:
   ```
   python installer/sign.py installer/output/GadSignLocalAPI-1.0.0-setup.exe --pfx codigo.pfx --password *****
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
