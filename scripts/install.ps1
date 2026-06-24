"""Instalador rapido para Windows (PowerShell + pip)."""
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSCommandPath
Set-Location $root

Write-Host "== localapi install ==" -ForegroundColor Cyan

# 1. Detectar Python 3.11+
$py = $null
foreach ($c in @("python", "py", "python3")) {
    try {
        $v = (& $c -c "import sys; print(sys.version_info.major, sys.version_info.minor)" 2>$null).Trim()
        if ($v) {
            $maj, $min = $v.Split(" ")
            if ([int]$maj -ge 3 -and [int]$min -ge 11) {
                $py = $c
                break
            }
        }
    } catch {}
}
if (-not $py) { throw "Se requiere Python >= 3.11." }
Write-Host "Python: $(& $py --version)"

# 2. Crear venv si no existe
if (-not (Test-Path ".venv")) {
    Write-Host "Creando venv..." -ForegroundColor Yellow
    & $py -m venv .venv
}
$venvPy = Join-Path $root ".venv\Scripts\python.exe"
$venvPip = Join-Path $root ".venv\Scripts\pip.exe"

# 3. Instalar dependencias
Write-Host "Instalando dependencias..." -ForegroundColor Yellow
& $venvPip install --upgrade pip | Out-Null
& $venvPip install -r requirements.txt

# 4. Copiar .env
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Archivo .env creado (editalo con tu PKCS11_MODULE_PATH)." -ForegroundColor Green
}

# 5. Crear acceso directo en Startup
$startup = [Environment]::GetFolderPath("Startup")
$bat = Join-Path $startup "localapi.bat"
$batContent = @"
@echo off
cd /d "$root"
"$venvPy" -m localapi.main
"@
Set-Content -Path $bat -Value $batContent -Encoding ASCII
Write-Host "Autostart creado: $bat" -ForegroundColor Green

Write-Host "`nListo. Para iniciar ahora:" -ForegroundColor Green
Write-Host "  .venv\Scripts\python.exe -m localapi.main"
Write-Host "Documentacion OpenAPI: http://127.0.0.1:44113/api/v1/docs"
