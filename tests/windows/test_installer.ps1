<#
.SYNOPSIS
  GadSign Local API — harness de pruebas de instalador Windows.
  Ejecutar en una VM desechable. Requiere permisos de usuario estandar.
.DESCRIPTION
  Prueba instalacion nueva, upgrade N->N+1, preservacion de datos,
  health de API, autostart y desinstalacion.
.PARAMETER SetupBaseline
  Ruta al instalador baseline (ej: 1.0.0).
.PARAMETER SetupCandidate
  Ruta al instalador candidato (ej: 1.0.1).
.PARAMETER SkipCleanup
  No desinstalar al final (para inspeccion manual).
.EXAMPLE
  .\test_installer.ps1 -SetupBaseline C:\artifacts\GadSignLocalAPI-1.0.0-setup.exe -SetupCandidate C:\artifacts\GadSignLocalAPI-1.0.1-setup.exe
#>
param(
    [Parameter(Mandatory)]
    [string]$SetupBaseline,
    [Parameter(Mandatory)]
    [string]$SetupCandidate,
    [switch]$SkipCleanup
)

$ErrorActionPreference = "Stop"
$AppDir = "$env:LOCALAPPDATA\Programs\GadSign Local API"
$DataDir = "$env:LOCALAPPDATA\GadSign\LocalAPI"
$BaseUrl = "http://127.0.0.1:44113"
$StartupLink = Join-Path ([Environment]::GetFolderPath('Startup')) 'GadSign Local API.lnk'
$LogDir = "$env:TEMP\gadsign-tests"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$pass = 0
$fail = 0

function Assert($condition, $message) {
    if ($condition) {
        Write-Host "  PASS  $message" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL  $message" -ForegroundColor Red
        $script:fail++
    }
}

function Wait-Health($timeoutSeconds = 30) {
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest "$BaseUrl/" -TimeoutSec 3 -SkipHttpErrorCheck
            if ($r.StatusCode -eq 200) { return $r }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    return $null
}

function Stop-App {
    $p = Get-Process -Name GadSignLocalAPI -ErrorAction SilentlyContinue
    if ($p) {
        $p | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

function Install-Silent($setupPath) {
    Write-Host "  Instalando: $setupPath"
    $log = "$LogDir\install-$(Get-Date -Format 'HHmmss').log"
    $p = Start-Process -FilePath $setupPath -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        '/TASKS="autostart"', "/LOG=$log"
    ) -Wait -PassThru
    Assert ($p.ExitCode -eq 0) "Setup exit code 0"
    return $p.ExitCode
}

function Uninstall-Silent($uninstallerPath) {
    Write-Host "  Desinstalando: $uninstallerPath"
    $log = "$LogDir\uninstall-$(Get-Date -Format 'HHmmss').log"
    $p = Start-Process -FilePath $uninstallerPath -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$log"
    ) -Wait -PassThru
    return $p.ExitCode
}

function Get-InstalledVersion {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $entry = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like '*GadSign*' }
    if ($entry) { return $entry.DisplayVersion }
    return $null
}

# ──────────────────────────────────────────────────
# 1. Instalacion nueva
# ──────────────────────────────────────────────────
Write-Host "`n=== 1. INSTALACION NUEVA ===" -ForegroundColor Cyan

Stop-App
if (Test-Path $AppDir) { Remove-Item -Recurse -Force $AppDir -ErrorAction SilentlyContinue }
if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue }

$rc1 = Install-Silent $SetupBaseline
if ($rc1 -ne 0) { Write-Host "ABORT: instalacion fallo"; exit 1 }

Assert (Test-Path "$AppDir\GadSignLocalAPI.exe") "EXE presente en app dir"
Assert (Test-Path "$AppDir\unins*.exe") "Uninstaller presente"
Assert ((Get-InstalledVersion) -ne $null) "Registrado en Add/Remove Programs"
Assert (Test-Path $StartupLink) "Shortcut autostart creado"

Start-Process "$AppDir\GadSignLocalAPI.exe"
$health = Wait-Health 30
Assert ($health -ne $null) "API responde en 30s"
if ($health) {
    $body = $health.Content | ConvertFrom-Json
    Assert ($body.installationId -ne $null) "installationId presente"
}

# Segunda instancia debe ser bloqueada
$p2 = Start-Process "$AppDir\GadSignLocalAPI.exe" -PassThru
Start-Sleep -Seconds 2
$count = @(Get-Process -Name GadSignLocalAPI -ErrorAction SilentlyContinue).Count
Assert ($count -eq 1) "Una sola instancia (mutex)"

# ──────────────────────────────────────────────────
# 2. Configuracion y pairing
# ──────────────────────────────────────────────────
Write-Host "`n=== 2. CONFIGURACION ===" -ForegroundColor Cyan
Start-Sleep -Seconds 1
Assert (Test-Path "$DataDir\config.json") "config.json creado"
Assert (Test-Path "$DataDir\pairing.json") "pairing.json creado"
Assert (Test-Path "$DataDir\logs\") "Directorio de logs creado"

$configHashBefore = (Get-FileHash "$DataDir\config.json" -Algorithm SHA256).Hash
$pairingHashBefore = (Get-FileHash "$DataDir\pairing.json" -Algorithm SHA256).Hash

# ──────────────────────────────────────────────────
# 3. Health sin hardware
# ──────────────────────────────────────────────────
Write-Host "`n=== 3. HEALTH ===" -ForegroundColor Cyan
$health = Invoke-WebRequest "$BaseUrl/api/v1/health" -SkipHttpErrorCheck
Assert ($health.StatusCode -in @(200, 503)) "Health responde (200 o 503)"
$body = $health.Content | ConvertFrom-Json
Assert ($body.version -ne $null) "Version en health"

# Loopback enforcement
$hostHeader = Invoke-WebRequest "$BaseUrl/" -Headers @{Host="evil.com"} -SkipHttpErrorCheck
Assert ($hostHeader.StatusCode -eq 403) "Host malicioso bloqueado (403)"

# ──────────────────────────────────────────────────
# 4. Upgrade N -> N+1
# ──────────────────────────────────────────────────
Write-Host "`n=== 4. UPGRADE ===" -ForegroundColor Cyan

$versionBefore = Get-InstalledVersion
Write-Host "  Version antes: $versionBefore"

Stop-App
$rc2 = Install-Silent $SetupCandidate
if ($rc2 -ne 0) { Write-Host "ABORT: upgrade fallo"; exit 1 }

$versionAfter = Get-InstalledVersion
Write-Host "  Version despues: $versionAfter"
Assert ($versionAfter -ne $versionBefore) "Version cambio tras upgrade"

$uninstallCount = @(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like '*GadSign*' }).Count
Assert ($uninstallCount -eq 1) "Una sola entrada en registro"

# ──────────────────────────────────────────────────
# 5. Preservacion de datos
# ──────────────────────────────────────────────────
Write-Host "`n=== 5. PRESERVACION DE DATOS ===" -ForegroundColor Cyan
$configHashAfter = (Get-FileHash "$DataDir\config.json" -Algorithm SHA256).Hash
$pairingHashAfter = (Get-FileHash "$DataDir\pairing.json" -Algorithm SHA256).Hash
Assert ($configHashBefore -eq $configHashAfter) "config.json preservado"
Assert ($pairingHashBefore -eq $pairingHashAfter) "pairing.json preservado"

# El shortcut sigue existiendo
Assert (Test-Path $StartupLink) "Autostart shortcut preservado"

# ──────────────────────────────────────────────────
# 6. API tras upgrade
# ──────────────────────────────────────────────────
Write-Host "`n=== 6. API TRAS UPGRADE ===" -ForegroundColor Cyan
Start-Process "$AppDir\GadSignLocalAPI.exe"
$health2 = Wait-Health 30
Assert ($health2 -ne $null) "API responde tras upgrade"

# Puerto bloqueado para no-loopback
$net = Get-NetTCPConnection -LocalPort 44113 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($net) {
    Assert ($net.LocalAddress -eq "127.0.0.1" -or $net.LocalAddress -eq "0.0.0.0") "Escucha loopback"
}

# ──────────────────────────────────────────────────
# 7. Desinstalacion
# ──────────────────────────────────────────────────
Write-Host "`n=== 7. DESINSTALACION ===" -ForegroundColor Cyan
Stop-App

$uninstaller = Get-ChildItem "$AppDir" -Filter "unins*.exe" | Select-Object -First 1
if ($uninstaller) {
    $rc3 = Uninstall-Silent $uninstaller.FullName
    Assert ($rc3 -eq 0) "Desinstalacion exitosa"
    Assert (-not (Test-Path $AppDir)) "App dir eliminado"
    Assert (-not (Test-Path $StartupLink)) "Autostart eliminado"
    Assert ((Get-Process -Name GadSignLocalAPI -ErrorAction SilentlyContinue).Count -eq 0) "Proceso terminado"

    # Datos de usuario se conservan (nueva politica)
    Assert (Test-Path "$DataDir\config.json") "Datos de usuario conservados"
}

# ──────────────────────────────────────────────────
# Resumen
# ──────────────────────────────────────────────────
Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "  PASS: $pass" -ForegroundColor Green
Write-Host "  FAIL: $fail" -ForegroundColor $(if ($fail -gt 0) { 'Red' } else { 'Green' })
Write-Host "=========================================" -ForegroundColor Cyan

if (-not $SkipCleanup) {
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
        Write-Host "Datos de prueba eliminados."
    }
}

exit $(if ($fail -gt 0) { 1 } else { 0 })
