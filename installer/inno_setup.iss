; Inno Setup script template for GadSign Local API
; Build with Inno Setup 6.x
;   iscc /DMyAppVersion=1.0.1 installer/inno_setup.iss
;
; Para firmar digitalmente (requiere certificado de code signing):
;   iscc /DSignInstaller /DMyAppVersion=1.0.1 installer/inno_setup.iss
;   Esto usa el SignTool "signtool" que debe configurarse previamente
;   (certificado en Windows Store con /sha1, o PFX con /p %CODESIGN_PASSWORD%).

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

#define MyAppName "GadSign Local API"
#define MyAppDisplayName "GadSign Local API"
#define MyAppPublisher "GadSign / Salcedo"
#define MyAppURL "https://www.salcedo.gob.ec/"
#define MyAppExeName "GadSignLocalAPI.exe"
#define MyAppCopyright "(c) 2026"

[Setup]
AppId={{A4F1A9B2-5C7C-4E4A-8E1C-9B5C9A0F1B2D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppCopyright={#MyAppCopyright}
AppMutex=Local\GadSignLocalAPI
VersionInfoVersion={#MyAppVersion}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoCopyright={#MyAppCopyright}
#ifdef SignInstaller
SignTool=signtool
SignedUninstaller=yes
#else
SignedUninstaller=no
#endif
DefaultDirName={localappdata}\Programs\{#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=no
OutputDir=output
OutputBaseFilename=GadSignLocalAPI-{#MyAppVersion}-setup
SetupIconFile=..\resources\gadsign.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "..\installer\dist\GadSignLocalAPI\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{userdesktop}\{#MyAppDisplayName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppDisplayName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: autostart

[Tasks]
Name: "desktopicon"; Description: "Crear acceso directo en el escritorio"; GroupDescription: "Accesos directos:"
Name: "autostart"; Description: "Iniciar GadSign Local API al iniciar sesion"; GroupDescription: "Inicio:";

[Run]
Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Description: "Iniciar GadSign Local API"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\*.pyc"

[Code]
function _version_tuple(const S: String): array of Integer;
var
  i, start, dot: Integer;
  v: String;
begin
  SetArrayLength(Result, 3);
  Result[0] := 0; Result[1] := 0; Result[2] := 0;
  if S = '' then Exit;
  start := 1;
  for i := 0 to 2 do
  begin
    dot := Pos('.', Copy(S, start, Length(S)));
    if dot = 0 then
      v := Copy(S, start, Length(S))
    else
      v := Copy(S, start, dot - 1);
    if v <> '' then
    begin
      try
        Result[i] := StrToInt(v);
      except
        Result[i] := 0;
      end;
    end;
    if dot = 0 then Break;
    start := start + dot;
  end;
end;

function _compare_versions(const A, B: String): Integer;
var
  va, vb: array of Integer;
  i: Integer;
begin
  va := _version_tuple(A);
  vb := _version_tuple(B);
  for i := 0 to 2 do
  begin
    if va[i] < vb[i] then begin Result := -1; Exit; end;
    if va[i] > vb[i] then begin Result := 1; Exit; end;
  end;
  Result := 0;
end;

function InitializeSetup(): Boolean;
var
  installedVersion: String;
begin
  Result := True;
  if not RegQueryStringValue(
    HKCU,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#emit SetupSetting("AppId")}_is1',
    'DisplayVersion',
    installedVersion
  ) then
    Exit;
  if installedVersion = '' then Exit;
  if _compare_versions('{#MyAppVersion}', installedVersion) < 0 then
  begin
    MsgBox(
      'Ya existe una version mas reciente (' + installedVersion + '). Desinstalela antes de instalar esta version (' + '{#MyAppVersion}' + ').',
      mbError, MB_OK
    );
    Result := False;
    Exit;
  end;
end;
