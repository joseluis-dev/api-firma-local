; Inno Setup script template for GadSign Local API
; Build with Inno Setup 6.x
;   iscc installer/inno_setup.iss

#define MyAppName "GadSign Local API"
#define MyAppDisplayName "GadSign Local API"
#define MyAppVersion "1.0.0"
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

[Icons]
Name: "{userdesktop}\{#MyAppDisplayName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppDisplayName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: autostart

[Tasks]
Name: "desktopicon"; Description: "Crear acceso directo en el escritorio"; GroupDescription: "Accesos directos:"
Name: "autostart"; Description: "Iniciar GadSign Local API al iniciar sesion"; GroupDescription: "Inicio:";

[Run]
Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Description: "Iniciar GadSign Local API"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\GadSign\LocalAPI"
