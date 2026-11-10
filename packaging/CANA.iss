; Inno Setup script for CANA.
; Compile on Windows with Inno Setup after building the onedir CANA folder.

#define MyAppName "CANA"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "CANA Project"
#define MyAppExeName "CANA.exe"

[Setup]
AppId={{9C3A1B7E-4D2F-4A11-9B8E-CANA00000001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\CANA
DefaultGroupName=CANA
DisableProgramGroupPage=no
OutputDir=output
OutputBaseFilename=CANA-Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=CANA Network Monitor
WizardStyle=modern
SetupIconFile=..\cana_ui\assets\cana.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "dist\CANA\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "resolve-installer-sid.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\CANA"
Name: "{commonappdata}\CANA\logs"
Name: "{commonappdata}\CANA\sessions"

[Icons]
Name: "{group}\CANA"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--ui"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall CANA"; Filename: "{uninstallexe}"
Name: "{autodesktop}\CANA"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--ui"; Tasks: desktopicon; IconFilename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--ui"; Description: "Open CANA"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveCANAService"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -Command "$ErrorActionPreference = ''Stop''; ' +
    '$s = Get-Service CANA -ErrorAction SilentlyContinue; if ($s) { ' +
    'Stop-Service CANA -Force; $s.WaitForStatus(''Stopped'', [TimeSpan]::FromSeconds(30)); $s.Dispose() }; exit 0"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := 'Could not stop CANA before updating its files.'
  else if ResultCode <> 0 then
    Result := 'CANA did not stop. Close CANA and retry setup.';
end;

{ An interactive account SID has the shape S-1-5-21-<a>-<b>-<c>-<rid>.
  Return True only for that exact shape. A bare prefix test is not
  enough: 'S-1-5-21' is eight characters, so 'Copy(Result, 1, 7)' never
  matches it and a malformed value such as 'S-1-5-21BAD' would slip
  through an eight-character prefix check. }
function IsValidInstallerSid(Value: String): Boolean;
var
  Body: String;
  I: Integer;
  Ch: Char;
  DashCount: Integer;
begin
  Result := False;
  Value := Trim(Value);
  if Copy(Value, 1, 9) <> 'S-1-5-21-' then
    exit;
  Body := Copy(Value, 10, Length(Value) - 9);
  if Body = '' then
    exit;
  DashCount := 0;
  for I := 1 to Length(Body) do
  begin
    Ch := Body[I];
    if Ch = '-' then
      DashCount := DashCount + 1
    else if (Ch < '0') or (Ch > '9') then
      exit;
  end;
  { Three further dashes: <a>-<b>-<c>-<rid>. }
  Result := DashCount = 3;
end;

function GetInstallerUserSid(Param: String): String;
var
  TmpFile: String;
  ResultCode: Integer;
  Data: AnsiString;
begin
  { Logged-on interactive user (explorer owner), not the elevated token. }
  TmpFile := ExpandConstant('{tmp}\cana-installer-user.sid');
  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\resolve-installer-sid.ps1') + '" -OutFile "' + TmpFile + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Could not launch the SID resolver. Installation aborted.');
  if (ResultCode <> 0) or (not LoadStringFromFile(TmpFile, Data)) then
  begin
    RaiseException('Could not determine the installing user SID. Installation aborted.');
  end;
  Result := Trim(String(Data));
  if not IsValidInstallerSid(Result) then
    RaiseException('Installer SID is not a valid unelevated user SID. Installation aborted.');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Params: String;
begin
  if CurStep = ssPostInstall then
  begin
    Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
      ExpandConstant('{app}\install.ps1') + '" -InstallDir "' +
      ExpandConstant('{app}') + '" -InstallerSid "' + GetInstallerUserSid('') + '"';
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      RaiseException('Could not start service setup. Installation aborted.');
    if ResultCode <> 0 then
      RaiseException('CANA service setup failed. See ' +
        ExpandConstant('{commonappdata}\CANA\logs\install.log'));
  end;
end;
