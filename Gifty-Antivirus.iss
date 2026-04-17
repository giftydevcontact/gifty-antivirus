; Gifty-Antivirus.iss - Inno Setup 6 script
; Produces: Gifty-Antivirus-PREMIUM-Setup.exe

[Setup]
AppName=Gifty Antivirus PREMIUM
AppVersion=4.0
AppVerName=Gifty Antivirus PREMIUM v4.0
AppPublisher=Gifty Software
DefaultDirName={autopf}\Gifty Antivirus PREMIUM
DefaultGroupName=Gifty Antivirus PREMIUM
OutputBaseFilename=Gifty-Antivirus-PREMIUM-Setup
OutputDir=.
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardResizable=no
LicenseFile=License.txt
PrivilegesRequired=admin
MinVersion=10.0
VersionInfoVersion=4.0.0.0
VersionInfoCompany=Gifty Software
VersionInfoDescription=Gifty Antivirus PREMIUM Installer
VersionInfoProductName=Gifty Antivirus PREMIUM
VersionInfoProductVersion=4.0.0.0
UninstallDisplayName=Gifty Antivirus PREMIUM
AppMutex=GiftyAntivirusInstaller
SetupIconFile=GiftAntivirusIcon.ico
UninstallDisplayIcon={app}\GiftAntivirusIcon.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "gifty_av.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "launcher.vbs"; DestDir: "{app}"; DestName: "Launch-Gifty-Antivirus.vbs"; Flags: ignoreversion
Source: "License.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "GiftAntivirusIcon.png"; DestDir: "{app}"; Flags: ignoreversion
Source: "GiftAntivirusIcon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Gifty Antivirus PREMIUM"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-Gifty-Antivirus.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\GiftAntivirusIcon.ico"; Comment: "Launch Gifty Antivirus PREMIUM"
Name: "{group}\Uninstall Gifty Antivirus PREMIUM"; Filename: "{uninstallexe}"
Name: "{commondesktop}\Gifty Antivirus PREMIUM"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-Gifty-Antivirus.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\GiftAntivirusIcon.ico"; Comment: "Launch Gifty Antivirus PREMIUM"

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{app}\Launch-Gifty-Antivirus.vbs"""; Description: "Launch Gifty Antivirus PREMIUM"; Flags: nowait postinstall skipifsilent

[Code]

// ── Python detection ──────────────────────────────────────────────────────
function FindPythonW: string;
var
  KeyNames: TArrayOfString;
  i: Integer;
  InstallPath, Candidate: string;
  Roots: array[0..1] of Integer;
  r: Integer;
begin
  Result := '';
  Roots[0] := HKLM;
  Roots[1] := HKCU;

  for r := 0 to 1 do
  begin
    if RegGetSubkeyNames(Roots[r], 'SOFTWARE\Python\PythonCore', KeyNames) then
    begin
      for i := 0 to GetArrayLength(KeyNames) - 1 do
      begin
        InstallPath := '';
        if RegQueryStringValue(Roots[r],
            'SOFTWARE\Python\PythonCore\' + KeyNames[i] + '\InstallPath',
            'ExecutablePath', InstallPath) then
        begin
          Candidate := ExtractFilePath(InstallPath) + 'pythonw.exe';
          if FileExists(Candidate) then
          begin
            Result := Candidate;
            Exit;
          end;
        end
        else if RegQueryStringValue(Roots[r],
            'SOFTWARE\Python\PythonCore\' + KeyNames[i] + '\InstallPath',
            '', InstallPath) then
        begin
          Candidate := AddBackslash(InstallPath) + 'pythonw.exe';
          if FileExists(Candidate) then
          begin
            Result := Candidate;
            Exit;
          end;
        end;
      end;
    end;
  end;
end;

function PythonIsInstalled: Boolean;
begin
  Result := (FindPythonW <> '');
end;

// ── Download & silently install Python 3.12 ──────────────────────────────
procedure DownloadAndInstallPython;
var
  DLUrl, InstallerPath, PSCmd, Params: string;
  ResultCode: Integer;
begin
  DLUrl         := 'https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe';
  InstallerPath := ExpandConstant('{tmp}\python-installer.exe');

  WizardForm.StatusLabel.Caption := 'Downloading Python 3.12 — this may take a moment...';
  Log('Downloading Python from: ' + DLUrl);

  PSCmd :=
    '-NoProfile -NonInteractive -WindowStyle Hidden -Command ' +
    '"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ' +
    'Invoke-WebRequest -Uri ''' + DLUrl + ''' -OutFile ''' + InstallerPath + '''"';

  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
       PSCmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if not FileExists(InstallerPath) then
  begin
    MsgBox(
      'Could not download Python automatically.' + #13#10 + #13#10 +
      'Please install Python 3.12 manually from:' + #13#10 +
      'https://www.python.org/downloads/' + #13#10 + #13#10 +
      'Tick "Add Python to PATH" during install, then re-launch Gifty Antivirus.',
      mbError, MB_OK);
    Log('Python download failed — file not found after download attempt.');
    Exit;
  end;

  Log('Download complete. Running silent install...');
  WizardForm.StatusLabel.Caption := 'Installing Python 3.12 — please wait (~30 seconds)...';

  Params := '/quiet InstallAllUsers=0 PrependPath=1 IncludePip=1 SimpleInstall=1';
  Exec(InstallerPath, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if ResultCode = 0 then
  begin
    Log('Python 3.12 installed successfully.');
    WizardForm.StatusLabel.Caption := 'Python 3.12 installed.';
  end
  else
  begin
    Log('Python installer exited with code: ' + IntToStr(ResultCode));
    MsgBox(
      'Python installed with exit code ' + IntToStr(ResultCode) + '.' + #13#10 +
      'If Gifty Antivirus does not launch, install Python 3.12 manually from' + #13#10 +
      'https://www.python.org/downloads/ and tick "Add Python to PATH".',
      mbInformation, MB_OK);
  end;
end;

// ── Write a path hint file so the launcher knows exactly where pythonw is ─
procedure WritePythonPathHint(PythonWPath: string);
begin
  SaveStringToFile(ExpandConstant('{app}\python_path.txt'), PythonWPath, False);
  Log('Wrote python path hint: ' + PythonWPath);
end;

// ── Main hook ─────────────────────────────────────────────────────────────
procedure CurStepChanged(CurStep: TSetupStep);
var
  PythonWPath: string;
begin
  if CurStep = ssPostInstall then
  begin
    PythonWPath := FindPythonW;

    if PythonWPath = '' then
    begin
      Log('Python not found — downloading and installing automatically...');
      DownloadAndInstallPython;
      PythonWPath := FindPythonW;
      if PythonWPath = '' then
      begin
        // Registry may not have refreshed yet; write the default per-user install path
        PythonWPath :=
          ExpandConstant('{localappdata}') + '\Programs\Python\Python312\pythonw.exe';
        Log('Registry not refreshed yet; using default hint: ' + PythonWPath);
      end;
    end
    else
      Log('Python already present at: ' + PythonWPath);

    WritePythonPathHint(PythonWPath);
  end;
end;
