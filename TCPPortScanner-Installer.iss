; TCP Port Scanner Installer (64-bit)
; Place this file: C:\Users\BT\Desktop\Tcp Port Scanner\TCPPortScanner-Installer.iss
; NOTE: Make sure the Source path below points to the actual .exe file.
; If you used the PyInstaller command above, the EXE will be:
; C:\Users\BT\Desktop\Tcp Port Scanner\dist\TCPPortScanner.exe

[Setup]
AppName=TCP Port Scanner
AppVersion=1.5
DefaultDirName={autopf}\TCP Port Scanner
DefaultGroupName=TCP Port Scanner
UninstallDisplayIcon={app}\TCPPortScanner.exe
Compression=lzma2
SolidCompression=yes
OutputDir=.
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern

[Files]
; --- IMPORTANT: Ensure this Source path matches your built .exe (including .exe extension) ---
Source: "C:\Users\BT\Desktop\Tcp Port Scanner\dist\TCPPortScanner.exe"; DestDir: "{app}"; DestName: "TCPPortScanner.exe"; Flags: ignoreversion

[Icons]
; Start Menu shortcut
Name: "{group}\TCP Port Scanner"; Filename: "{app}\TCPPortScanner.exe"
; Desktop shortcut (optional) - user can choose in installer
Name: "{commondesktop}\TCP Port Scanner"; Filename: "{app}\TCPPortScanner.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
; Launch program after installation (post-install checkbox)
Filename: "{app}\TCPPortScanner.exe"; Description: "Launch TCP Port Scanner"; Flags: nowait postinstall skipifsilent




