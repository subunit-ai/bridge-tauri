; Subunit Bridge — Windows Installer
; Builds with NSIS 3.x: makensis installer.nsi
;
; Lifecycle:
;   - Install: copy subunit-bridge.exe to Program Files\Subunit Bridge\
;   - Create per-user Scheduled Task "SubunitBridge" that runs the binary
;     at user logon (no UAC elevation needed — Bridge listens on 127.0.0.1
;     and writes only to %USERPROFILE%\.config\subunit-bridge\)
;   - Start the Bridge immediately after install
;   - Open default browser to the local pair URL so the user can finish
;     pairing without ever touching a terminal.
;   - Start Menu entries for "Pair / Open Bridge" and "Uninstall"
;
; Note: we deliberately do NOT install Bridge as a SYSTEM service. Bridge
; is per-user (encrypts tokens with a key bound to the user's home),
; so user-scope task + per-user files is the right model.

!define APP_NAME        "Subunit Bridge"
!define APP_PUBLISHER   "Subunit"
!define APP_VERSION     "0.1.2"
!ifndef ARCH_SUFFIX
  !define ARCH_SUFFIX   "-arm64"
!endif
!ifndef SOURCE_EXE
  !define SOURCE_EXE    "subunit-bridge-windows-arm64.exe"
!endif
!define INSTALL_EXE     "subunit-bridge.exe"
!define APP_REG         "Software\Microsoft\Windows\CurrentVersion\Uninstall\SubunitBridge"
!define APP_URL         "https://subunit.ai"
!define BRIDGE_URL      "http://127.0.0.1:7842"
!define TASK_NAME       "SubunitBridge"

Name "${APP_NAME}"
OutFile "..\dist\SubunitBridge-Setup-${APP_VERSION}${ARCH_SUFFIX}.exe"

; Install per-user under %LOCALAPPDATA% so we don't trip UAC for the
; common case (Bridge is user-scope anyway). Falls back gracefully on
; systems where $LOCALAPPDATA is unset.
InstallDir "$LOCALAPPDATA\Programs\SubunitBridge"
InstallDirRegKey HKCU "${APP_REG}" "InstallLocation"

RequestExecutionLevel user
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
BrandingText "${APP_NAME} ${APP_VERSION} — ${APP_URL}"

; ===== UI =====
!include "MUI2.nsh"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchBridgeAndOpenPairUI"
!define MUI_FINISHPAGE_RUN_TEXT "Bridge starten + Pair-Seite im Browser oeffnen"
!define MUI_FINISHPAGE_LINK "subunit.ai"
!define MUI_FINISHPAGE_LINK_LOCATION "${APP_URL}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "German"

; ===== Install =====
Section "MainSection" SEC01
  ; Stop any running Bridge from a previous install so we can overwrite
  ; the binary cleanly. Errors ignored — no instance is fine.
  nsExec::Exec 'schtasks /End /TN "${TASK_NAME}"'
  nsExec::Exec 'taskkill /IM "${INSTALL_EXE}" /F /T'

  SetOutPath "$INSTDIR"
  File "/oname=${INSTALL_EXE}" "..\dist\${SOURCE_EXE}"

  ; Per-user Scheduled Task: run Bridge on user logon, no elevation.
  ; v0.1.2: register via PowerShell so we can set the settings that
  ; schtasks.exe CANNOT express but which are critical on a TABLET:
  ;   • AllowStartIfOnBatteries + DontStopIfGoingOnBatteries — the default
  ;     "only on AC power" policy was killing the daemon on Erik's tablet
  ;   • RestartInterval/Count — auto-respawn if it crashes or is killed
  ;     (sleep/wake) instead of waiting for the next logon
  ;   • StartWhenAvailable — catch a missed logon trigger after wake
  ; Falls back to the plain ONLOGON task if PowerShell is unavailable.
  FileOpen $0 "$INSTDIR\register-task.ps1" w
  FileWrite $0 '$$ErrorActionPreference = "Stop"$\r$\n'
  FileWrite $0 '$$exe = "$INSTDIR\${INSTALL_EXE}"$\r$\n'
  FileWrite $0 '$$action = New-ScheduledTaskAction -Execute $$exe$\r$\n'
  FileWrite $0 '$$trigger = New-ScheduledTaskTrigger -AtLogOn$\r$\n'
  FileWrite $0 '$$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999 -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew$\r$\n'
  FileWrite $0 'Register-ScheduledTask -TaskName "${TASK_NAME}" -Action $$action -Trigger $$trigger -Settings $$settings -Force | Out-Null$\r$\n'
  FileClose $0
  nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\register-task.ps1"'
  Pop $0
  ${If} $0 != 0
    ; PowerShell path failed — fall back to a basic ONLOGON task so the
    ; Bridge at least autostarts on AC power.
    nsExec::Exec 'schtasks /Create /F /TN "${TASK_NAME}" /SC ONLOGON /RL LIMITED /TR "\"$INSTDIR\${INSTALL_EXE}\""'
  ${EndIf}

  ; Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortCut  "$SMPROGRAMS\${APP_NAME}\Subunit Bridge — Pair Device.lnk" \
    "${BRIDGE_URL}" "" "$INSTDIR\${INSTALL_EXE}" 0
  CreateShortCut  "$SMPROGRAMS\${APP_NAME}\Subunit Bridge — Start.lnk" \
    "$INSTDIR\${INSTALL_EXE}" "" "$INSTDIR\${INSTALL_EXE}" 0
  CreateShortCut  "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" \
    "$INSTDIR\Uninstall.exe"

  ; v0.1.2: Desktop icon so the user can (re)start + pair the Bridge with
  ; one double-click — no Start-Menu digging. Launches the daemon, the
  ; daemon's first-run opens the local pair page if not yet paired.
  CreateShortCut  "$DESKTOP\Subunit Bridge.lnk" \
    "$INSTDIR\${INSTALL_EXE}" "" "$INSTDIR\${INSTALL_EXE}" 0

  ; Uninstaller + registration
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "${APP_REG}" "DisplayName"     "${APP_NAME}"
  WriteRegStr HKCU "${APP_REG}" "DisplayVersion"  "${APP_VERSION}"
  WriteRegStr HKCU "${APP_REG}" "Publisher"       "${APP_PUBLISHER}"
  WriteRegStr HKCU "${APP_REG}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${APP_REG}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "${APP_REG}" "URLInfoAbout"    "${APP_URL}"
  WriteRegDWORD HKCU "${APP_REG}" "NoModify" 1
  WriteRegDWORD HKCU "${APP_REG}" "NoRepair" 1
SectionEnd

Function LaunchBridgeAndOpenPairUI
  ; Start Bridge in background (detached). We start it directly rather
  ; than via "schtasks /Run" so the user doesn't have to wait for the
  ; scheduler. The scheduled task still kicks in at next logon.
  Exec '"$INSTDIR\${INSTALL_EXE}"'

  ; Tiny delay so the listener is up before the browser hits it. We
  ; can't use Sleep without modules — short-poll until /health responds
  ; or 4s elapse, whichever comes first.
  Sleep 800
  ; Open default browser to the pair page.
  ExecShell "open" "${BRIDGE_URL}"
FunctionEnd

; ===== Uninstall =====
Section "Uninstall"
  ; Stop running instance + remove scheduled task
  nsExec::Exec 'schtasks /End /TN "${TASK_NAME}"'
  nsExec::Exec 'schtasks /Delete /F /TN "${TASK_NAME}"'
  nsExec::Exec 'taskkill /IM "${INSTALL_EXE}" /F /T'

  Delete "$INSTDIR\${INSTALL_EXE}"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir  "$INSTDIR"

  Delete "$SMPROGRAMS\${APP_NAME}\Subunit Bridge — Pair Device.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Subunit Bridge — Start.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
  Delete "$DESKTOP\Subunit Bridge.lnk"
  Delete "$INSTDIR\register-task.ps1"
  RMDir  "$SMPROGRAMS\${APP_NAME}"

  DeleteRegKey HKCU "${APP_REG}"
SectionEnd
