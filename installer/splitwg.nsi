; SplitWG Windows Installer (NSIS)
;
; Installs splitwg.exe, splitwg-svc.exe, and wintun.dll to Program Files,
; registers the Windows Service, creates Start Menu shortcuts, registers
; the x-splitwg:// URL scheme, and adds an uninstaller entry.

!ifndef VERSION
  !define VERSION "dev"
!endif

!define PRODUCT_NAME "SplitWG"
!define PRODUCT_PUBLISHER "KilimcininKorOglu"
!define INSTALL_DIR "$PROGRAMFILES\${PRODUCT_NAME}"
!define SERVICE_NAME "splitwg"

Name "${PRODUCT_NAME} ${VERSION}"
OutFile "..\dist\SplitWG-Setup.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin

;--- Sections ---

Section "Install"
  SetOutPath "$INSTDIR"

  ; Stop existing service if running
  nsExec::ExecToLog 'sc stop ${SERVICE_NAME}'

  ; Copy binaries
  File "..\target\release\splitwg.exe"
  File "..\target\release\splitwg-svc.exe"
  File "..\target\release\wintun.dll"

  ; Install and start the service
  nsExec::ExecToLog 'sc create ${SERVICE_NAME} binPath= "$INSTDIR\splitwg-svc.exe" start= auto DisplayName= "SplitWG Tunnel Service"'
  nsExec::ExecToLog 'sc start ${SERVICE_NAME}'

  ; Create Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\splitwg.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  ; Register x-splitwg:// URL scheme
  WriteRegStr HKCU "Software\Classes\x-splitwg" "" "URL:SplitWG Protocol"
  WriteRegStr HKCU "Software\Classes\x-splitwg" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\x-splitwg\shell\open\command" "" '"$INSTDIR\splitwg.exe" "%1"'

  ; Add to auto-start (current user)
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "SplitWG" '"$INSTDIR\splitwg.exe"'

  ; Register uninstaller in Add/Remove Programs
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
    "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
    "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
    "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
    "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
    "DisplayVersion" "${VERSION}"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
    "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
    "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  ; Stop and remove service
  nsExec::ExecToLog 'sc stop ${SERVICE_NAME}'
  nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'

  ; Remove files
  Delete "$INSTDIR\splitwg.exe"
  Delete "$INSTDIR\splitwg-svc.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  ; Remove Start Menu
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"

  ; Remove URL scheme
  DeleteRegKey HKCU "Software\Classes\x-splitwg"

  ; Remove auto-start
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "SplitWG"

  ; Remove uninstaller registry
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd
