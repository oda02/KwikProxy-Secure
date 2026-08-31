; KwikProxy Secure privileged installation contract.
;
; The per-machine installer is the only lifecycle owner. The helper validates
; its exact Program Files location, provisions ProgramData through no-follow
; Windows handle APIs, writes the protected HKLM manifest, and performs bounded
; SCM polling. No user-writable path, recursive ACL command, fixed sleep, or
; image-name process kill is used here.
;
; Upstream/legacy services and data are deliberately untouched. Migration is a
; separate, explicit operation after the secure installation succeeds.

!define KWIK_SECURE_SERVICE "KwikProxySecureHelper"
!define KWIK_SECURE_INSTALL_ROOT "$PROGRAMFILES64\KwikProxy Secure"
!define KWIK_SECURE_HELPER "$INSTDIR\kwik-helper-x86_64-pc-windows-msvc.exe"

!macro KWIK_SECURE_REQUIRE_FIXED_INSTALL_ROOT
  ; The reviewed helper is a native x64 binary and owns the 64-bit HKLM view.
  SetRegView 64
  ${If} "$INSTDIR" != "${KWIK_SECURE_INSTALL_ROOT}"
    MessageBox MB_ICONSTOP "KwikProxy Secure must be installed at ${KWIK_SECURE_INSTALL_ROOT}. Custom install paths are disabled because the SYSTEM helper trusts this protected location."
    Abort
  ${EndIf}
!macroend

; The helper process has exited when nsExec returns, but antivirus/indexing can
; briefly retain a sharing handle. Retry only the one canonical executable and
; fail closed if it is still present. Never queue deletion for reboot: a
; successful uninstall must leave the next clean install unambiguously safe.
!macro KWIK_SECURE_DELETE_HELPER_BOUNDED RESULT
  StrCpy ${RESULT} 1
  StrCpy $3 0
  ${Do}
    ClearErrors
    Delete "${KWIK_SECURE_HELPER}"
    ${IfNot} ${FileExists} "${KWIK_SECURE_HELPER}"
      StrCpy ${RESULT} 0
      ${ExitDo}
    ${EndIf}
    IntOp $3 $3 + 1
    ${If} $3 >= 20
      ${ExitDo}
    ${EndIf}
    Sleep 100
  ${Loop}
!macroend

; SetOutPath creates the fixed root before PREINSTALL. Enumerate it explicitly:
; NSIS wildcard existence checks also match `.`/`..` and therefore
; rejects a genuinely empty directory. This macro ignores only those two exact
; names, bounds iteration, and closes every valid search handle. A FindFirst
; error remains fail-closed; FindNext's documented error flag ends a valid
; enumeration without consulting the volatile Win32 last-error slot.
!macro KWIK_SECURE_CHECK_INSTALL_ROOT_EMPTY RESULT
  StrCpy ${RESULT} 1
  ClearErrors
  FindFirst $0 $1 "$INSTDIR\*"
  ${IfNot} ${Errors}
    StrCpy ${RESULT} 0
    StrCpy $2 0
    ${Do}
      ${If} "$1" != "."
      ${AndIf} "$1" != ".."
        StrCpy ${RESULT} 1
        ${ExitDo}
      ${EndIf}
      IntOp $2 $2 + 1
      ${If} $2 >= 512
        StrCpy ${RESULT} 1
        ${ExitDo}
      ${EndIf}
      ClearErrors
      FindNext $0 $1
      ${If} ${Errors}
        ${ExitDo}
      ${EndIf}
    ${Loop}
    FindClose $0
  ${EndIf}
!macroend

; If helper provisioning failed before it could protect the root/write the
; manifest, the strict installer-only cleanup identity intentionally does not
; exist. Recovery is still safe after independently proving that neither SCM
; nor the 64-bit manifest key contains privileged state: delete only the exact
; helper name and retain the registered uninstaller for stock file cleanup.
!macro KWIK_SECURE_RECOVER_UNPROVISIONED_INSTALL RESULT
  StrCpy ${RESULT} 1
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query ${KWIK_SECURE_SERVICE}'
  Pop $5
  Pop $9
  ${If} $5 == 1060
    System::Call 'advapi32::RegOpenKeyExW(p 0x80000002, w "SOFTWARE\KwikProxySecure", i 0, i 0x20119, *p .r7) i.r6'
    ${If} $6 == 2
    ${OrIf} $6 == 3
      !insertmacro KWIK_SECURE_DELETE_HELPER_BOUNDED ${RESULT}
    ${ElseIf} $6 == 0
      System::Call 'advapi32::RegCloseKey(p r7) i.r8'
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro KWIK_SECURE_REQUIRE_FIXED_INSTALL_ROOT

  ; In-place upgrade is intentionally disabled until a transactional updater
  ; can stage, verify, replace and roll back every protected binary as one unit.
  ; Never remove a known-good service before NSIS has safely committed files.
  ${If} ${FileExists} "${KWIK_SECURE_HELPER}"
    MessageBox MB_ICONSTOP "In-place upgrade is disabled for this security preview. The existing protected service was left untouched. Uninstall KwikProxy Secure explicitly, then run this installer as a clean install."
    Abort
  ${EndIf}

  ; SetOutPath has created an empty directory for a genuinely clean install.
  ; Any entry here is therefore stale/partial protected state. Do not merge a
  ; new trusted payload into it or execute anything found there.
  !insertmacro KWIK_SECURE_CHECK_INSTALL_ROOT_EMPTY $3
  ${If} $3 != 0
    MessageBox MB_ICONSTOP "The fixed KwikProxy Secure installation directory is not empty. Installation is aborted without executing or replacing its contents. Complete the prior uninstall (or have an administrator remove the verified stale directory), then retry."
    Abort
  ${EndIf}

  ; Query SCM itself so a corrupt service key with a missing ImagePath cannot
  ; be mistaken for absence. Only ERROR_SERVICE_DOES_NOT_EXIST (1060) is the
  ; clean-install case; access/query failures abort fail-closed.
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query ${KWIK_SECURE_SERVICE}'
  Pop $0
  Pop $2
  ${If} $0 == 0
    MessageBox MB_ICONSTOP "A KwikProxy Secure SYSTEM service already exists. In-place upgrade/repair is disabled, so installation is aborted without changing it."
    Abort
  ${EndIf}
  ${If} $0 != 1060
    MessageBox MB_ICONSTOP "The installer could not prove that the KwikProxy Secure SYSTEM service is absent (SCM query exit $0). Installation is aborted without changing machine state."
    Abort
  ${EndIf}

  ; Detect the HKLM key independent of ManifestV1 value type/readability.
  System::Call 'advapi32::RegOpenKeyExW(p 0x80000002, w "SOFTWARE\KwikProxySecure", i 0, i 0x20119, *p .r1) i.r0'
  ${If} $0 == 0
    System::Call 'advapi32::RegCloseKey(p r1) i.r2'
    MessageBox MB_ICONSTOP "A KwikProxy Secure machine manifest already exists. In-place upgrade/repair is disabled; uninstall the prior installation explicitly first."
    Abort
  ${EndIf}
  ${If} $0 != 2
  ${AndIf} $0 != 3
    MessageBox MB_ICONSTOP "The installer could not prove that the KwikProxy Secure machine manifest key is absent (registry query error $0). Installation is aborted."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro KWIK_SECURE_REQUIRE_FIXED_INSTALL_ROOT

  DetailPrint "Provisioning the protected KwikProxy Secure helper service..."
  nsExec::ExecToStack '"${KWIK_SECURE_HELPER}" install'
  Pop $0
  Pop $2
  DetailPrint "$2"
  ${If} $0 != 0
    ; Best-effort rollback uses the same canonical helper and bounded SCM path.
    ; The rollback result is checked and reported; nothing is silently ignored.
    nsExec::ExecToLog '"${KWIK_SECURE_HELPER}" uninstall-for-installer'
    Pop $1
    ${If} $1 == 0
      !insertmacro KWIK_SECURE_DELETE_HELPER_BOUNDED $4
      ${If} $4 != 0
        StrCpy $1 $4
      ${EndIf}
    ${Else}
      !insertmacro KWIK_SECURE_RECOVER_UNPROVISIONED_INSTALL $4
      ${If} $4 == 0
        StrCpy $1 0
      ${EndIf}
    ${EndIf}
    ${If} $1 != 0
      MessageBox MB_ICONSTOP "Helper provisioning failed (exit $0), and rollback also failed (exit $1). Do not use this installation; inspect the service in an isolated test VM."
    ${Else}
      MessageBox MB_ICONSTOP "Helper provisioning failed safely (exit $0). No SYSTEM service or exact helper remains; the registered uninstaller was retained to remove remaining files and any protected recovery metadata."
    ${EndIf}
    SetErrorLevel 2
    Abort
  ${EndIf}

  ; Restrict SCM control/reconfiguration to SYSTEM and local Administrators.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" sdset ${KWIK_SECURE_SERVICE} "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"'
  Pop $0
  ${If} $0 != 0
    nsExec::ExecToLog '"${KWIK_SECURE_HELPER}" uninstall-for-installer'
    Pop $1
    ${If} $1 == 0
      !insertmacro KWIK_SECURE_DELETE_HELPER_BOUNDED $4
      ${If} $4 != 0
        StrCpy $1 $4
      ${EndIf}
    ${Else}
      !insertmacro KWIK_SECURE_RECOVER_UNPROVISIONED_INSTALL $4
      ${If} $4 == 0
        StrCpy $1 0
      ${EndIf}
    ${EndIf}
    ${If} $1 != 0
      MessageBox MB_ICONSTOP "Service ACL protection failed (exit $0), and rollback also failed (exit $1). Do not use this installation; inspect the service in an isolated test VM."
    ${Else}
      MessageBox MB_ICONSTOP "Service ACL protection failed safely (exit $0). No SYSTEM service or exact helper remains; the registered uninstaller was retained to remove remaining files and any protected recovery metadata."
    ${EndIf}
    SetErrorLevel 2
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro KWIK_SECURE_REQUIRE_FIXED_INSTALL_ROOT

  ; Tauri invokes PREUNINSTALL before its own running-app check. Run the same
  ; gate before removing SCM/manifest state; the later template check remains
  ; useful as a race re-check.
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  ${If} ${FileExists} "${KWIK_SECURE_HELPER}"
    DetailPrint "Removing the installer-managed KwikProxy Secure helper..."
    ; This installer-only command first removes SCM/ProgramData state, then
    ; prunes the handle-verified fixed Program Files tree without following
    ; reparse points. It intentionally hands only itself and uninstall.exe
    ; back to NSIS.
    nsExec::ExecToLog '"${KWIK_SECURE_HELPER}" uninstall-for-installer'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "The KwikProxy Secure helper could not be removed safely (exit $0). Uninstall is aborted before deleting privileged files."
      SetErrorLevel 2
      Abort
    ${EndIf}

    !insertmacro KWIK_SECURE_DELETE_HELPER_BOUNDED $1
    ${If} $1 != 0
      MessageBox MB_ICONSTOP "The protected KwikProxy Secure helper is still in use. Uninstall did not complete; close security/indexing tools that may hold the file and retry."
      SetErrorLevel 2
      Abort
    ${EndIf}
  ${Else}
    nsExec::ExecToStack '"$SYSDIR\sc.exe" query ${KWIK_SECURE_SERVICE}'
    Pop $0
    Pop $2
    ${If} $0 == 0
      MessageBox MB_ICONSTOP "The KwikProxy Secure SYSTEM service still exists, but its protected helper binary is missing. Uninstall is aborted before deleting any remaining privileged files."
      SetErrorLevel 2
      Abort
    ${EndIf}
    ${If} $0 != 1060
      MessageBox MB_ICONSTOP "Uninstall could not prove that the KwikProxy Secure SYSTEM service is absent (SCM query exit $0). No remaining protected files were deleted."
      SetErrorLevel 2
      Abort
    ${EndIf}
  ${EndIf}
  DeleteRegKey HKLM "SOFTWARE\KwikProxySecure"
  System::Call 'advapi32::RegOpenKeyExW(p 0x80000002, w "SOFTWARE\KwikProxySecure", i 0, i 0x20119, *p .r1) i.r0'
  ${If} $0 == 0
    System::Call 'advapi32::RegCloseKey(p r1) i.r2'
    MessageBox MB_ICONSTOP "The protected machine manifest could not be removed. Uninstall is aborted before the stock file/registration cleanup so the failure can be retried safely."
    SetErrorLevel 2
    Abort
  ${EndIf}
  ${If} $0 != 2
  ${AndIf} $0 != 3
    MessageBox MB_ICONSTOP "Uninstall could not verify machine-manifest removal (registry query error $0). Stock file/registration cleanup is aborted fail-closed."
    SetErrorLevel 2
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; The helper already verified/pruned the protected tree, and the stock Tauri
  ; template has now deleted uninstall.exe and attempted to remove $INSTDIR.
  ; Do not let an unchecked Delete/RMDir report success with a protected root
  ; (or any canonical payload) still present.
  ; Retry removal of an empty exact root after stock NSIS cleanup. If an empty
  ; directory remains harmlessly locked, it is safe for the next SetOutPath;
  ; only remaining entries are an uninstall failure.
  StrCpy $3 0
  ${Do}
    RMDir "$INSTDIR"
    System::Call 'kernel32::GetFileAttributesW(w "$INSTDIR") i.r4'
    ${If} $4 == -1
      ${ExitDo}
    ${EndIf}
    IntOp $3 $3 + 1
    ${If} $3 >= 20
      ${ExitDo}
    ${EndIf}
    Sleep 100
  ${Loop}
  System::Call 'kernel32::GetFileAttributesW(w "$INSTDIR") i.r4'
  ${If} $4 != -1
    !insertmacro KWIK_SECURE_CHECK_INSTALL_ROOT_EMPTY $5
    ${If} $5 != 0
      MessageBox MB_ICONSTOP "KwikProxy Secure uninstall is incomplete because its protected installation directory still contains files. Do not reinstall yet; retry uninstall with administrator rights."
      SetErrorLevel 2
      Abort
    ${EndIf}
  ${EndIf}
!macroend
