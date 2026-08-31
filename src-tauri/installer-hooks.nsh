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
  ${If} ${FileExists} "$INSTDIR\*.*"
    MessageBox MB_ICONSTOP "The fixed KwikProxy Secure installation directory is not empty. Installation is aborted without executing or replacing its contents. Complete the prior uninstall (or have an administrator remove the verified stale directory), then retry."
    Abort
  ${EndIf}

  ClearErrors
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\${KWIK_SECURE_SERVICE}" "ImagePath"
  ${IfNot} ${Errors}
    MessageBox MB_ICONSTOP "A KwikProxy Secure SYSTEM service already exists. In-place upgrade/repair is disabled, so installation is aborted without changing it."
    Abort
  ${EndIf}

  ClearErrors
  ReadRegStr $0 HKLM "SOFTWARE\KwikProxySecure" "ManifestV1"
  ${IfNot} ${Errors}
    MessageBox MB_ICONSTOP "A KwikProxy Secure machine manifest already exists. In-place upgrade/repair is disabled; uninstall the prior installation explicitly first."
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
    nsExec::ExecToLog '"${KWIK_SECURE_HELPER}" uninstall'
    Pop $1
    DeleteRegKey HKLM "SOFTWARE\KwikProxySecure"
    ${If} $1 != 0
      MessageBox MB_ICONSTOP "Helper provisioning failed (exit $0), and rollback also failed (exit $1). Do not use this installation; inspect the service in an isolated test VM."
    ${Else}
      MessageBox MB_ICONSTOP "Helper provisioning failed safely (exit $0). The partial service registration was removed."
    ${EndIf}
    Abort
  ${EndIf}

  ; Restrict SCM control/reconfiguration to SYSTEM and local Administrators.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" sdset ${KWIK_SECURE_SERVICE} "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"'
  Pop $0
  ${If} $0 != 0
    nsExec::ExecToLog '"${KWIK_SECURE_HELPER}" uninstall'
    Pop $1
    DeleteRegKey HKLM "SOFTWARE\KwikProxySecure"
    ${If} $1 != 0
      MessageBox MB_ICONSTOP "Service ACL protection failed (exit $0), and rollback also failed (exit $1). Do not use this installation; inspect the service in an isolated test VM."
    ${Else}
      MessageBox MB_ICONSTOP "Service ACL protection failed safely (exit $0). The service was removed."
    ${EndIf}
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
    ClearErrors
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\${KWIK_SECURE_SERVICE}" "ImagePath"
    ${IfNot} ${Errors}
      MessageBox MB_ICONSTOP "The KwikProxy Secure SYSTEM service still exists, but its protected helper binary is missing. Uninstall is aborted before deleting any remaining privileged files."
      SetErrorLevel 2
      Abort
    ${EndIf}
  ${EndIf}
  DeleteRegKey HKLM "SOFTWARE\KwikProxySecure"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; The helper already verified/pruned the protected tree, and the stock Tauri
  ; template has now deleted uninstall.exe and attempted to remove $INSTDIR.
  ; Do not let an unchecked Delete/RMDir report success with a protected root
  ; (or any canonical payload) still present.
  System::Call 'kernel32::GetFileAttributesW(w "$INSTDIR") i.r3'
  ${If} $3 != -1
    MessageBox MB_ICONSTOP "KwikProxy Secure uninstall is incomplete because its protected installation directory still exists. Do not reinstall yet; retry uninstall with administrator rights."
    SetErrorLevel 2
    Abort
  ${EndIf}
!macroend
