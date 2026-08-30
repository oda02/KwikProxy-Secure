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

!macro NSIS_HOOK_PREINSTALL
  !insertmacro KWIK_SECURE_REQUIRE_FIXED_INSTALL_ROOT

  ; In-place upgrade is intentionally disabled until a transactional updater
  ; can stage, verify, replace and roll back every protected binary as one unit.
  ; Never remove a known-good service before NSIS has safely committed files.
  ${If} ${FileExists} "${KWIK_SECURE_HELPER}"
    MessageBox MB_ICONSTOP "In-place upgrade is disabled for this security preview. The existing protected service was left untouched. Uninstall KwikProxy Secure explicitly, then run this installer as a clean install."
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
  nsExec::ExecToLog '"${KWIK_SECURE_HELPER}" install'
  Pop $0
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

  ${If} ${FileExists} "${KWIK_SECURE_HELPER}"
    DetailPrint "Removing the installer-managed KwikProxy Secure helper..."
    nsExec::ExecToLog '"${KWIK_SECURE_HELPER}" uninstall'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "The KwikProxy Secure helper could not be removed safely (exit $0). Uninstall is aborted before deleting privileged files."
      Abort
    ${EndIf}
  ${Else}
    ClearErrors
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\${KWIK_SECURE_SERVICE}" "ImagePath"
    ${IfNot} ${Errors}
      MessageBox MB_ICONSTOP "The KwikProxy Secure SYSTEM service still exists, but its protected helper binary is missing. Uninstall is aborted before deleting any remaining privileged files."
      Abort
    ${EndIf}
  ${EndIf}
  DeleteRegKey HKLM "SOFTWARE\KwikProxySecure"
!macroend
