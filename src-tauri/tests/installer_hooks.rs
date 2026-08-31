const HOOKS: &str = include_str!("../installer-hooks.nsh");

fn macro_body(name: &str) -> &'static str {
    let start_marker = format!("!macro {name}");
    let start = HOOKS
        .find(&start_marker)
        .unwrap_or_else(|| panic!("missing NSIS macro {name}"));
    let rest = &HOOKS[start..];
    let end = rest
        .find("!macroend")
        .unwrap_or_else(|| panic!("unterminated NSIS macro {name}"));
    &rest[..end]
}

#[test]
fn clean_install_guard_still_rejects_existing_protected_state() {
    let preinstall = macro_body("NSIS_HOOK_PREINSTALL");
    assert!(preinstall.contains("${FileExists} \"${KWIK_SECURE_HELPER}\""));
    assert!(preinstall.contains("${FileExists} \"$INSTDIR\\*.*\""));
    assert!(preinstall.contains("SYSTEM\\CurrentControlSet\\Services\\${KWIK_SECURE_SERVICE}"));
    assert!(preinstall.contains("SOFTWARE\\KwikProxySecure"));
    assert!(preinstall.contains("ManifestV1"));
}

#[test]
fn uninstall_checks_app_before_mutating_privileged_state() {
    let preuninstall = macro_body("NSIS_HOOK_PREUNINSTALL");
    let app_check = preuninstall
        .find("CheckIfAppIsRunning")
        .expect("missing early running-app gate");
    let helper_call = preuninstall
        .find("uninstall-for-installer")
        .expect("missing installer-only protected cleanup");
    let manifest_delete = preuninstall
        .find("DeleteRegKey HKLM \"SOFTWARE\\KwikProxySecure\"")
        .expect("missing manifest cleanup");
    assert!(app_check < helper_call);
    assert!(helper_call < manifest_delete);
    assert!(preuninstall.contains("KWIK_SECURE_DELETE_HELPER_BOUNDED"));
}

#[test]
fn uninstall_cannot_succeed_with_protected_install_root_left_behind() {
    let postuninstall = macro_body("NSIS_HOOK_POSTUNINSTALL");
    assert!(postuninstall.contains("GetFileAttributesW"));
    assert!(postuninstall.contains("$INSTDIR"));
    assert!(postuninstall.contains("SetErrorLevel 2"));
    assert!(postuninstall.contains("Abort"));

    let bounded_delete = macro_body("KWIK_SECURE_DELETE_HELPER_BOUNDED");
    assert!(bounded_delete.contains("Delete \"${KWIK_SECURE_HELPER}\""));
    assert!(bounded_delete.contains("${FileExists} \"${KWIK_SECURE_HELPER}\""));
    assert!(!bounded_delete.contains("/REBOOTOK"));
    assert!(!bounded_delete.contains("RMDir /r"));
}
