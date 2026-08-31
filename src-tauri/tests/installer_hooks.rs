const HOOKS: &str = include_str!("../installer-hooks.nsh");
const SECURITY: &str = include_str!("../src/bin/kwik_helper/security.rs");
const SERVICE: &str = include_str!("../src/bin/kwik_helper/service.rs");

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

fn modeled_root_is_dirty(entries: &[&str]) -> bool {
    entries.iter().any(|name| *name != "." && *name != "..")
}

#[test]
fn clean_install_guard_still_rejects_existing_protected_state() {
    let preinstall = macro_body("NSIS_HOOK_PREINSTALL");
    assert!(preinstall.contains("${FileExists} \"${KWIK_SECURE_HELPER}\""));
    assert!(preinstall.contains("KWIK_SECURE_CHECK_INSTALL_ROOT_EMPTY"));
    assert!(preinstall.contains("$SYSDIR\\sc.exe\" query ${KWIK_SECURE_SERVICE}"));
    assert!(preinstall.contains("$0 != 1060"));
    assert!(preinstall.contains("RegOpenKeyExW"));
    assert!(preinstall.contains("0x20119"));
    assert!(preinstall.contains("SOFTWARE\\KwikProxySecure"));
}

#[test]
fn explicit_root_enumeration_accepts_only_dot_entries() {
    assert!(!modeled_root_is_dirty(&[]));
    assert!(!modeled_root_is_dirty(&[".", ".."]));
    assert!(modeled_root_is_dirty(&[".", "..", "uninstall.exe"]));

    let check = macro_body("KWIK_SECURE_CHECK_INSTALL_ROOT_EMPTY");
    assert!(check.contains("FindFirst"));
    assert!(check.contains("FindNext"));
    assert!(check.contains("FindClose"));
    assert!(check.contains("\"$1\" != \".\""));
    assert!(check.contains("\"$1\" != \"..\""));
    assert!(check.contains("$2 >= 512"));
    assert!(check.contains("${IfNot} ${Errors}"));
    let next = check.find("FindNext $0 $1").expect("missing FindNext");
    assert!(check[next..].contains("${If} ${Errors}"));
    assert_eq!(check.matches("FindFirst").count(), 1);
    assert_eq!(check.matches("FindClose").count(), 1);
    assert!(!check.contains("GetLastError"));
    assert!(!check.contains("System::Call"));
    assert!(!check.contains("${FileExists}"));
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
    assert!(preuninstall.contains("RegOpenKeyExW"));
    assert!(preuninstall.contains("SetErrorLevel 2"));
}

#[test]
fn uninstall_cannot_succeed_with_protected_payload_left_behind() {
    let postuninstall = macro_body("NSIS_HOOK_POSTUNINSTALL");
    assert!(postuninstall.contains("GetFileAttributesW"));
    assert!(postuninstall.contains("$INSTDIR"));
    assert!(postuninstall.contains("KWIK_SECURE_CHECK_INSTALL_ROOT_EMPTY"));
    assert!(postuninstall.contains("SetErrorLevel 2"));
    assert!(postuninstall.contains("Abort"));

    let bounded_delete = macro_body("KWIK_SECURE_DELETE_HELPER_BOUNDED");
    assert!(bounded_delete.contains("Delete \"${KWIK_SECURE_HELPER}\""));
    assert!(bounded_delete.contains("${FileExists} \"${KWIK_SECURE_HELPER}\""));
    assert!(!bounded_delete.contains("/REBOOTOK"));
    assert!(!bounded_delete.contains("RMDir /r"));
}

#[test]
fn install_failure_rollback_preserves_registered_recovery_path() {
    let postinstall = macro_body("NSIS_HOOK_POSTINSTALL");
    assert!(postinstall.contains("stage=helper-provision outcome=failed"));
    assert!(postinstall.contains("uninstall-for-installer"));
    assert!(postinstall.contains("KWIK_SECURE_DELETE_HELPER_BOUNDED"));
    assert!(postinstall.contains("KWIK_SECURE_RECOVER_UNPROVISIONED_INSTALL"));
    assert!(!postinstall.contains("DeleteRegKey HKLM \"SOFTWARE\\KwikProxySecure\""));
    assert!(!postinstall.contains("\"${KWIK_SECURE_HELPER}\" uninstall'"));

    let pre_provision_recovery = macro_body("KWIK_SECURE_RECOVER_UNPROVISIONED_INSTALL");
    assert!(pre_provision_recovery.contains("$SYSDIR\\sc.exe\" query"));
    assert!(pre_provision_recovery.contains("$5 == 1060"));
    assert!(pre_provision_recovery.contains("RegOpenKeyExW"));
    assert!(pre_provision_recovery.contains("0x20119"));
    assert!(pre_provision_recovery.contains("$6 == 2"));
    assert!(pre_provision_recovery.contains("$6 == 3"));
    assert!(pre_provision_recovery.contains("KWIK_SECURE_DELETE_HELPER_BOUNDED"));
    assert!(!pre_provision_recovery.contains("DeleteRegKey"));
}

#[test]
fn service_acl_exposes_status_only_to_authenticated_users() {
    let postinstall = macro_body("NSIS_HOOK_POSTINSTALL");
    assert!(postinstall.contains("(A;;LC;;;AU)"));
    assert_eq!(postinstall.matches(";;;AU)").count(), 1);
    for forbidden in ["CC", "DC", "RP", "WP", "DT", "CR", "WD", "WO"] {
        assert!(
            !postinstall.contains(&format!("(A;;{forbidden};;;AU)")),
            "authenticated users must not receive {forbidden}"
        );
    }
}

#[test]
fn deletion_boundary_is_loaded_before_scm_mutation_and_never_canonicalizes_product_root() {
    let uninstall = SERVICE
        .split("fn uninstall_impl")
        .nth(1)
        .expect("missing uninstall implementation");
    let identity = uninstall
        .find("UninstallIdentity::load")
        .expect("missing retry-safe uninstall identity");
    let scm = uninstall
        .find("ServiceManager::local_computer")
        .expect("missing SCM mutation path");
    assert!(identity < scm);

    let loader = SECURITY
        .split("impl UninstallIdentity")
        .nth(1)
        .expect("missing uninstall identity implementation")
        .split("impl Installation")
        .next()
        .unwrap();
    assert!(loader.contains("open_directory_no_reparse(&install_dir"));
    assert!(loader.contains("final_path_by_handle"));
    assert!(loader.contains("_program_files_handle: program_files_handle"));
    assert!(!loader.contains("canonical_dir"));
}
