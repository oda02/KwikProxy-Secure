//! Fail-closed trust boundary for the privileged helper.
//!
//! The per-machine installer provisions an HKLM manifest and protects the
//! referenced files/directories with ACLs. The helper never accepts paths
//! from the pipe client.

use std::ffi::c_void;
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle as StdOwnedHandle};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SetSecurityInfo, SE_FILE_OBJECT, SE_REGISTRY_KEY,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
    GetTokenInformation, IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid,
    ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FlushFileBuffers, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, MoveFileExW, RemoveDirectoryW, WriteFile,
    BY_HANDLE_FILE_INFORMATION, CREATE_ALWAYS, CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
    OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemDirectoryW, GetSystemWindowsDirectoryW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ};
use winreg::RegKey;

const MANIFEST_KEY: &str = r"SOFTWARE\KwikProxySecure";
const MANIFEST_VALUE: &str = "ManifestV1";
const SDDL_REVISION_1: u32 = 1;
pub const MIHOMO_ARTIFACT_SHA256: &str =
    "fcc641d58094f3129c2fc3be411c506946d3a5ddbb459ff42d34dd9bfa0864fd";
pub const WINTUN_ARTIFACT_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
pub const GEOIP_ARTIFACT_SHA256: &str =
    "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354";
pub const GEOSITE_ARTIFACT_SHA256: &str =
    "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestV1 {
    generation: String,
    owner_sid: String,
    install_id: String,
    version: String,
    install_dir: String,
    ui_path: String,
    helper_path: String,
    mihomo_path: String,
    wintun_path: String,
    geoip_path: String,
    geosite_path: String,
    ui_sha256: String,
    helper_sha256: String,
    mihomo_sha256: String,
    wintun_sha256: String,
    geoip_sha256: String,
    geosite_sha256: String,
}

#[derive(Clone, Debug)]
pub struct Installation {
    pub generation: String,
    pub owner_sid: String,
    pub install_id: String,
    pub version: String,
    pub install_dir: PathBuf,
    pub ui_path: PathBuf,
    pub helper_path: PathBuf,
    pub mihomo_path: PathBuf,
    pub wintun_path: PathBuf,
    pub geoip_path: PathBuf,
    pub geosite_path: PathBuf,
    pub ui_sha256: String,
    pub helper_sha256: String,
    pub mihomo_sha256: String,
    pub wintun_sha256: String,
    pub geoip_sha256: String,
    pub geosite_sha256: String,
    pub runtime_dir: PathBuf,
}

impl Installation {
    /// Load the installer-owned manifest. Missing or inconsistent metadata is
    /// a hard error: starting a permissive helper is never a fallback.
    pub fn load() -> Result<Self> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm
            .open_subkey_with_flags(MANIFEST_KEY, KEY_READ)
            .with_context(|| format!("missing protected helper manifest HKLM\\{MANIFEST_KEY}"))?;

        let raw_a: String = key
            .get_value(MANIFEST_VALUE)
            .context("manifest atomic value")?;
        let raw_b: String = key
            .get_value(MANIFEST_VALUE)
            .context("manifest atomic re-read")?;
        if raw_a != raw_b {
            bail!("helper manifest changed during load");
        }
        let manifest: ManifestV1 = serde_json::from_str(&raw_a).context("parse helper manifest")?;
        uuid::Uuid::parse_str(&manifest.generation).context("manifest generation is not a UUID")?;
        let generation = manifest.generation.clone();
        let owner_sid = manifest.owner_sid;
        validate_sid_text(&owner_sid)?;
        verify_registry_acl(key.raw_handle() as HANDLE, &owner_sid)
            .context("protected manifest registry ACL rejected")?;
        let install_id = manifest.install_id;
        uuid::Uuid::parse_str(&install_id).context("manifest InstallId is not a UUID")?;
        let version = manifest.version;
        if version != env!("CARGO_PKG_VERSION") {
            bail!("helper manifest version mismatch");
        }

        let program_files = canonical_dir(known_program_files()?)?;
        let install_dir = canonical_dir(manifest.install_dir)?;
        require_descendant(&install_dir, &program_files, "InstallDir")?;
        let install_handle = open_directory_no_reparse(&install_dir, false)?;
        verify_runtime_acl(install_handle.0, &owner_sid)
            .context("protected install-root ACL rejected")?;
        let resources_dir = canonical_dir(install_dir.join("resources"))?;
        require_descendant(&resources_dir, &install_dir, "ResourcesDir")?;
        let resources_handle = open_directory_no_reparse(&resources_dir, false)?;
        verify_runtime_acl(resources_handle.0, &owner_sid)
            .context("protected resources-directory ACL rejected")?;

        validate_sha256_text(&manifest.ui_sha256, "UiSha256")?;
        validate_sha256_text(&manifest.helper_sha256, "HelperSha256")?;
        validate_sha256_text(&manifest.mihomo_sha256, "MihomoSha256")?;
        validate_sha256_text(&manifest.wintun_sha256, "WintunSha256")?;
        validate_sha256_text(&manifest.geoip_sha256, "GeoIpSha256")?;
        validate_sha256_text(&manifest.geosite_sha256, "GeoSiteSha256")?;
        require_artifact_hash(&manifest.mihomo_sha256, MIHOMO_ARTIFACT_SHA256, "Mihomo")?;
        require_artifact_hash(&manifest.wintun_sha256, WINTUN_ARTIFACT_SHA256, "WinTUN")?;
        require_artifact_hash(&manifest.geoip_sha256, GEOIP_ARTIFACT_SHA256, "GeoIP")?;
        require_artifact_hash(&manifest.geosite_sha256, GEOSITE_ARTIFACT_SHA256, "GeoSite")?;

        let ui_path = verify_protected_file(
            Path::new(&manifest.ui_path),
            &install_dir,
            &owner_sid,
            &manifest.ui_sha256,
            "UiPath",
        )?;
        let helper_path = verify_protected_file(
            Path::new(&manifest.helper_path),
            &install_dir,
            &owner_sid,
            &manifest.helper_sha256,
            "HelperPath",
        )?;
        let mihomo_path = verify_protected_file(
            Path::new(&manifest.mihomo_path),
            &install_dir,
            &owner_sid,
            &manifest.mihomo_sha256,
            "MihomoPath",
        )?;
        let wintun_path = verify_protected_file(
            Path::new(&manifest.wintun_path),
            &install_dir,
            &owner_sid,
            &manifest.wintun_sha256,
            "WintunPath",
        )?;
        let geoip_path = verify_protected_file(
            Path::new(&manifest.geoip_path),
            &install_dir,
            &owner_sid,
            &manifest.geoip_sha256,
            "GeoIpPath",
        )?;
        let geosite_path = verify_protected_file(
            Path::new(&manifest.geosite_path),
            &install_dir,
            &owner_sid,
            &manifest.geosite_sha256,
            "GeoSitePath",
        )?;

        let current_helper = canonical_file(std::env::current_exe()?)?;
        if !same_path(&current_helper, &helper_path) {
            bail!(
                "running helper does not match protected HelperPath (running={}, expected={})",
                current_helper.display(),
                helper_path.display()
            );
        }

        let program_data = known_program_data()?;
        let runtime_dir = program_data
            .join("KwikProxy Secure")
            .join("runtime")
            .join(&owner_sid)
            .join(&install_id);

        Ok(Self {
            generation,
            owner_sid,
            install_id,
            version,
            install_dir,
            ui_path,
            helper_path,
            mihomo_path,
            wintun_path,
            geoip_path,
            geosite_path,
            ui_sha256: manifest.ui_sha256,
            helper_sha256: manifest.helper_sha256,
            mihomo_sha256: manifest.mihomo_sha256,
            wintun_sha256: manifest.wintun_sha256,
            geoip_sha256: manifest.geoip_sha256,
            geosite_sha256: manifest.geosite_sha256,
            runtime_dir,
        })
    }

    /// WFP application rules are derived solely from protected metadata.
    pub fn trusted_app_paths(&self) -> Vec<PathBuf> {
        vec![
            self.ui_path.clone(),
            self.helper_path.clone(),
            self.mihomo_path.clone(),
        ]
    }

    pub fn open_verified_geoip(&self) -> Result<std::fs::File> {
        self.open_verified_artifact(&self.geoip_path, &self.geoip_sha256, "GeoIP")
    }

    pub fn open_verified_geosite(&self) -> Result<std::fs::File> {
        self.open_verified_artifact(&self.geosite_path, &self.geosite_sha256, "GeoSite")
    }

    fn open_verified_artifact(
        &self,
        path: &Path,
        expected_sha256: &str,
        label: &str,
    ) -> Result<std::fs::File> {
        let mut file =
            open_verified_plain_file(path, &self.install_dir, &self.owner_sid, false, label)?;
        let actual = digest_file(file.try_clone()?)?;
        if actual != expected_sha256 {
            bail!("protected {label} changed after service startup");
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    pub fn existing_runtime_dir(&self) -> Result<PathBuf> {
        if !self.runtime_dir.is_dir() {
            bail!(
                "protected runtime directory was not provisioned: {}",
                self.runtime_dir.display()
            );
        }
        let canonical = std::fs::canonicalize(&self.runtime_dir)?;
        if !same_path(&canonical, &self.runtime_dir) {
            bail!("runtime directory crosses a reparse/redirection boundary");
        }
        Ok(canonical)
    }

    pub fn verify_runtime_marker(&self) -> Result<()> {
        let _runtime = open_directory_no_reparse(&self.runtime_dir, false)?;
        let marker = self.runtime_dir.join(RUNTIME_MARKER);
        let wide = wide_path(&marker);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            bail!("runtime provisioning marker is missing");
        }
        let handle = OwnedHandle(handle);
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || info.nNumberOfLinks != 1
        {
            bail!("runtime provisioning marker is not a plain file");
        }
        drop(handle);
        let actual = std::fs::read_to_string(&marker)?;
        if actual != marker_contents(self) {
            bail!("runtime provisioning marker does not match installation manifest");
        }
        Ok(())
    }

    pub fn replace_runtime_file(&self, name: &str) -> Result<std::fs::File> {
        self.open_runtime_file(name, true)
    }

    pub fn open_runtime_log(&self, name: &str) -> Result<std::fs::File> {
        self.open_runtime_file(name, false)
    }

    fn open_runtime_file(&self, name: &str, replace: bool) -> Result<std::fs::File> {
        if name.is_empty()
            || name.len() > 128
            || name == RUNTIME_MARKER
            || name == RUNTIME_MARKER_TMP
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            bail!("invalid protected runtime filename");
        }
        self.verify_runtime_marker()?;
        let path = self.runtime_dir.join(name);
        let wide = wide_path(&path);
        if replace && unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND {
                bail!("remove existing protected runtime entry failed: {error}");
            }
        }
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                std::ptr::null(),
                if replace { CREATE_NEW } else { OPEN_ALWAYS },
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            bail!("open protected runtime file {} failed", path.display());
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0
            || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                != 0
            || info.nNumberOfLinks != 1
        {
            unsafe { CloseHandle(handle) };
            bail!("protected runtime entry is not a plain file");
        }
        Ok(unsafe { std::fs::File::from_raw_handle(handle) })
    }
}

fn known_folder(id: *const windows_sys::core::GUID) -> Result<PathBuf> {
    let mut raw = std::ptr::null_mut();
    let hr =
        unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, std::ptr::null_mut(), &mut raw) };
    if hr < 0 || raw.is_null() {
        bail!("SHGetKnownFolderPath failed: HRESULT {hr:#x}");
    }
    let mut len = 0usize;
    unsafe {
        while *raw.add(len) != 0 {
            len += 1;
        }
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, len)
    }));
    unsafe { CoTaskMemFree(raw as *const c_void) };
    Ok(path)
}

pub fn known_program_files() -> Result<PathBuf> {
    known_folder(&FOLDERID_ProgramFiles)
}

pub fn known_program_data() -> Result<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
}

fn system_directory(api: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    let written = unsafe { api(buffer.as_mut_ptr(), buffer.len() as u32) };
    if written == 0 || written as usize >= buffer.len() {
        bail!("trusted Windows system directory lookup failed");
    }
    buffer.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

pub fn known_windows_directory() -> Result<PathBuf> {
    system_directory(GetSystemWindowsDirectoryW)
}

pub fn known_system_directory() -> Result<PathBuf> {
    system_directory(GetSystemDirectoryW)
}

fn validate_sha256_text(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not a lowercase SHA-256 digest");
    }
    Ok(())
}

fn require_artifact_hash(actual: &str, expected: &str, label: &str) -> Result<()> {
    validate_sha256_text(actual, label)?;
    if actual != expected {
        bail!("{label} does not match the reviewed ARTIFACTS.json digest");
    }
    Ok(())
}

fn final_path_by_handle(handle: HANDLE) -> Result<PathBuf> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    let needed = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, flags) };
    if needed == 0 || needed > 32_768 {
        bail!("GetFinalPathNameByHandleW size failed");
    }
    let mut buffer = vec![0u16; needed as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags)
    };
    if written == 0 || written as usize >= buffer.len() {
        bail!("GetFinalPathNameByHandleW failed");
    }
    buffer.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

fn file_dacl_sddl(owner_sid: &str) -> String {
    // Use the file-specific mapping of GENERIC_READ | GENERIC_EXECUTE.
    // SetSecurityInfo maps generic rights before storing an ACE, so retaining
    // GRGX in the expected descriptor makes exact post-write verification
    // reject the ACL that Windows itself just canonicalized.
    format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{owner_sid})")
}

fn verify_file_acl(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let expected = descriptor_from_sddl(&format!("O:BAG:BA{}", file_dacl_sddl(owner_sid)))?;
    let mut expected_present = 0;
    let mut expected_defaulted = 0;
    let mut expected_dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            expected,
            &mut expected_present,
            &mut expected_dacl,
            &mut expected_defaulted,
        )
    } == 0
        || expected_present == 0
        || expected_dacl.is_null()
    {
        unsafe { LocalFree(expected) };
        bail!("expected protected-file DACL is invalid");
    }
    let mut owner = std::ptr::null_mut();
    let mut group = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let mut control = 0u16;
    let mut revision = 0u32;
    let verified = status == 0
        && !descriptor.is_null()
        && unsafe {
            IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
                && IsWellKnownSid(group, WinBuiltinAdministratorsSid) != 0
                && !dacl.is_null()
                && GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
                && control & SE_DACL_PROTECTED != 0
                && acl_matches_exactly(dacl, expected_dacl)
        };
    unsafe {
        if !descriptor.is_null() {
            LocalFree(descriptor);
        }
        LocalFree(expected);
    }
    if !verified {
        bail!("protected-file owner/DACL verification failed closed");
    }
    Ok(())
}

fn apply_and_verify_file_acl(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let descriptor = descriptor_from_sddl(&format!("O:BAG:BA{}", file_dacl_sddl(owner_sid)))?;
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut group = std::ptr::null_mut();
    let mut group_defaulted = 0;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let extracted = unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) != 0
            && GetSecurityDescriptorGroup(descriptor, &mut group, &mut group_defaulted) != 0
            && GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) != 0
    };
    if !extracted || owner.is_null() || group.is_null() || present == 0 || dacl.is_null() {
        unsafe { LocalFree(descriptor) };
        bail!("generated protected-file descriptor is incomplete");
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            group,
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor) };
    if status != 0 {
        bail!("SetSecurityInfo(protected file) failed: {status}");
    }
    verify_file_acl(handle, owner_sid)
}

fn open_verified_plain_file(
    path: &Path,
    root: &Path,
    owner_sid: &str,
    writable_security: bool,
    label: &str,
) -> Result<std::fs::File> {
    require_descendant(path, root, label)?;
    let mut access = GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL;
    if writable_security {
        access |= WRITE_DAC | WRITE_OWNER;
    }
    let wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!("open protected {label} failed: {}", path.display());
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0
        || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
        || info.nFileSizeHigh != 0
        || info.nFileSizeLow > 512 * 1024 * 1024
    {
        unsafe { CloseHandle(handle) };
        bail!("protected {label} is reparse, hardlinked, or unreasonably large");
    }
    let file = unsafe { std::fs::File::from_raw_handle(handle) };
    let actual = final_path_by_handle(file.as_raw_handle() as HANDLE)?;
    let expected = canonical_file(path)?;
    if !same_path(&actual, &expected) || !same_path(path, &expected) {
        bail!("protected {label} final path mismatch");
    }
    let acl_result = if writable_security {
        apply_and_verify_file_acl(file.as_raw_handle() as HANDLE, owner_sid)
    } else {
        verify_file_acl(file.as_raw_handle() as HANDLE, owner_sid)
    };
    if let Err(error) = acl_result {
        return Err(error).with_context(|| format!("protected {label} ACL"));
    }
    Ok(file)
}

fn digest_file(mut file: std::fs::File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_protected_file(path: &Path, root: &Path, owner_sid: &str, label: &str) -> Result<String> {
    digest_file(open_verified_plain_file(
        path, root, owner_sid, false, label,
    )?)
}

fn verify_protected_file(
    path: &Path,
    root: &Path,
    owner_sid: &str,
    expected_sha256: &str,
    label: &str,
) -> Result<PathBuf> {
    validate_sha256_text(expected_sha256, label)?;
    let file = open_verified_plain_file(path, root, owner_sid, false, label)?;
    let final_path = final_path_by_handle(file.as_raw_handle() as HANDLE)?;
    let actual_sha256 = digest_file(file)?;
    if actual_sha256 != expected_sha256 {
        bail!("protected {label} SHA-256 mismatch");
    }
    Ok(final_path)
}

fn provision_install_tree(
    owner_sid: &str,
    install_dir: &Path,
    critical_files: &[&Path],
) -> Result<()> {
    validate_sid_text(owner_sid)?;
    let program_files = canonical_dir(known_program_files()?)?;
    let _program_files_guard = open_directory_no_reparse(&program_files, false)?;
    let install_dir = canonical_dir(install_dir)?;
    require_descendant(&install_dir, &program_files, "InstallDir")?;
    let install_guard = open_directory_no_reparse(&install_dir, true)?;
    apply_and_verify_runtime_acl(install_guard.0, owner_sid).context("protect install root")?;

    let resources = install_dir.join("resources");
    if critical_files
        .iter()
        .any(|path| path.starts_with(&resources))
    {
        let resources = canonical_dir(&resources)?;
        let resources_guard = open_directory_no_reparse(&resources, true)?;
        apply_and_verify_runtime_acl(resources_guard.0, owner_sid)
            .context("protect install resources directory")?;
    }
    for (index, path) in critical_files.iter().enumerate() {
        let _file = open_verified_plain_file(
            path,
            &install_dir,
            owner_sid,
            true,
            &format!("critical file #{index}"),
        )?;
    }
    Ok(())
}

/// Installer entry point for an atomic, versioned manifest. The registry key
/// is protected and verified before the single serialized value is replaced.
pub fn provision_install_manifest(
    owner_sid: &str,
    install_dir: &Path,
    ui_path: &Path,
    helper_path: &Path,
    mihomo_path: &Path,
    wintun_path: &Path,
    geoip_path: &Path,
    geosite_path: &Path,
) -> Result<()> {
    validate_sid_text(owner_sid)?;
    provision_install_tree(
        owner_sid,
        install_dir,
        &[
            ui_path,
            helper_path,
            mihomo_path,
            wintun_path,
            geoip_path,
            geosite_path,
        ],
    )?;
    let ui_sha256 = hash_protected_file(ui_path, install_dir, owner_sid, "UiPath")?;
    let helper_sha256 = hash_protected_file(helper_path, install_dir, owner_sid, "HelperPath")?;
    let mihomo_sha256 = hash_protected_file(mihomo_path, install_dir, owner_sid, "MihomoPath")?;
    let wintun_sha256 = hash_protected_file(wintun_path, install_dir, owner_sid, "WintunPath")?;
    let geoip_sha256 = hash_protected_file(geoip_path, install_dir, owner_sid, "GeoIpPath")?;
    let geosite_sha256 = hash_protected_file(geosite_path, install_dir, owner_sid, "GeoSitePath")?;
    require_artifact_hash(&mihomo_sha256, MIHOMO_ARTIFACT_SHA256, "Mihomo")?;
    require_artifact_hash(&wintun_sha256, WINTUN_ARTIFACT_SHA256, "WinTUN")?;
    require_artifact_hash(&geoip_sha256, GEOIP_ARTIFACT_SHA256, "GeoIP")?;
    require_artifact_hash(&geosite_sha256, GEOSITE_ARTIFACT_SHA256, "GeoSite")?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey_with_flags(MANIFEST_KEY, KEY_ALL_ACCESS)?;
    apply_and_verify_registry_acl(key.raw_handle() as HANDLE, owner_sid)?;

    let existing = key
        .get_value::<String, _>(MANIFEST_VALUE)
        .ok()
        .and_then(|raw| serde_json::from_str::<ManifestV1>(&raw).ok());
    let install_id = existing
        .filter(|old| old.owner_sid.eq_ignore_ascii_case(owner_sid))
        .and_then(|old| {
            uuid::Uuid::parse_str(&old.install_id)
                .ok()
                .map(|_| old.install_id)
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let manifest = ManifestV1 {
        generation: uuid::Uuid::new_v4().to_string(),
        owner_sid: owner_sid.to_string(),
        install_id,
        version: env!("CARGO_PKG_VERSION").to_string(),
        install_dir: install_dir.to_string_lossy().into_owned(),
        ui_path: ui_path.to_string_lossy().into_owned(),
        helper_path: helper_path.to_string_lossy().into_owned(),
        mihomo_path: mihomo_path.to_string_lossy().into_owned(),
        wintun_path: wintun_path.to_string_lossy().into_owned(),
        geoip_path: geoip_path.to_string_lossy().into_owned(),
        geosite_path: geosite_path.to_string_lossy().into_owned(),
        ui_sha256,
        helper_sha256,
        mihomo_sha256,
        wintun_sha256,
        geoip_sha256,
        geosite_sha256,
    };
    key.set_value(MANIFEST_VALUE, &serde_json::to_string(&manifest)?)?;
    apply_and_verify_registry_acl(key.raw_handle() as HANDLE, owner_sid)
}

fn apply_and_verify_registry_acl(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let sddl = format!("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;{owner_sid})");
    let expected = descriptor_from_sddl(&sddl)?;
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut group = std::ptr::null_mut();
    let mut group_defaulted = 0;
    let mut present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let extracted = unsafe {
        GetSecurityDescriptorOwner(expected, &mut owner, &mut owner_defaulted) != 0
            && GetSecurityDescriptorGroup(expected, &mut group, &mut group_defaulted) != 0
            && GetSecurityDescriptorDacl(expected, &mut present, &mut dacl, &mut dacl_defaulted)
                != 0
    };
    if !extracted || owner.is_null() || group.is_null() || present == 0 || dacl.is_null() {
        unsafe { LocalFree(expected) };
        bail!("generated registry security descriptor is incomplete");
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            group,
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        unsafe { LocalFree(expected) };
        bail!("SetSecurityInfo(manifest registry) failed: {status}");
    }
    unsafe { LocalFree(expected) };
    verify_registry_acl(handle, owner_sid)
}

fn verify_registry_acl(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let expected = descriptor_from_sddl(&format!(
        "O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;{owner_sid})"
    ))?;
    let mut expected_present = 0;
    let mut expected_defaulted = 0;
    let mut expected_dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            expected,
            &mut expected_present,
            &mut expected_dacl,
            &mut expected_defaulted,
        )
    } == 0
        || expected_present == 0
        || expected_dacl.is_null()
    {
        unsafe { LocalFree(expected) };
        bail!("expected manifest registry DACL is invalid");
    }
    let mut actual_owner = std::ptr::null_mut();
    let mut actual_group = std::ptr::null_mut();
    let mut actual_dacl = std::ptr::null_mut();
    let mut actual = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut actual_owner,
            &mut actual_group,
            &mut actual_dacl,
            std::ptr::null_mut(),
            &mut actual,
        )
    };
    let mut control = 0u16;
    let mut revision = 0u32;
    let verified = status == 0
        && !actual.is_null()
        && unsafe {
            IsWellKnownSid(actual_owner, WinBuiltinAdministratorsSid) != 0
                && IsWellKnownSid(actual_group, WinBuiltinAdministratorsSid) != 0
                && GetSecurityDescriptorControl(actual, &mut control, &mut revision) != 0
                && control & SE_DACL_PROTECTED != 0
                && acl_matches_exactly(actual_dacl, expected_dacl)
        };
    unsafe {
        if !actual.is_null() {
            LocalFree(actual);
        }
        LocalFree(expected);
    }
    if !verified {
        bail!("manifest registry ACL verification failed closed");
    }
    Ok(())
}

const RUNTIME_MARKER: &str = ".kwikproxy-secure-provisioned";
const RUNTIME_MARKER_TMP: &str = ".kwikproxy-secure-provisioned.tmp";

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn runtime_dacl_sddl(owner_sid: &str) -> String {
    // Windows canonicalizes one inheritable directory GRGX ACE into an
    // effective file-specific ACE plus an inherit-only generic ACE. Spell out
    // that stable representation so exact verification compares like-for-like.
    format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\
         (A;;0x1200a9;;;{owner_sid})(A;OICIIO;GRGX;;;{owner_sid})"
    )
}

fn create_directory_if_missing(path: &Path, owner_sid: &str) -> Result<bool> {
    let wide = wide_path(path);
    // New components are born with the protected DACL, closing the window
    // between name creation and the subsequent handle-based owner/ACL pass.
    let descriptor = descriptor_from_sddl(&runtime_dacl_sddl(owner_sid))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
    unsafe { LocalFree(descriptor) };
    if created == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_ALREADY_EXISTS {
            bail!("CreateDirectoryW {} failed: {error}", path.display());
        }
        return Ok(false);
    }
    Ok(true)
}

/// Open a directory itself (not its reparse target) and reject any reparse
/// point by handle. The handle remains valid while ACL operations run.
fn open_directory_no_reparse(path: &Path, writable_security: bool) -> Result<OwnedHandle> {
    let mut access = FILE_READ_ATTRIBUTES | READ_CONTROL;
    if writable_security {
        access |= WRITE_DAC | WRITE_OWNER;
    }
    let wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!("open directory {} failed", path.display());
    }
    let handle = OwnedHandle(handle);
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        bail!("GetFileInformationByHandle {} failed", path.display());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!(
            "runtime path component is not a plain directory: {}",
            path.display()
        );
    }
    Ok(handle)
}

fn apply_and_verify_runtime_acl(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let sddl = format!("O:BAG:BA{}", runtime_dacl_sddl(owner_sid));
    let descriptor = descriptor_from_sddl(&sddl)?;
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut group = std::ptr::null_mut();
    let mut group_defaulted = 0;
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let extracted = unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) != 0
            && GetSecurityDescriptorGroup(descriptor, &mut group, &mut group_defaulted) != 0
            && GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            ) != 0
    };
    if !extracted || owner.is_null() || group.is_null() || dacl_present == 0 || dacl.is_null() {
        unsafe { LocalFree(descriptor) };
        bail!("generated runtime security descriptor is incomplete");
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            group,
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        unsafe { LocalFree(descriptor) };
        bail!("SetSecurityInfo(runtime) failed: {status}");
    }

    let mut actual_owner = std::ptr::null_mut();
    let mut actual_group = std::ptr::null_mut();
    let mut actual_dacl = std::ptr::null_mut();
    let mut actual_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut actual_owner,
            &mut actual_group,
            &mut actual_dacl,
            std::ptr::null_mut(),
            &mut actual_descriptor,
        )
    };
    if status != 0 || actual_descriptor.is_null() {
        unsafe {
            if !actual_descriptor.is_null() {
                LocalFree(actual_descriptor);
            }
            LocalFree(descriptor);
        }
        bail!("GetSecurityInfo(runtime verification) failed: {status}");
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    let verified = unsafe {
        IsWellKnownSid(actual_owner, WinBuiltinAdministratorsSid) != 0
            && IsWellKnownSid(actual_group, WinBuiltinAdministratorsSid) != 0
            && !actual_dacl.is_null()
            && GetSecurityDescriptorControl(actual_descriptor, &mut control, &mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
            && acl_matches_exactly(actual_dacl, dacl)
    };
    unsafe {
        LocalFree(actual_descriptor);
        LocalFree(descriptor);
    }
    if !verified {
        bail!("runtime ACL verification failed closed");
    }
    Ok(())
}

fn verify_runtime_acl(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let expected = descriptor_from_sddl(&format!("O:BAG:BA{}", runtime_dacl_sddl(owner_sid)))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut expected_dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(expected, &mut present, &mut expected_dacl, &mut defaulted)
    } == 0
        || present == 0
        || expected_dacl.is_null()
    {
        unsafe { LocalFree(expected) };
        bail!("expected runtime DACL is invalid");
    }
    let mut owner = std::ptr::null_mut();
    let mut group = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        unsafe { LocalFree(expected) };
        bail!("GetSecurityInfo(runtime verification) failed: {status}");
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    let ok = unsafe {
        IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            && IsWellKnownSid(group, WinBuiltinAdministratorsSid) != 0
            && !dacl.is_null()
            && GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
            && acl_matches_exactly(dacl, expected_dacl)
    };
    unsafe {
        LocalFree(descriptor);
        LocalFree(expected);
    }
    if !ok {
        bail!("preexisting runtime ACL does not match protected policy");
    }
    Ok(())
}

/// Compare every ACE, including order, type, inheritance flags, access mask
/// and SID. This rejects inherited, deny, additional, or weakened entries
/// rather than merely checking that a non-NULL protected DACL exists.
unsafe fn acl_matches_exactly(
    actual: *mut windows_sys::Win32::Security::ACL,
    expected: *mut windows_sys::Win32::Security::ACL,
) -> bool {
    let mut actual_info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    let mut expected_info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    if GetAclInformation(
        actual,
        &mut actual_info as *mut _ as *mut c_void,
        size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    ) == 0
        || GetAclInformation(
            expected,
            &mut expected_info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
        || actual_info.AceCount != expected_info.AceCount
    {
        return false;
    }

    for index in 0..actual_info.AceCount {
        let mut actual_raw = std::ptr::null_mut();
        let mut expected_raw = std::ptr::null_mut();
        if GetAce(actual, index, &mut actual_raw) == 0
            || GetAce(expected, index, &mut expected_raw) == 0
            || actual_raw.is_null()
            || expected_raw.is_null()
        {
            return false;
        }
        let actual_ace = &*(actual_raw as *const ACCESS_ALLOWED_ACE);
        let expected_ace = &*(expected_raw as *const ACCESS_ALLOWED_ACE);
        if actual_ace.Header.AceType != expected_ace.Header.AceType
            || actual_ace.Header.AceFlags != expected_ace.Header.AceFlags
            || actual_ace.Header.AceSize != expected_ace.Header.AceSize
            || actual_ace.Mask != expected_ace.Mask
            || EqualSid(
                &actual_ace.SidStart as *const u32 as *mut c_void,
                &expected_ace.SidStart as *const u32 as *mut c_void,
            ) == 0
        {
            return false;
        }
    }
    true
}

fn marker_contents(installation: &Installation) -> String {
    format!(
        "generation={}\ninstall_id={}\nversion={}\nowner_sid={}\n",
        installation.generation,
        installation.install_id,
        installation.version,
        installation.owner_sid
    )
}

fn write_runtime_marker(installation: &Installation) -> Result<()> {
    let temporary = installation.runtime_dir.join(RUNTIME_MARKER_TMP);
    let final_path = installation.runtime_dir.join(RUNTIME_MARKER);
    let temporary_wide = wide_path(&temporary);
    let handle = unsafe {
        CreateFileW(
            temporary_wide.as_ptr(),
            GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            std::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!("create runtime provisioning marker failed");
    }
    let handle = OwnedHandle(handle);
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || info.nNumberOfLinks != 1
    {
        bail!("runtime provisioning marker is a reparse point");
    }
    let contents = marker_contents(installation);
    let mut written = 0u32;
    if unsafe {
        WriteFile(
            handle.0,
            contents.as_ptr(),
            contents.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    } == 0
        || written as usize != contents.len()
        || unsafe { FlushFileBuffers(handle.0) } == 0
    {
        bail!("write runtime provisioning marker failed");
    }
    drop(handle);
    let final_wide = wide_path(&final_path);
    if unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            final_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING,
        )
    } == 0
    {
        bail!("atomically publish runtime provisioning marker failed");
    }
    Ok(())
}

/// Installer-only provisioning. Each path component is opened no-follow,
/// checked by handle, ACL'd by handle, and checked again before the atomic
/// completion marker is published.
pub fn provision_runtime_dir(installation: &Installation) -> Result<()> {
    validate_sid_text(&installation.owner_sid)?;
    let program_data = known_program_data()?;
    let _program_data_handle = open_directory_no_reparse(&program_data, false)?;
    let product = program_data.join("KwikProxy Secure");
    let runtime = product.join("runtime");
    let owner_runtime = runtime.join(&installation.owner_sid);
    if !same_path(
        &owner_runtime.join(&installation.install_id),
        &installation.runtime_dir,
    ) {
        bail!("runtime directory does not match the exact protected layout");
    }

    for directory in [&product, &runtime, &owner_runtime] {
        create_directory_if_missing(directory, &installation.owner_sid)?;
        let handle = open_directory_no_reparse(directory, true)?;
        apply_and_verify_runtime_acl(handle.0, &installation.owner_sid)?;
        // Re-check attributes through the same stable handle after ACL update.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            bail!("runtime component changed during provisioning");
        }
    }

    let created = create_directory_if_missing(&installation.runtime_dir, &installation.owner_sid)?;
    let handle = open_directory_no_reparse(&installation.runtime_dir, true)?;
    if !created {
        // A repair may reuse only a directory previously provisioned for
        // this exact random InstallId. Never bless a precreated tree.
        installation
            .verify_runtime_marker()
            .context("refusing unmarked preexisting runtime directory")?;
        verify_runtime_acl(handle.0, &installation.owner_sid)?;
    }
    apply_and_verify_runtime_acl(handle.0, &installation.owner_sid)?;
    invalidate_runtime_marker(installation)?;
    write_runtime_marker(installation)
}

/// Remove completion markers before a repair/re-provision operation. Deleting
/// a reparse-point name removes the link itself; the protected parent prevents
/// unprivileged replacement races.
pub fn invalidate_runtime_marker(installation: &Installation) -> Result<()> {
    let _runtime = open_directory_no_reparse(&installation.runtime_dir, true)?;
    for name in [RUNTIME_MARKER, RUNTIME_MARKER_TMP] {
        let wide = wide_path(&installation.runtime_dir.join(name));
        if unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND {
                bail!("delete runtime marker failed: {error}");
            }
        }
    }
    Ok(())
}

/// Best-effort uninstall cleanup for the one manifest-derived InstallId only.
/// It intentionally does not require the completion marker: SCM deletion must
/// remain repairable when that marker or a runtime file is damaged.
pub fn cleanup_runtime_after_uninstall(installation: &Installation) -> Result<()> {
    validate_sid_text(&installation.owner_sid)?;
    uuid::Uuid::parse_str(&installation.install_id)?;
    let program_data = known_program_data()?;
    let product = program_data.join("KwikProxy Secure");
    let runtime = product.join("runtime");
    let owner_runtime = runtime.join(&installation.owner_sid);
    let exact = owner_runtime.join(&installation.install_id);
    if !same_path(&exact, &installation.runtime_dir) {
        bail!("refusing cleanup outside exact manifest runtime directory");
    }

    // Keep ancestors open without FILE_SHARE_DELETE while the one exact leaf
    // is validated. The leaf itself is then removed by a bounded no-follow
    // walk, including provider caches created by Mihomo.
    let mut guards = Vec::new();
    for directory in [&program_data, &product, &runtime, &owner_runtime] {
        guards.push(open_directory_no_reparse(directory, false)?);
    }
    let leaf_guard = open_directory_no_reparse(&installation.runtime_dir, false)?;
    verify_runtime_acl(leaf_guard.0, &installation.owner_sid)?;
    drop(leaf_guard);
    let mut budget = 8_192usize;
    remove_bounded_tree_no_follow(&installation.runtime_dir, 8, &mut budget)?;
    drop(guards);
    Ok(())
}

/// Corrupt-manifest uninstall fallback. It never consults manifest paths and
/// never leaves the exact `%ProgramData%\KwikProxy Secure\runtime` root.
/// Only SID/GUID-shaped leaves are considered, with hard depth/entry bounds.
pub fn cleanup_product_runtime_after_uninstall() -> Result<()> {
    let program_data = known_program_data()?;
    let product = program_data.join("KwikProxy Secure");
    let runtime = product.join("runtime");
    let _program_data = open_directory_no_reparse(&program_data, false)?;
    let _product = match open_directory_no_reparse(&product, false) {
        Ok(handle) => handle,
        Err(_) if !product.exists() => return Ok(()),
        Err(error) => return Err(error),
    };
    let _runtime = match open_directory_no_reparse(&runtime, false) {
        Ok(handle) => handle,
        Err(_) if !runtime.exists() => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut owners_seen = 0usize;
    for owner in std::fs::read_dir(&runtime)? {
        owners_seen += 1;
        if owners_seen > 64 {
            bail!("runtime owner cleanup bound exceeded");
        }
        let owner = owner?;
        let owner_name = owner.file_name().to_string_lossy().into_owned();
        if validate_sid_text(&owner_name).is_err() {
            continue;
        }
        let owner_path = owner.path();
        let owner_guard = open_directory_no_reparse(&owner_path, false)?;
        let mut installs_seen = 0usize;
        for install in std::fs::read_dir(&owner_path)? {
            installs_seen += 1;
            if installs_seen > 128 {
                bail!("runtime generation cleanup bound exceeded");
            }
            let install = install?;
            let install_name = install.file_name().to_string_lossy().into_owned();
            if uuid::Uuid::parse_str(&install_name).is_err() {
                continue;
            }
            let mut budget = 8_192usize;
            remove_bounded_tree_no_follow(&install.path(), 8, &mut budget)?;
        }
        drop(owner_guard);
        let wide = wide_path(&owner_path);
        let _ = unsafe { RemoveDirectoryW(wide.as_ptr()) };
    }
    Ok(())
}

fn remove_bounded_tree_no_follow(path: &Path, depth: usize, budget: &mut usize) -> Result<()> {
    if depth == 0 || *budget == 0 {
        bail!("protected runtime cleanup bound exceeded");
    }
    *budget -= 1;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let attributes = metadata.file_attributes();
    let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let is_reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if is_reparse {
        let wide = wide_path(path);
        let removed = if is_directory {
            unsafe { RemoveDirectoryW(wide.as_ptr()) }
        } else {
            unsafe { DeleteFileW(wide.as_ptr()) }
        };
        if removed == 0 {
            bail!("unlink protected runtime reparse entry failed");
        }
        return Ok(());
    }
    if !is_directory {
        return delete_runtime_plain_file(path);
    }
    let guard = open_directory_no_reparse(path, false)?;
    let entries = std::fs::read_dir(path)?
        .take(*budget + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    if entries.len() > *budget {
        bail!("protected runtime cleanup entry bound exceeded");
    }
    for entry in entries {
        remove_bounded_tree_no_follow(&entry.path(), depth - 1, budget)?;
    }
    drop(guard);
    let wide = wide_path(path);
    if unsafe { RemoveDirectoryW(wide.as_ptr()) } == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND {
            bail!("remove protected runtime directory failed: {error}");
        }
    }
    Ok(())
}

fn delete_runtime_plain_file(path: &Path) -> Result<()> {
    let wide = wide_path(path);
    if unsafe { DeleteFileW(wide.as_ptr()) } == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND {
            bail!(
                "delete protected runtime file {} failed: {error}",
                path.display()
            );
        }
    }
    Ok(())
}

fn canonical_file(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    if !path.is_file() {
        bail!("required protected file is missing: {}", path.display());
    }
    std::fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

fn canonical_dir(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    if !path.is_dir() {
        bail!(
            "required protected directory is missing: {}",
            path.display()
        );
    }
    std::fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

fn normalized(path: &Path) -> String {
    let value = path
        .as_os_str()
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase();
    if let Some(unc) = value.strip_prefix(r"\\?\unc\") {
        return format!(r"\\{unc}");
    }
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_string()
}

fn same_path(a: &Path, b: &Path) -> bool {
    normalized(a) == normalized(b)
}

fn require_descendant(path: &Path, root: &Path, label: &str) -> Result<()> {
    let root = normalized(root);
    let path = normalized(path);
    let prefix = format!("{}\\", root.trim_end_matches('\\'));
    if path != root && !path.starts_with(&prefix) {
        bail!("{label} escapes protected root: {path}");
    }
    Ok(())
}

fn validate_sid_text(sid: &str) -> Result<()> {
    if sid.len() < 5
        || sid.len() > 184
        || !sid.starts_with("S-1-")
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
    {
        bail!("invalid OwnerSid in helper manifest");
    }
    Ok(())
}

/// Resolve the user owning the Explorer shell in the installer's current
/// interactive session. This avoids binding OwnerSid to over-the-shoulder UAC
/// credentials while still failing closed for service/session-0 invocations.
pub fn interactive_shell_user_sid() -> Result<String> {
    let shell = unsafe { GetShellWindow() };
    if shell.is_null() {
        bail!("interactive shell window is unavailable");
    }
    let mut shell_pid = 0u32;
    if unsafe { GetWindowThreadProcessId(shell, &mut shell_pid) } == 0 || shell_pid == 0 {
        bail!("interactive shell process is unavailable");
    }
    let current_pid = unsafe { GetCurrentProcessId() };
    let mut shell_session = 0u32;
    let mut current_session = 0u32;
    if unsafe { ProcessIdToSessionId(shell_pid, &mut shell_session) } == 0
        || unsafe { ProcessIdToSessionId(current_pid, &mut current_session) } == 0
        || shell_session != current_session
        || shell_session == 0
    {
        bail!("interactive shell is absent or belongs to a different session");
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, shell_pid) };
    if process.is_null() {
        bail!("OpenProcess(interactive shell) failed");
    }
    let result = process_sid(process);
    unsafe { CloseHandle(process) };
    let sid = result?;
    validate_sid_text(&sid)?;
    if sid.eq_ignore_ascii_case("S-1-5-18") {
        bail!("interactive shell unexpectedly belongs to LocalSystem");
    }
    Ok(sid)
}

/// Keeps the client process handle alive until request completion, preventing
/// PID reuse after authentication.
pub struct AuthenticatedClient {
    _process: StdOwnedHandle,
    pub pid: u32,
    pub session_id: u32,
}

pub fn authenticate_client(
    pipe: &NamedPipeServer,
    installation: &Installation,
) -> Result<AuthenticatedClient> {
    let pipe_handle = pipe.as_raw_handle() as HANDLE;
    let mut pid = 0u32;
    if unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut pid) } == 0 || pid == 0 {
        bail!("GetNamedPipeClientProcessId failed");
    }

    let raw_process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw_process.is_null() {
        bail!("OpenProcess({pid}) failed");
    }
    // SAFETY: OpenProcess returned a fresh owned process HANDLE. OwnedHandle
    // provides exactly-once close and is safe to retain across async dispatch.
    let process = unsafe { StdOwnedHandle::from_raw_handle(raw_process) };
    let raw_process = process.as_raw_handle() as HANDLE;

    let result = (|| -> Result<u32> {
        let sid = process_sid(raw_process)?;
        if !sid.eq_ignore_ascii_case(&installation.owner_sid) {
            bail!("pipe client SID is not the installation owner");
        }
        let mut session_id = 0u32;
        if unsafe { ProcessIdToSessionId(pid, &mut session_id) } == 0
            || session_id == 0
            || !is_active_interactive_session(session_id)?
        {
            bail!("pipe client is not in an active interactive session");
        }
        let image = canonical_file(process_image(raw_process)?)?;
        if !same_path(&image, &installation.ui_path) {
            bail!("pipe client image is not the protected UI executable");
        }
        Ok(session_id)
    })();

    result.map(|session_id| AuthenticatedClient {
        _process: process,
        pid,
        session_id,
    })
}

fn is_active_interactive_session(session_id: u32) -> Result<bool> {
    let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count) }
        == 0
        || sessions.is_null()
    {
        bail!("WTSEnumerateSessionsW failed");
    }
    let active = unsafe { std::slice::from_raw_parts(sessions, count as usize) }
        .iter()
        .any(|session| session.SessionId == session_id && session.State == WTSActive);
    unsafe { WTSFreeMemory(sessions as *mut c_void) };
    Ok(active)
}

fn process_image(process: HANDLE) -> Result<PathBuf> {
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut len) } == 0 {
        bail!("QueryFullProcessImageNameW failed");
    }
    buf.truncate(len as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)))
}

fn process_sid(process: HANDLE) -> Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        bail!("OpenProcessToken failed");
    }
    let result = (|| -> Result<String> {
        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed < size_of::<TOKEN_USER>() as u32 {
            bail!("GetTokenInformation returned invalid size");
        }
        let mut bytes = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                bytes.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            )
        } == 0
        {
            bail!("GetTokenInformation(TokenUser) failed");
        }
        let user = unsafe { &*(bytes.as_ptr() as *const TOKEN_USER) };
        let mut sid_text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 {
            bail!("ConvertSidToStringSidW failed");
        }
        let mut len = 0usize;
        unsafe {
            while *sid_text.add(len) != 0 {
                len += 1;
            }
        }
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_text, len) });
        unsafe { LocalFree(sid_text as *mut c_void) };
        Ok(value)
    })();
    unsafe { CloseHandle(token) };
    result
}

/// Non-NULL DACL: SYSTEM, Administrators and the installation owner. A second
/// process identity check still runs after each connection.
pub struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    sa: Box<SECURITY_ATTRIBUTES>,
}

impl PipeSecurity {
    pub fn for_owner(owner_sid: &str) -> Result<Self> {
        validate_sid_text(owner_sid)?;
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner_sid})");
        let descriptor = descriptor_from_sddl(&sddl)?;
        let sa = Box::new(SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        });
        Ok(Self { descriptor, sa })
    }

    pub fn as_attrs_ptr(&mut self) -> *mut c_void {
        self.sa.as_mut() as *mut _ as *mut c_void
    }
}

fn descriptor_from_sddl(sddl: &str) -> Result<PSECURITY_DESCRIPTOR> {
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        bail!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
    }
    Ok(descriptor)
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        unsafe { LocalFree(self.descriptor) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_prefix_confusion() {
        let root = Path::new(r"C:\Program Files\KwikProxy Secure");
        let sibling = Path::new(r"C:\Program Files\KwikProxy Secure Evil\app.exe");
        assert!(require_descendant(sibling, root, "test").is_err());
    }

    #[test]
    fn extended_length_paths_compare_to_dos_paths() {
        assert!(same_path(
            Path::new(r"\\?\C:\ProgramData\KwikProxy Secure"),
            Path::new(r"C:\ProgramData\KwikProxy Secure")
        ));
    }

    #[test]
    fn sid_text_is_strict() {
        assert!(validate_sid_text("S-1-5-21-1-2-3-1001").is_ok());
        assert!(validate_sid_text(r"S-1-5-21\\..\\evil").is_err());
    }

    #[test]
    fn atomic_manifest_rejects_unknown_fields() {
        let json = r#"{"generation":"00000000-0000-4000-8000-000000000001","owner_sid":"S-1-5-21-1-2-3-1001","install_id":"00000000-0000-4000-8000-000000000002","version":"0","install_dir":"x","ui_path":"x","helper_path":"x","mihomo_path":"x","injected":true}"#;
        assert!(serde_json::from_str::<ManifestV1>(json).is_err());
    }

    #[test]
    fn privileged_artifact_digests_match_reviewed_manifest() {
        let artifacts = include_str!("../../../binaries/ARTIFACTS.json");
        for digest in [
            MIHOMO_ARTIFACT_SHA256,
            WINTUN_ARTIFACT_SHA256,
            GEOIP_ARTIFACT_SHA256,
            GEOSITE_ARTIFACT_SHA256,
        ] {
            validate_sha256_text(digest, "test digest").unwrap();
            assert!(artifacts.contains(digest));
        }
    }

    fn sddl_ace_count(sddl: &str) -> u32 {
        let descriptor = descriptor_from_sddl(sddl).unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        assert!(!dacl.is_null());
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        assert_ne!(
            unsafe {
                GetAclInformation(
                    dacl,
                    &mut info as *mut _ as *mut c_void,
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        unsafe { LocalFree(descriptor) };
        info.AceCount
    }

    #[test]
    fn protected_acl_expectations_use_windows_canonical_generic_mapping() {
        let sid = "S-1-5-21-1-2-3-1001";
        let directory = runtime_dacl_sddl(sid);
        let file = file_dacl_sddl(sid);
        assert!(directory.contains("(A;;0x1200a9;;;"));
        assert!(directory.contains("(A;OICIIO;GRGX;;;"));
        assert!(file.contains("(A;;0x1200a9;;;"));
        assert_eq!(sddl_ace_count(&directory), 4);
        assert_eq!(sddl_ace_count(&file), 3);
    }

    #[test]
    fn authenticated_client_guard_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuthenticatedClient>();
    }
}
