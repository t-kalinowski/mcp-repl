#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use crate::sandbox::SandboxPolicy;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::LUID;
use windows_sys::Win32::Foundation::SetHandleInformation;
use windows_sys::Win32::Foundation::WAIT_FAILED;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::AdjustTokenPrivileges;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_UNKNOWN;
use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
use windows_sys::Win32::Security::CopySid;
use windows_sys::Win32::Security::CreateRestrictedToken;
use windows_sys::Win32::Security::CreateWellKnownSid;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::Security::SetTokenInformation;
use windows_sys::Win32::Security::TOKEN_ADJUST_DEFAULT;
use windows_sys::Win32::Security::TOKEN_ADJUST_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_ADJUST_SESSIONID;
use windows_sys::Win32::Security::TOKEN_ASSIGN_PRIMARY;
use windows_sys::Win32::Security::TOKEN_DUPLICATE;
use windows_sys::Win32::Security::TOKEN_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Security::TokenDefaultDacl;
use windows_sys::Win32::Security::TokenGroups;
use windows_sys::Win32::System::Console::GetStdHandle;
use windows_sys::Win32::System::Console::STD_ERROR_HANDLE;
use windows_sys::Win32::System::Console::STD_INPUT_HANDLE;
use windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE;
use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
use windows_sys::Win32::System::JobObjects::CreateJobObjectW;
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
use windows_sys::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
use windows_sys::Win32::System::JobObjects::JobObjectExtendedLimitInformation;
use windows_sys::Win32::System::JobObjects::SetInformationJobObject;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::CreateProcessAsUserW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOW;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const DISABLE_MAX_PRIVILEGE: u32 = 0x01;
const LUA_TOKEN: u32 = 0x04;
const WRITE_RESTRICTED: u32 = 0x08;
const GENERIC_ALL: u32 = 0x1000_0000;
const WIN_WORLD_SID: i32 = 1;
const SE_GROUP_LOGON_ID: u32 = 0xC0000000;
const HANDLE_FLAG_INHERIT: u32 = 0x00000001;

#[repr(C)]
struct TokenDefaultDaclInfo {
    default_dacl: *mut ACL,
}

pub fn run_sandboxed_command(
    policy: &SandboxPolicy,
    sandbox_policy_cwd: &Path,
    command: &[String],
) -> Result<i32, String> {
    if command.is_empty() {
        return Err("no command specified to execute".to_string());
    }

    match policy {
        SandboxPolicy::ReadOnly | SandboxPolicy::WorkspaceWrite { .. } => {}
        SandboxPolicy::DangerFullAccess | SandboxPolicy::ExternalSandbox { .. } => {
            return Err(
                "windows sandbox runner only supports read-only/workspace-write".to_string(),
            );
        }
    }

    unsafe {
        let base_token = get_current_token_for_restriction()?;
        let token_result = create_restricted_token_for_policy(base_token, policy);
        CloseHandle(base_token);
        let restricted_token = token_result?;

        let env_map = std::env::vars().collect::<HashMap<_, _>>();
        let spawn_result =
            create_process_as_user(restricted_token, command, sandbox_policy_cwd, &env_map);
        let (proc_info, _startup_info) = match spawn_result {
            Ok(value) => value,
            Err(err) => {
                CloseHandle(restricted_token);
                return Err(err);
            }
        };

        let job_handle = create_job_kill_on_close().ok();
        if let Some(job) = job_handle {
            let _ = AssignProcessToJobObject(job, proc_info.hProcess);
        }

        let wait_status = WaitForSingleObject(proc_info.hProcess, INFINITE);
        if wait_status == WAIT_FAILED {
            if let Some(job) = job_handle {
                CloseHandle(job);
            }
            CloseHandle(proc_info.hThread);
            CloseHandle(proc_info.hProcess);
            CloseHandle(restricted_token);
            return Err(format!(
                "WaitForSingleObject failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut exit_code: u32 = 1;
        if GetExitCodeProcess(proc_info.hProcess, &mut exit_code) == 0 {
            if let Some(job) = job_handle {
                CloseHandle(job);
            }
            CloseHandle(proc_info.hThread);
            CloseHandle(proc_info.hProcess);
            CloseHandle(restricted_token);
            return Err(format!(
                "GetExitCodeProcess failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        if let Some(job) = job_handle {
            CloseHandle(job);
        }
        CloseHandle(proc_info.hThread);
        CloseHandle(proc_info.hProcess);
        CloseHandle(restricted_token);

        Ok(exit_code as i32)
    }
}

unsafe fn create_job_kill_on_close() -> Result<HANDLE, String> {
    let h = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
    if h.is_null() {
        return Err("CreateJobObjectW failed".to_string());
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let ok = SetInformationJobObject(
        h,
        JobObjectExtendedLimitInformation,
        &mut limits as *mut _ as *mut _,
        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
    );
    if ok == 0 {
        CloseHandle(h);
        return Err("SetInformationJobObject failed".to_string());
    }
    Ok(h)
}

unsafe fn create_restricted_token_for_policy(
    base_token: HANDLE,
    policy: &SandboxPolicy,
) -> Result<HANDLE, String> {
    let mut logon_sid_bytes = get_logon_sid_bytes(base_token)?;
    let psid_logon = logon_sid_bytes.as_mut_ptr() as *mut c_void;
    let mut everyone = world_sid()?;
    let psid_everyone = everyone.as_mut_ptr() as *mut c_void;

    let mut restricted_sids: Vec<SID_AND_ATTRIBUTES> = Vec::new();
    let mut flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN;

    if matches!(policy, SandboxPolicy::ReadOnly) {
        flags |= WRITE_RESTRICTED;
        restricted_sids.push(SID_AND_ATTRIBUTES {
            Sid: psid_logon,
            Attributes: 0,
        });
        restricted_sids.push(SID_AND_ATTRIBUTES {
            Sid: psid_everyone,
            Attributes: 0,
        });
    }

    let mut new_token: HANDLE = std::ptr::null_mut();
    let sid_count = restricted_sids.len() as u32;
    let sid_ptr = if restricted_sids.is_empty() {
        std::ptr::null_mut()
    } else {
        restricted_sids.as_mut_ptr()
    };
    let ok = CreateRestrictedToken(
        base_token,
        flags,
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        sid_count,
        sid_ptr,
        &mut new_token,
    );
    if ok == 0 {
        return Err(format!("CreateRestrictedToken failed: {}", GetLastError()));
    }

    let dacl_sids = [psid_logon, psid_everyone];
    set_default_dacl(new_token, &dacl_sids)?;
    enable_single_privilege(new_token, "SeChangeNotifyPrivilege")?;
    Ok(new_token)
}

unsafe fn create_process_as_user(
    token: HANDLE,
    argv: &[String],
    cwd: &Path,
    env_map: &HashMap<String, String>,
) -> Result<(PROCESS_INFORMATION, STARTUPINFOW), String> {
    let cmdline_str = argv
        .iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmdline = to_wide(&cmdline_str);

    let env_block = make_env_block(env_map);
    let mut startup_info: STARTUPINFOW = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let desktop = to_wide("Winsta0\\Default");
    startup_info.lpDesktop = desktop.as_ptr() as *mut u16;
    ensure_inheritable_stdio(&mut startup_info)?;

    let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();
    let ok = CreateProcessAsUserW(
        token,
        std::ptr::null(),
        cmdline.as_mut_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        1,
        CREATE_UNICODE_ENVIRONMENT,
        env_block.as_ptr() as *mut c_void,
        to_wide(cwd).as_ptr(),
        &startup_info,
        &mut proc_info,
    );
    if ok == 0 {
        return Err(format!(
            "CreateProcessAsUserW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((proc_info, startup_info))
}

unsafe fn ensure_inheritable_stdio(startup_info: &mut STARTUPINFOW) -> Result<(), String> {
    for std_handle_kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let std_handle = GetStdHandle(std_handle_kind);
        if std_handle.is_null() || std_handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "GetStdHandle failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if SetHandleInformation(std_handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            return Err(format!(
                "SetHandleInformation failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    startup_info.dwFlags |= STARTF_USESTDHANDLES;
    startup_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup_info.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    Ok(())
}

fn make_env_block(env: &HashMap<String, String>) -> Vec<u16> {
    let mut items: Vec<(String, String)> =
        env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    items.sort_by(|a, b| {
        a.0.to_uppercase()
            .cmp(&b.0.to_uppercase())
            .then(a.0.cmp(&b.0))
    });
    let mut wide_env: Vec<u16> = Vec::new();
    for (key, value) in items {
        let mut entry = to_wide(format!("{key}={value}"));
        entry.pop();
        wide_env.extend_from_slice(&entry);
        wide_env.push(0);
    }
    wide_env.push(0);
    wide_env
}

fn to_wide<S: AsRef<OsStr>>(value: S) -> Vec<u16> {
    let mut wide: Vec<u16> = value.as_ref().encode_wide().collect();
    wide.push(0);
    wide
}

fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r' | '"'));
    if !needs_quotes {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }
    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes * 2));
    }
    quoted.push('"');
    quoted
}

unsafe fn set_default_dacl(token: HANDLE, sids: &[*mut c_void]) -> Result<(), String> {
    if sids.is_empty() {
        return Ok(());
    }

    let entries: Vec<EXPLICIT_ACCESS_W> = sids
        .iter()
        .map(|sid| EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: *sid as *mut u16,
            },
        })
        .collect();

    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    let status = SetEntriesInAclW(
        entries.len() as u32,
        entries.as_ptr(),
        std::ptr::null_mut(),
        &mut new_dacl,
    );
    if status != ERROR_SUCCESS {
        return Err(format!("SetEntriesInAclW failed: {status}"));
    }

    let mut info = TokenDefaultDaclInfo {
        default_dacl: new_dacl,
    };
    let ok = SetTokenInformation(
        token,
        TokenDefaultDacl,
        &mut info as *mut _ as *mut c_void,
        std::mem::size_of::<TokenDefaultDaclInfo>() as u32,
    );
    if ok == 0 {
        if !new_dacl.is_null() {
            LocalFree(new_dacl as HLOCAL);
        }
        return Err(format!(
            "SetTokenInformation(TokenDefaultDacl) failed: {}",
            GetLastError()
        ));
    }

    if !new_dacl.is_null() {
        LocalFree(new_dacl as HLOCAL);
    }
    Ok(())
}

unsafe fn enable_single_privilege(token: HANDLE, privilege_name: &str) -> Result<(), String> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = LookupPrivilegeValueW(
        std::ptr::null(),
        to_wide(privilege_name).as_ptr(),
        &mut luid,
    );
    if ok == 0 {
        return Err(format!("LookupPrivilegeValueW failed: {}", GetLastError()));
    }

    let mut privileges: TOKEN_PRIVILEGES = std::mem::zeroed();
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = 0x00000002;
    let ok = AdjustTokenPrivileges(
        token,
        0,
        &privileges,
        0,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if ok == 0 {
        return Err(format!("AdjustTokenPrivileges failed: {}", GetLastError()));
    }
    if GetLastError() != 0 {
        return Err(format!(
            "AdjustTokenPrivileges completed with error: {}",
            GetLastError()
        ));
    }
    Ok(())
}

unsafe fn get_current_token_for_restriction() -> Result<HANDLE, String> {
    let desired_access = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = OpenProcessToken(GetCurrentProcess(), desired_access, &mut token);
    if ok == 0 {
        return Err(format!("OpenProcessToken failed: {}", GetLastError()));
    }
    Ok(token)
}

unsafe fn world_sid() -> Result<Vec<u8>, String> {
    let mut sid_len: u32 = 0;
    CreateWellKnownSid(
        WIN_WORLD_SID,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut sid_len,
    );
    let mut sid = vec![0_u8; sid_len as usize];
    let ok = CreateWellKnownSid(
        WIN_WORLD_SID,
        std::ptr::null_mut(),
        sid.as_mut_ptr() as *mut c_void,
        &mut sid_len,
    );
    if ok == 0 {
        return Err(format!("CreateWellKnownSid failed: {}", GetLastError()));
    }
    Ok(sid)
}

unsafe fn get_logon_sid_bytes(token: HANDLE) -> Result<Vec<u8>, String> {
    unsafe fn scan_token_groups_for_logon(token: HANDLE) -> Option<Vec<u8>> {
        let mut required: u32 = 0;
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut required);
        if required == 0 {
            return None;
        }

        let mut groups_buf = vec![0_u8; required as usize];
        let ok = GetTokenInformation(
            token,
            TokenGroups,
            groups_buf.as_mut_ptr() as *mut c_void,
            required,
            &mut required,
        );
        if ok == 0 || (required as usize) < std::mem::size_of::<u32>() {
            return None;
        }

        let group_count = std::ptr::read_unaligned(groups_buf.as_ptr() as *const u32) as usize;
        let after_count = groups_buf.as_ptr().add(std::mem::size_of::<u32>()) as usize;
        let align = std::mem::align_of::<SID_AND_ATTRIBUTES>();
        let aligned = (after_count + (align - 1)) & !(align - 1);
        let groups_ptr = aligned as *const SID_AND_ATTRIBUTES;

        for index in 0..group_count {
            let entry = std::ptr::read_unaligned(groups_ptr.add(index));
            if (entry.Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID {
                continue;
            }
            let sid_len = GetLengthSid(entry.Sid);
            if sid_len == 0 {
                return None;
            }
            let mut sid = vec![0_u8; sid_len as usize];
            if CopySid(sid_len, sid.as_mut_ptr() as *mut c_void, entry.Sid) == 0 {
                return None;
            }
            return Some(sid);
        }

        None
    }

    if let Some(logon_sid) = scan_token_groups_for_logon(token) {
        return Ok(logon_sid);
    }

    #[repr(C)]
    struct TokenLinkedToken {
        linked_token: HANDLE,
    }
    const TOKEN_LINKED_TOKEN_CLASS: i32 = 19;

    let mut required: u32 = 0;
    GetTokenInformation(
        token,
        TOKEN_LINKED_TOKEN_CLASS,
        std::ptr::null_mut(),
        0,
        &mut required,
    );
    if required >= std::mem::size_of::<TokenLinkedToken>() as u32 {
        let mut linked_buf = vec![0_u8; required as usize];
        let ok = GetTokenInformation(
            token,
            TOKEN_LINKED_TOKEN_CLASS,
            linked_buf.as_mut_ptr() as *mut c_void,
            required,
            &mut required,
        );
        if ok != 0 {
            let linked = std::ptr::read_unaligned(linked_buf.as_ptr() as *const TokenLinkedToken);
            if !linked.linked_token.is_null() {
                let result = scan_token_groups_for_logon(linked.linked_token);
                CloseHandle(linked.linked_token);
                if let Some(logon_sid) = result {
                    return Ok(logon_sid);
                }
            }
        }
    }

    Err("logon SID not present on token".to_string())
}
