//! Where the optional backend DLLs (`wintun.dll`, `libslirp-0.dll`,
//! `tinyvmm_gvisor.dll`) load from: one absolute path each, and nowhere else.
//!
//! A DLL loaded by its bare name is looked for next to the executable and in
//! the system directories, then in the current directory, then along `PATH`.
//! One that isn't installed next to the executable is then taken from
//! wherever tinyvmm happens to be started (a folder a guest can write to
//! through a share, say) and runs inside the VMM, with administrator rights
//! for WinTun. So each backend DLL has exactly one place: the path in its
//! environment variable if that is set, else the running executable's
//! directory. What it imports in turn comes from its own directory, the
//! executable's or System32 (the `LOAD_LIBRARY_SEARCH_*` flags in [`load_at`]
//! replace the standard search order, so neither the current directory nor
//! `PATH` is consulted). A DLL that isn't there, or doesn't load, is an error
//! that names the path: there is no fallback.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

/// Load `dll` from the path in the environment variable `env` if it is set
/// (and not empty), else from the running executable's directory. `hint` ends
/// the error message: how to get the DLL there.
pub(crate) fn load(dll: &str, env: &str, hint: &str) -> Result<HMODULE, String> {
    let over = std::env::var_os(env).filter(|p| !p.is_empty());
    load_from(dll, over.as_deref(), hint)
}

/// [`load`], given the environment override (if any) rather than its name.
fn load_from(dll: &str, over: Option<&OsStr>, hint: &str) -> Result<HMODULE, String> {
    let path = locate(dll, over)?;
    load_at(&path).map_err(|e| format!("{e}; {hint}"))
}

/// The one path `dll` may load from: `over`, its environment override, made
/// absolute; else `dll` in the running executable's directory. The file need
/// not exist.
fn locate(dll: &str, over: Option<&OsStr>) -> Result<PathBuf, String> {
    match over {
        Some(p) => std::path::absolute(p)
            .map_err(|e| format!("{dll}: bad path {}: {e}", Path::new(p).display())),
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(dll)))
            .ok_or_else(|| format!("{dll}: can't tell which directory tinyvmm.exe is in")),
    }
}

/// Load the DLL at `path`. Only an absolute path is accepted: a relative one,
/// or a bare name, would be looked up along the search path.
fn load_at(path: &Path) -> Result<HMODULE, String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    if !path.is_file() {
        return Err(format!("{} not found", path.display()));
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: a NUL-terminated absolute path, which these flags require.
    // Imports are looked for in the DLL's directory, then the executable's,
    // then System32, and nowhere else.
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR
                | LOAD_LIBRARY_SEARCH_APPLICATION_DIR
                | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        // SAFETY: plain thread-local error query.
        let err = unsafe { GetLastError() };
        return Err(format!(
            "could not load {} (err={err}; the DLLs it imports must be in its directory, \
             tinyvmm.exe's or System32)",
            path.display()
        ));
    }
    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe_dir() -> PathBuf {
        let exe = std::env::current_exe().unwrap();
        exe.parent().unwrap().to_path_buf()
    }

    /// A DLL every Windows has in System32.
    fn system32(dll: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot is set");
        PathBuf::from(root).join("System32").join(dll)
    }

    /// Without an override a DLL belongs next to the executable. An override
    /// replaces that place, and a relative one is made absolute: whatever is
    /// asked for, the loader gets one absolute path.
    #[test]
    fn each_dll_has_one_absolute_path() {
        let next_to_exe = locate("x.dll", None).unwrap();
        assert_eq!(next_to_exe, exe_dir().join("x.dll"));
        assert!(next_to_exe.is_absolute());

        let abs = system32("y.dll");
        assert_eq!(locate("x.dll", Some(abs.as_os_str())).unwrap(), abs);

        let cwd = std::env::current_dir().unwrap();
        for rel in ["sub\\y.dll", "sub/y.dll", "y.dll", ".\\y.dll"] {
            let got = locate("x.dll", Some(OsStr::new(rel))).unwrap();
            assert!(got.is_absolute(), "{rel} -> {}", got.display());
            assert!(got.starts_with(&cwd), "{rel} -> {}", got.display());
            assert_eq!(got.file_name(), Some(OsStr::new("y.dll")));
        }
        assert_eq!(
            locate("x.dll", Some(OsStr::new("sub\\y.dll"))).unwrap(),
            cwd.join("sub").join("y.dll")
        );
    }

    /// A DLL that isn't at its path is an error naming that path, even when a
    /// search would have found one: kernel32.dll is in System32 (and already
    /// loaded), which a bare-name load would return.
    #[test]
    fn missing_dll_is_an_error_not_a_search() {
        let want = exe_dir().join("kernel32.dll");
        assert!(!want.exists(), "{} exists", want.display());
        for err in [
            load_from("kernel32.dll", None, "HINT").unwrap_err(),
            // An environment variable that isn't set: the same place.
            load("kernel32.dll", "TINYVMM_TEST_NEVER_SET", "HINT").unwrap_err(),
        ] {
            assert!(err.contains(&want.display().to_string()), "{err}");
            assert!(err.contains("not found"), "{err}");
            assert!(err.ends_with("; HINT"), "{err}");
        }

        // A missing override is an error too, naming it. The executable's
        // directory is no fallback: the file asked for by name exists there.
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_str().unwrap();
        let missing = exe_dir().join("no-such-dir").join(name);
        let err = load_from(name, Some(missing.as_os_str()), "HINT").unwrap_err();
        assert!(err.contains(&missing.display().to_string()), "{err}");
        assert!(err.contains("not found"), "{err}");
    }

    /// The loader itself refuses anything but an absolute path, so no bare
    /// name or relative path can reach the DLL search order.
    #[test]
    fn only_an_absolute_path_reaches_the_loader() {
        for p in [
            "kernel32.dll",
            "System32\\kernel32.dll",
            ".\\kernel32.dll",
            "\\Windows\\System32\\kernel32.dll",
            "C:kernel32.dll",
        ] {
            let err = load_at(Path::new(p)).unwrap_err();
            assert!(err.contains("not an absolute path"), "{p}: {err}");
        }
    }

    /// An absolute path loads, here from System32 through the override, with
    /// the search flags the backend DLLs get.
    #[test]
    fn absolute_path_loads() {
        let path = system32("version.dll");
        let module = load_from("version.dll", Some(path.as_os_str()), "HINT").unwrap();
        assert!(!module.is_null());
    }
}
