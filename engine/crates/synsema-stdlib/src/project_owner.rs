//! v0.6.58 (§3 de `specs/v0.6.58-diseno.md`, D-18 (b), E-8): un `synsema.json` que no es del usuario
//! que corre se ignora, como `safe.directory` de git. Se mira sobre el archivo **ya abierto**
//! (`fstat` en Unix; `GetSecurityInfo` sobre el handle en Windows), y el núcleo parsea esos mismos
//! bytes: no hay ventana entre mirar y leer.
//!
//! - Unix: el uid dueño contra el uid efectivo.
//! - Windows: el SID dueño contra el SID del usuario del token; también vale el grupo
//!   Administradores si el token lo tiene (un archivo que crea un administrador elevado queda a
//!   nombre del grupo, como lo acepta git).

/// Registra el chequeo en el núcleo (una vez por proceso).
pub fn install() {
    synsema_core::project::set_owner_check(owned_by_current_user);
}

#[cfg(unix)]
fn owned_by_current_user(f: &std::fs::File) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let md = f.metadata().map_err(|e| e.to_string())?;
    // SAFETY: `geteuid` no toma argumentos, no falla y no toca memoria.
    let me = unsafe { libc::geteuid() };
    Ok(md.uid() == me)
}

#[cfg(windows)]
fn owned_by_current_user(f: &std::fs::File) -> Result<bool, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, PSID};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, IsWellKnownSid, TokenGroups, TokenUser, WinBuiltinAdministratorsSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// La información del token en un búfer alineado a 8 (`TOKEN_USER`/`TOKEN_GROUPS` tienen punteros).
    fn token_info(token: HANDLE, class: i32) -> Result<Vec<u64>, String> {
        let mut need = 0u32;
        // SAFETY: primera llamada con búfer nulo y largo 0: sólo escribe el largo necesario en `need`.
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut need) };
        if need == 0 {
            return Err(format!("GetTokenInformation: {}", std::io::Error::last_os_error()));
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: `buf` tiene al menos `need` bytes, alineados a 8, y vive mientras se use.
        let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) };
        if ok == 0 {
            return Err(format!("GetTokenInformation: {}", std::io::Error::last_os_error()));
        }
        Ok(buf)
    }

    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: el handle es el del archivo abierto (vive en `f`); `owner` apunta adentro de `sd`, que
    // se libera con `LocalFree` al final y no se usa después.
    let rc = unsafe {
        GetSecurityInfo(
            f.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("GetSecurityInfo: {}", std::io::Error::from_raw_os_error(rc as i32)));
    }
    struct FreeSd(PSECURITY_DESCRIPTOR);
    impl Drop for FreeSd {
        fn drop(&mut self) {
            // SAFETY: lo reservó `GetSecurityInfo` y se libera una sola vez.
            unsafe { LocalFree(self.0 as _) };
        }
    }
    let _sd = FreeSd(sd);
    // B12 (ronda 1): en un volumen sin ACL el descriptor puede no tener dueño. Sin dueño válido no se
    // puede decir de quién es: error (el que llama lo ignora con aviso), nunca un SID nulo a `EqualSid`.
    if !owner_is_valid(owner) {
        return Err("the file has no valid owner (a volume without permissions?)".to_string());
    }
    let mut token: HANDLE = 0;
    // SAFETY: el pseudo-handle del proceso actual; `token` recibe un handle que se cierra abajo.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!("OpenProcessToken: {}", std::io::Error::last_os_error()));
    }
    struct Close(HANDLE);
    impl Drop for Close {
        fn drop(&mut self) {
            // SAFETY: el handle del token, abierto arriba y cerrado una sola vez.
            unsafe { CloseHandle(self.0) };
        }
    }
    let _token = Close(token);
    let user = token_info(token, TokenUser)?;
    // SAFETY: `user` es un `TOKEN_USER` que escribió el sistema, alineado y del largo que pidió.
    let user_sid = unsafe { (*(user.as_ptr() as *const TOKEN_USER)).User.Sid };
    // SAFETY: dos SID válidos (el del token, vivo en `user`; el dueño, vivo en `sd`).
    if unsafe { EqualSid(owner, user_sid) } != 0 {
        return Ok(true);
    }
    // SAFETY: `owner` es un SID válido mientras viva `sd`.
    if unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) } == 0 {
        return Ok(false);
    }
    // winnt.h (están en `Win32_System_SystemServices` de windows-sys, que no se habilita por dos números).
    const SE_GROUP_ENABLED: u32 = 0x0000_0004;
    const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
    let groups = token_info(token, TokenGroups)?;
    // SAFETY: `groups` es un `TOKEN_GROUPS` que escribió el sistema: `GroupCount` entradas seguidas a
    // partir de `Groups`, todas dentro del búfer.
    let in_admins = unsafe {
        let g = groups.as_ptr() as *const TOKEN_GROUPS;
        let n = (*g).GroupCount as usize;
        let first = std::ptr::addr_of!((*g).Groups) as *const SID_AND_ATTRIBUTES;
        // N4 (ronda 1): el grupo cuenta sólo habilitado y no «sólo para denegar» (un token sin elevar
        // de UAC lo trae así), como `CheckTokenMembership`, que es lo que usa git.
        (0..n).any(|i| {
            let ga = &*first.add(i);
            IsWellKnownSid(ga.Sid, WinBuiltinAdministratorsSid) != 0 && ga.Attributes & SE_GROUP_ENABLED != 0 && ga.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0
        })
    };
    Ok(in_admins)
}

/// B12 (ronda 1): un dueño que se puede comparar: no nulo y un SID válido.
#[cfg(windows)]
fn owner_is_valid(owner: windows_sys::Win32::Foundation::PSID) -> bool {
    // SAFETY: `owner` es nulo (no se lee) o apunta a un SID vivo del que llama; `IsValidSid` sólo lo lee.
    !owner.is_null() && unsafe { windows_sys::Win32::Security::IsValidSid(owner) } != 0
}

#[cfg(not(any(unix, windows)))]
fn owned_by_current_user(_f: &std::fs::File) -> Result<bool, String> {
    Err("no owner check on this system".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_file_this_process_creates_is_its_own() {
        let dir = std::env::temp_dir().join(format!("syn-owner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("synsema.json");
        std::fs::write(&p, b"{}").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        assert_eq!(super::owned_by_current_user(&f), Ok(true));
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// B12 (ronda 1): un dueño nulo (un volumen sin ACL) no se compara: el chequeo da error, que el
    /// que llama ignora con aviso.
    #[cfg(windows)]
    #[test]
    fn a_null_owner_is_not_valid() {
        assert!(!super::owner_is_valid(std::ptr::null_mut()));
    }
}
