use libc::{self};
use std::{ffi::{CString, CStr}};
use pwhash;

#[derive(Debug)]
#[allow(dead_code)]
pub enum ShadowError {
    UnknownEntry,
    CStrError(StringErrors),
    NullEntry,
    UnknownError,
}

#[derive(Debug)]
pub enum StringErrors {
    NulError(std::ffi::NulError),
    UTFError(std::str::Utf8Error),
}

pub fn verify_user(hash:&str, pw:&str) -> bool {
    pwhash::unix::verify(pw, hash)
}

pub fn get_shadow_hash(name:&str) -> Result<String, ShadowError > {
    let entry = unsafe {
        let res = libc::getpwnam(match CString::new(name) {
            Err(err) => Err(ShadowError::CStrError(StringErrors::NulError(err))),
            Ok(res) => Ok(res)
        }?.as_ptr());
        if res.is_null() {
            Err(ShadowError::NullEntry)
        } else {
            Ok(*res)
        }
    }?;

    let pw = match unsafe { CStr::from_ptr(entry.pw_passwd).to_str() } {
        Err(err) => Err(ShadowError::CStrError(StringErrors::UTFError(err))),
        Ok(res) => Ok(res),
    }?;

    if pw.as_bytes()[0] == 'x' as u8 && pw.len() == 1  {
        get_sp_password(name)
    }
    else if pw.as_bytes()[0] != '*' as u8 {
        Err(ShadowError::UnknownEntry)
    } 
    else {
        Ok(pw.to_owned())
    }
}

fn get_sp_password(name:&str) -> Result<String, ShadowError> {
    let entry = unsafe {
        let res = libc::getspnam(match CString::new(name) {
            Err(err) => Err(ShadowError::CStrError(StringErrors::NulError(err))),
            Ok(res) => Ok(res)
        }?.as_ptr());

        if res.is_null() {
            Err(ShadowError::NullEntry)
        } else {
            Ok(*res)
        }
    }?;

    let pw = match unsafe { CStr::from_ptr(entry.sp_pwdp).to_str() } {
        Err(err) => Err(ShadowError::CStrError(StringErrors::UTFError(err))),
        Ok(res) => Ok(res),
    }?;
    Ok(pw.to_owned())
}
