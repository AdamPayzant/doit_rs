/*  
 * A collection of safe wrappers for my pam bindings.
 * 
 * Note: A detailed usage guide can be found here:
 * http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_ADG.html
 */

use num_traits::FromPrimitive;
use std::{ffi::{CString, CStr}, ptr, mem::transmute};
use crate::pam::pam_bindings::*;
use enum_primitive_derive::Primitive;

#[repr(u32)]
#[derive(Primitive)]
pub enum PamReturn {
    Abort = PAM_ABORT,
    AcctExpired = PAM_ACCT_EXPIRED,
    AuthtokDisableAging  = PAM_AUTHTOK_DISABLE_AGING,
    AuthtokErr = PAM_AUTHTOK_ERR,
    AuthtokExpired = PAM_AUTHTOK_EXPIRED,
    AuthtokLockBusy = PAM_AUTHTOK_LOCK_BUSY,
    AuthtokRecoveryErr = PAM_AUTHTOK_RECOVERY_ERR,
    AuthErr = PAM_AUTH_ERR,
    BufErr = PAM_BUF_ERR,
    ConvErr = PAM_CONV_ERR,
    CredErr = PAM_CRED_ERR,
    CredExpired = PAM_CRED_EXPIRED,
    CredInsufficient = PAM_CRED_INSUFFICIENT,
    CredUnavail = PAM_CRED_UNAVAIL,
    Ignore = PAM_IGNORE,
    MaxTries = PAM_MAXTRIES,
    ModuleUnkown = PAM_MODULE_UNKNOWN,
    NewAuthtokReqd = PAM_NEW_AUTHTOK_REQD,
    NoModuleData = PAM_NO_MODULE_DATA,
    OpenErr = PAM_OPEN_ERR,
    PermDenied = PAM_PERM_DENIED,
    ServiceErr = PAM_SERVICE_ERR,
    Success = PAM_SUCCESS,
    SymbolErr = PAM_SYMBOL_ERR,
    TryAgain = PAM_TRY_AGAIN,
    UserUnknown = PAM_USER_UNKNOWN,
    SystemErr = PAM_SYSTEM_ERR,
    BadItem = PAM_BAD_ITEM,
}

#[repr(u32)]
#[derive(Primitive)]
pub enum PamItemType {
    Service = PAM_SERVICE,
    User = PAM_USER,
    UserPrompt = PAM_USER_PROMPT,
    TTY = PAM_TTY,
    RUser = PAM_RUSER,
    RHost = PAM_RHOST,
    Authtok = PAM_AUTHTOK,
    OldAuthtok = PAM_OLDAUTHTOK,
    Conv = PAM_CONV,
    FailDelay = PAM_FAIL_DELAY,
    XDisplay = PAM_XDISPLAY,
    XAuthData = PAM_XAUTHDATA,
    AuthtokType = PAM_AUTHTOK_TYPE,
}

pub enum PamItem {
    Service(String),
    User(String),
    UserPrompt(String),
    TTY(String),
    RUser(String),
    RHost(String),
    Authtok(String),
    OldAuthtok(String),
    Conv(pam_conv),
    FailDelay(unsafe extern "C" fn(
            retval: std::os::raw::c_int, 
            usec_delay: std::os::raw::c_uint, 
            *const std::os::raw::c_void)),
    XDisplay(String),
    XAuthData(pam_xauth_data),
    AuthtokType(String),
}

#[repr(u32)]
#[derive(Primitive)]
pub enum PamFlags {
    PamSilent = PAM_SILENT,
    PamDisallowNullAuthtok = PAM_DISALLOW_NULL_AUTHTOK,
}

pub fn safe_pam_start(service_name: String, user: String, conv: pam_conv) 
    -> (PamReturn, *mut pam_handle_t) {

    let mut handle: *mut pam_handle_t = ptr::null_mut();
    let service = CString::new(service_name).expect("CString::new failure");
    let usr = CString::new(user).expect("CString::new error");

    let res = unsafe {
        pam_start(
            service.as_ptr(), 
            usr.as_ptr(),
            &conv,
            &mut handle
        ) as u32
    };

    (PamReturn::from_u32(res).unwrap(), handle)
}

pub fn safe_pam_end(handle: *mut pam_handle_t, status: PamReturn) -> PamReturn {
    
    let res = unsafe {
        pam_end(handle, status as i32) as u32
    };
    PamReturn::from_u32(res).unwrap()
}

pub fn safe_pam_set_item(handle: *mut pam_handle_t, i: PamItem) -> PamReturn {
    let res = unsafe {
        // God I hate this match statement
        // NOTE: The strings might cause seg faults. Need to test this
        let (item_type, item): (u32, *mut std::os::raw::c_void) = match i {
            PamItem::Service(service) => 
                (PAM_SERVICE, 
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(service).expect("CString::new error").as_ptr())
            ),
            PamItem::User(user) => 
                (PAM_USER, 
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(user).expect("CString::new error").as_ptr())
                 ),
            PamItem::UserPrompt(prompt) => 
                (PAM_USER_PROMPT,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(prompt).expect("CString::new error").as_ptr())
                ),
            PamItem::TTY(tty) => 
                (PAM_TTY,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(tty).expect("CString::new error").as_ptr())
                ),
            PamItem::RUser(user) => 
                (PAM_RUSER,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(user).expect("CString::new error").as_ptr())
                ), 
            PamItem::RHost(host) => 
                (PAM_RHOST,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(host).expect("CString::new error").as_ptr())
                ),
            PamItem::Authtok(authtok) => 
                (PAM_AUTHTOK,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(authtok).expect("CString::new error").as_ptr())
                ),
            PamItem::OldAuthtok(authtok) => 
                (PAM_OLDAUTHTOK,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(authtok).expect("CString::new error").as_ptr())
                ),
            PamItem::Conv(conv) => 
                (PAM_CONV,
                 transmute::<*const pam_conv,*mut std::os::raw::c_void>(&conv)
                ),
            PamItem::FailDelay(delay) => 
                (PAM_FAIL_DELAY,
                 transmute::<
                    unsafe extern "C" fn(i32, u32, *const std::os::raw::c_void), 
                    *mut std::os::raw::c_void>(delay)
                ),
            PamItem::XDisplay(display) => 
                (PAM_XDISPLAY,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(display).expect("CString::new error").as_ptr())
                ),
            PamItem::XAuthData(data) => 
                (PAM_XAUTHDATA,
                 transmute::<*const pam_xauth_data, *mut std::os::raw::c_void>(&data)
                 ),
            PamItem::AuthtokType(typ) => 
                (PAM_AUTHTOK_TYPE,
                 transmute::<*const std::os::raw::c_char,*mut std::os::raw::c_void>(
                     CString::new(typ).expect("CString::new error").as_ptr())
                ),
        };
        pam_set_item(handle, item_type as i32, item)
    };
    PamReturn::from_u32(res as u32).unwrap() 
}

pub fn safe_pam_get_item(handle: *mut pam_handle_t, item_type: PamItemType) -> 
    (PamReturn, PamItem) {
    // I turned them into enums because I thought life would be all nice,
    // now we get these massive match statements
    let it_type = item_type as u32 as i32;
    unsafe {
        use std::os::raw::c_void;
        let i: *mut *const c_void = ptr::null_mut();
        let res = pam_get_item(handle, it_type, i);
        let item = match PamItemType::from_i32(it_type).unwrap() {
            PamItemType::Service => PamItem::Service(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::User => PamItem::User(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::UserPrompt => PamItem::UserPrompt(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::TTY => PamItem::TTY(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::RUser => PamItem::RUser(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::RHost => PamItem::RHost(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::Authtok => PamItem::Authtok(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::OldAuthtok => PamItem::OldAuthtok(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::Conv => PamItem::Conv(
                *transmute::<*const c_void, *const pam_conv>(*i)),
            PamItemType::FailDelay => PamItem::FailDelay(
                transmute::<*const c_void, 
                    unsafe extern "C" fn(i32, u32, *const c_void)>(*i)),
            PamItemType::XDisplay => PamItem::XDisplay(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
            PamItemType::XAuthData => PamItem::XAuthData(
                *transmute::<*const c_void, *const pam_xauth_data>(*i)),
            PamItemType::AuthtokType => PamItem::AuthtokType(
                CStr::from_ptr(
                    transmute::<*const c_void, *const std::os::raw::c_char>
                    (*i)).to_str().unwrap().to_owned()),
        };
        (PamReturn::from_u32(res as u32).unwrap(), item)
    }
}

pub fn safe_pam_strerror(handle: *mut pam_handle_t, errnum: i32) -> String {
    unsafe {
        let res: *const std::os::raw::c_char = pam_strerror(handle, errnum);
        CStr::from_ptr(res).to_str().unwrap().to_owned().clone()
    }
}

pub fn safe_pam_fail_delay(handle: *mut pam_handle_t, usec: u32) -> PamReturn {
    let res = unsafe {
        pam_fail_delay(handle, usec)
    };
    PamReturn::from_i32(res).unwrap()
}

pub fn safe_pam_authenticate(handle: *mut pam_handle_t, flags: i32) ->  PamReturn {
    PamReturn::from_i32(unsafe {pam_authenticate(handle, flags)}).unwrap()
}

pub fn safe_pam_setcred(handle: *mut pam_handle_t, flags: i32) -> PamReturn {
    PamReturn::from_i32(unsafe {pam_setcred(handle, flags)}).unwrap()
}

pub fn safe_pam_acct_mgmt(handle: *mut pam_handle_t, flags: i32) -> PamReturn {
    PamReturn::from_i32(unsafe {pam_acct_mgmt(handle, flags)}).unwrap()
}

pub fn safe_pam_chauthtok(handle: *mut pam_handle_t, flags: i32) -> PamReturn {
    PamReturn::from_i32(unsafe {pam_chauthtok(handle , flags)}).unwrap()
}

pub fn safe_pam_open_session(handle: *mut pam_handle_t, flags: i32) -> PamReturn {
    PamReturn::from_i32(unsafe {pam_open_session(handle, flags)}).unwrap()
}

pub fn safe_pam_close_session(handle: *mut pam_handle_t, flags: i32) -> PamReturn {
    PamReturn::from_i32(unsafe {pam_close_session(handle, flags)}).unwrap()
}

pub fn safe_pam_putenv(handle: *mut pam_handle_t, name: String) -> PamReturn {
    PamReturn::from_i32(unsafe {
        let n = CString::new(name).expect("CString::new error");
        pam_putenv(handle, n.as_ptr())
    }).unwrap()
}

pub fn safe_pam_getenv(handle: *mut pam_handle_t, name: String) -> Option<String> {
    let n = CString::new(name).expect("CString::new error");
    unsafe {
        let res = pam_getenv(handle, n.as_ptr());
        if res.is_null() {
            None
        } else {
            Some(CStr::from_ptr(res).to_str().unwrap().to_owned())
        }
    }
}

pub fn safe_pam_getenvlist(handle: *mut pam_handle_t) -> Option<Vec<String>> {
    unsafe {
        let res = pam_getenvlist(handle);
        if res.is_null() {
            None
        } else {
            let mut list: Vec<String> = Vec::new();
            

            None
        }
    }
}

