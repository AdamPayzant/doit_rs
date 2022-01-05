/*  
 * A collection of safe wrappers for my pam bindings.
 * 
 * Note: A detailed usage guide can be found here:
 * http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_ADG.html
 */

use num_traits::FromPrimitive;
use std::{ffi::CString, ptr, mem::transmute};
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
    FailDelay(unsafe extern "C" fn(retval: std::os::raw::c_int, usec_delay: std::os::raw::c_uint, *const std::os::raw::c_void)),
    XDisplay(String),
    XAuthData(pam_xauth_data), // Wow, I've got absolutely no idea what fills this one
    AuthtokType(String),
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

