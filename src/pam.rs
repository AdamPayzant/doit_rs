use std::{ffi, ptr, panic};
use ffi::CString;

const SERVICE_NAME: &str = "doit";


// C bindings

#[repr(C)]
struct pam_message {
    msg_style: ffi::c_int,
    msg: *const ffi::c_char,
}

#[repr(C)]
struct pam_response {
    resp: *mut ffi::c_char,
    resp_retcode: ffi::c_int,
}

#[repr(C)]
struct pam_conv {
    pub conv: unsafe extern "C" fn(
        num_msg: ffi::c_int,
        msg: *mut *const pam_message,
        resp: *mut *mut pam_response,
        appdata_ptr: *mut ffi::c_void,
    ) -> ffi::c_int,
    pub appdata_ptr: *mut ffi::c_void,
}

#[repr(C)]
pub struct pam_handle_t {
    _unused: [u8; 0],
}

#[link(name="pam")]
extern {
    fn pam_start(SERVICE_NAME: *const ffi::c_char,
                 user: *const ffi::c_char,
                 pam_conversation: *const pam_conv,
                 pamh: *mut *mut pam_handle_t) -> ffi::c_int;
    fn pam_authenticate(pamh: *mut pam_handle_t,
                        flags: ffi::c_int) -> ffi::c_int;
    fn pam_end(pamh: *mut pam_handle_t, pam_status: ffi::c_int) -> ffi::c_int;
    fn pam_acct_mgmt(pamh: *mut pam_handle_t, flags: ffi::c_int) -> ffi::c_int;
}
#[link(name="pam_misc")]
extern {
    fn misc_conv(num_msg: ffi::c_int, 
        msgm: *mut *const pam_message,
        response: *mut *mut pam_response,
        appdata_ptr: *mut ffi::c_void) -> ffi::c_int;
}


enum PAMRetVal {
    PAMSuccess = 0,
}

pub fn pam_verify_user(username: &str) -> bool {
    let conv = pam_conv {
        conv: misc_conv,
        appdata_ptr: ptr::null_mut::<ffi::c_void>(),
    };
    let mut pamh: *mut pam_handle_t = ptr::null_mut::<pam_handle_t>();
    
    let service_name_cstr = CString::new(SERVICE_NAME).unwrap();
    let user_cstr = CString::new(username).unwrap();

    let mut ret = unsafe { pam_start(
        service_name_cstr.as_ptr(),
        user_cstr.as_ptr(),
        &conv,
        ptr::addr_of_mut!(pamh),
    )};
    if ret != PAMRetVal::PAMSuccess as i32 {
        return false;
    }

    // Authenticate user
    ret = unsafe { pam_authenticate(pamh, 0) };
    if ret != PAMRetVal::PAMSuccess as i32 {
        return false;
    }
    
    // Does the user have access
    ret = unsafe { pam_acct_mgmt(pamh, 0) };
    if ret != PAMRetVal::PAMSuccess as i32 {
        return false;
    }

    // Close the session
    ret = unsafe { pam_end(pamh, ret as i32) };
    if ret != PAMRetVal::PAMSuccess as i32 {
        panic!("Failed to release PAM authenticator");
    }

    // If we've made it this far, the user's good
    true
}
