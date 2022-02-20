/* 
 * doit.rs
 *
 * copyright (c) Edward Adam Payzant <payzantedwardiv@gmail.com>
 */

use std;
use std::{error::Error, io::Write, env, str::FromStr, ptr::null_mut};
use whoami;
use rpassword;

mod pam_mod;
use pam_mod::pam;

//const DOIT_LIST: &str = "/etc/doit.conf";
const SERVICE_NAME: String = String::from("doit");

unsafe extern "C" fn conv (
    num_msg: std::os::raw::c_int,
    msg: *mut *const pam::pam_message,
    resp: *mut *mut pam::pam_response,
    appdata_ptr: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    1
}

// Verifies user with PAM
fn verify_password(user:String, pwd: String) -> Result<bool, Box<dyn Error>> {
    let handle = pam::safe_pam_start(SERVICE_NAME, user, pam::pam_conv {
        conv: Some(conv), 
        appdata_ptr: null_mut(), 
    });
    Ok(true)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let user = whoami::username();
    // God I hate how long this line is
    print!("doit ({}@{}) password: ", user, whoami::hostname());
    std::io::stdout().flush().unwrap_or(());
    let pass = rpassword::read_password().unwrap();

    match verify_password(user, pass) {
        Ok(true) => println!("Authentication success"),
        Ok(false) => println!("Could not authenticate"),
        _ => println!("Something went wrong"),
    }
}

