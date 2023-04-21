/* 
 * doit.rs
 *
 * copyright (c) Edward Adam Payzant <payzantedwardiv@gmail.com>
 */

use std;
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufRead, Write};
use std::os::unix::process::CommandExt;
use libc;
use rpassword;
use std::process::Command;

mod shadow;
mod pam;

//const DOIT_LIST: &str = "/etc/doit.conf";
const DOIT_LIST: &str = "doit.conf";

#[derive(Debug)]
#[allow(dead_code)]
enum UserError {
    NullEntry,
    StringError,
    UnknownError,
}

fn get_username() -> Result<String, UserError> {
    let uid = unsafe { libc::getuid() };
    match unsafe {
        let ptr = libc::getpwuid(uid);
        if ptr.is_null() {
            return Err(UserError::NullEntry);
        }
        let passwd = *ptr;
        CStr::from_ptr(passwd.pw_name).to_str()
    } {
        Ok(res) => Ok(res.to_owned()),
        Err(_) => Err(UserError::StringError),
    }
}

fn shadow_verify_password(user:&str, pass: &str) -> bool {
    let hash = match shadow::get_shadow_hash(user) {
        Ok(res) => res,
        Err(err) => {
            match err {
                shadow::ShadowError::CStrError(_) => println!("CString failure"),
                _ => println!("Failure: {:?}", err),
            };
            return false
        }
    };

    shadow::verify_user(hash.as_str(), pass)
}

#[derive(PartialEq)]
enum UserEntry {
    ShadowEntry,
    PamEntry,
    NotFound,
}

fn check_user_entry(user:&str) -> UserEntry {
    let lines = std::io::BufReader::new(match File::open(DOIT_LIST) {
        Ok(res) => res,
        Err(err) => {
            println!("{:?}", err);
            return UserEntry::NotFound;
        }
    }).lines();
    for line in lines {
        if line.is_ok() {
            let l = line.unwrap();
            let split: Vec<&str> = l.split_whitespace().collect();
            
            if split[0] == user {
                if split.len() > 1 && split[1].eq_ignore_ascii_case("PAM") {
                    return UserEntry::PamEntry;
                } else {
                    return UserEntry::ShadowEntry;
                }
            }
        }
    }
    UserEntry::NotFound
}

fn main() {
    let user = match get_username() {
        Ok(res) => res,
        Err(err) => {
            println!("Error {:?} while getting user", err);
            return;
        }
    };
    let entry = check_user_entry(user.as_str());
    if entry == UserEntry::NotFound {
        println!("User {} is not authorized", user);
        return;
    }
    
    let res: bool;
    if entry == UserEntry::ShadowEntry {
        // Verify via shadow
        print!("doit ({}@{}) password: ", user, whoami::hostname());
        std::io::stdout().flush().unwrap_or(());
        let pass = rpassword::read_password().unwrap();
        res = shadow_verify_password(user.as_str(), pass.as_str());
    } else {
        // Verify via PAM
        res = pam::pam_verify_user(user.as_str());
    }

    if !res {
        println!("User not authenticated");
        return;
    }

    // Okay, we've authroized the user, time to invoke
    if std::env::args().len() < 2 {
        println!("No arguments provided");
        return;
    }
    let name = std::env::args().collect::<Vec<String>>()[1].clone();
    let args:Vec<String> = std::env::args().skip(2).collect();
    let err = Command::new(name).args(&args).exec();
    println!("{:?}", err);
}

