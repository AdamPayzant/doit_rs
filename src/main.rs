// NOTE: Please ignore all this for now, all focus in on the pam wrapper

use std::{error::Error, io::Write, env};
use whoami;
use rpassword;

mod pam;

//const DOIT_LIST: &str = "/etc/doit.conf";


// Verifies user with PAM
fn verify_password(program: String, user:String, pwd: String) -> Result<bool, Box<dyn Error>> {
    // println!("user: {}, pass: {}", user, pwd);
    // //let mut auth = pam::Authenticator::with_password(program.as_str())?;
    // auth.get_handler().set_credentials(user, pwd);
    // if auth.authenticate().is_ok() && auth.open_session().is_ok() {
    //     Ok(true)
    // }
    // else {
    //     Ok(false)
    // }
    Ok(true)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let program = args[0].clone();
    let user = whoami::username();
    // God I hate how long this line is
    print!("doit ({}@{}) password: ", user, whoami::hostname());
    std::io::stdout().flush().unwrap_or(());
    let pass = rpassword::read_password().unwrap();

    match verify_password(program, user, pass) {
        Ok(true) => println!("Authentication success"),
        Ok(false) => println!("Could not authenticate"),
        _ => println!("Something went wrong"),
    }
}

