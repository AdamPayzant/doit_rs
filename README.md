# doit.rs

A simplified privledge escalation tool.

## Building

This project uses the [`just` command runner](https://github.com/casey/just) and requires root permissions.
You will also need [rustup installed](https://rustup.rs/).

Once you have those installed, run the following command:

`just release`

The built binary will be found under `target/release/doit`.

## Usage

`doit` is a very simple command. Add your username to the doit.conf file, then preprend a command to run as root.

## Important Points for Consideration

* Just because this program attempts to make use of memory safety and a smaller codebase
does not mean this program is more secure. Memory safety is just one facet of the broad
Security landscape and logical errors may pose a greater threat. Sudo is a massive
is a massive codebase and has thousands of eyes on it.
* If those previous points didn't dissuade you, please do not use this program!
There are absolutely no security guarantees!


## Remaining Goals

- [X] PAM support - This currently only supports shadow authentication. 
It would be nice to add PAM support like I originally intended.
- [ ] Unit tests
- [ ] Actual release mode - We do a few awkward things like having the `doit.conf` file in the project directory where non-root users can read/write to it.
This is bad and should be fixed.

