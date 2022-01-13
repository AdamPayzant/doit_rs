# doit.rs

A simplified privledge escalation tool.
Attempting to combine the memory safety guarantees of Rust with a small, auditable
codebase.

I was really unhappy with the existing PAM options for rust, so this project has currently
devolved into me writing a safe wrapper for PAM.

## Important Points for Consideration

* Just because this program attempts to make use of memory safety and a smaller codebase
does not mean this program is more secure. Memory safety is just one facet of the broad
Security landscape and logical errors may pose a greater threat. Sudo is a massive
is a massive codebase and has thousands of eyes on it.
* If those previous points didn't dissuade you, please do not use this program!
There are absolutely no security guarantees!

