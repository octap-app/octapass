//! What `gpg.ssh.program` and `gpg.program` point to. Git runs it as it would run `ssh-keygen` or
//! `gpg`, so every argument is passed on untouched. See `octapass git setup`.

fn main() {
    let context = match octapass_cli::Context::system() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("octapass: {error}");
            std::process::exit(1);
        }
    };
    let args = ["octapass", "git", "sign", "--"]
        .into_iter()
        .map(std::ffi::OsString::from)
        .chain(std::env::args_os().skip(1));
    std::process::exit(octapass_cli::run(args, context));
}
