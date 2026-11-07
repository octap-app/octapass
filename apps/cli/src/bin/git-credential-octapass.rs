//! Git's credential helper: `credential.helper = octapass` runs this with `get`, `store` or
//! `erase`. See `octapass git setup`.

fn main() {
    let context = match octapass_cli::Context::system() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("octapass: {error}");
            std::process::exit(1);
        }
    };
    let args = ["octapass", "git", "credential"]
        .into_iter()
        .map(std::ffi::OsString::from)
        .chain(std::env::args_os().skip(1));
    std::process::exit(octapass_cli::run(args, context));
}
