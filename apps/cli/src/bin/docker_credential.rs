//! `docker-credential-octapass`: Docker runs a helper by this name with `get`, `store`, `erase` or
//! `list` as its only argument. See `octapass docker-credential`.

fn main() {
    let context = match octapass_cli::Context::system() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("docker-credential-octapass: {error}");
            std::process::exit(1);
        }
    };
    let args = ["octapass".into(), "docker-credential".into()]
        .into_iter()
        .chain(std::env::args_os().skip(1));
    std::process::exit(octapass_cli::run(args, context));
}
