//! `octapass`: see the library for the commands.

fn main() {
    let context = match octapass_cli::Context::system() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("octapass: {error}");
            std::process::exit(1);
        }
    };
    std::process::exit(octapass_cli::run(std::env::args_os(), context));
}
