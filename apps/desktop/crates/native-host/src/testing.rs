//! For tests of the host and the app (feature `testing`): the built host binary, and a stand-in
//! browser that development builds accept because of where its executable is.

use std::path::{Path, PathBuf};

/// `target/<profile>`: test binaries run from its `deps` folder.
fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    exe.parent()
        .and_then(Path::parent)
        .expect("test binaries are in target/<profile>/deps")
        .to_owned()
}

fn built(path: PathBuf, what: &str) -> PathBuf {
    assert!(
        path.is_file(),
        "{} is missing: run the tests with `cargo test --workspace` so {what} is built",
        path.display()
    );
    path
}

/// The `octapass-native-host` binary from this build.
pub fn host_binary() -> PathBuf {
    let name = format!("octapass-native-host{}", std::env::consts::EXE_SUFFIX);
    built(target_dir().join(name), "octapass-native-host")
}

/// A copy of the `fake-browser` example under `dir`, at a path that names a known browser
/// (Firefox). Run it with the program to start and that program's arguments.
pub fn fake_browser(dir: &Path) -> PathBuf {
    let example = format!("fake-browser{}", std::env::consts::EXE_SUFFIX);
    let source = built(
        target_dir().join("examples").join(example),
        "the fake-browser example",
    );
    let browser = if cfg!(target_os = "macos") {
        dir.join("Firefox.app/Contents/MacOS/firefox")
    } else {
        dir.join(format!("firefox{}", std::env::consts::EXE_SUFFIX))
    };
    std::fs::create_dir_all(browser.parent().expect("has a folder")).expect("creates the folder");
    std::fs::copy(source, &browser).expect("copies the fake browser");
    browser
}
