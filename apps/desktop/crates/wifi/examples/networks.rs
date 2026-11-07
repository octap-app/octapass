//! Prints what this computer's Wi-Fi tells Octa Pass: the permission, the current network, the
//! networks in range and the saved networks. Never reads passwords.
//!
//! `cargo run -p octapass-wifi --example networks [-- --scan]`

fn main() {
    let wifi = octapass_wifi::platform();
    let scan = std::env::args().any(|a| a == "--scan");
    println!("features:   {:?}", wifi.features());
    println!("permission: {:?}", wifi.permission());
    println!("current:    {:?}", wifi.current());
    match wifi.nearby(scan) {
        Ok(nearby) => println!("in range:   {nearby:?}"),
        Err(error) => println!("in range:   {error}"),
    }
    match wifi.saved() {
        Ok(saved) => {
            println!("saved:      {} networks", saved.len());
            for network in saved {
                println!(
                    "  {:?} security={:?} hidden={}",
                    network.ssid, network.security, network.hidden
                );
            }
        }
        Err(error) => println!("saved:      {error}"),
    }
}
