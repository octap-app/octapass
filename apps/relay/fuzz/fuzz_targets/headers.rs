#![no_main]

use libfuzzer_sys::fuzz_target;
use octapass_relay::rewrite::{self, Forward, Reply};

fuzz_target!(|data: &[u8]| {
    let Ok((fields, body)) = rewrite::split(data) else {
        return;
    };
    let forwarded = rewrite::forward(
        &fields,
        body,
        &Forward {
            alias: "alias@relay.example",
            reverse: "r-x@relay.example",
            sender: "jane@sender.example",
            sender_name: Some("Jane"),
            domain: "relay.example",
            results: "Authentication-Results: relay.example; none\r\n",
        },
    );
    // What goes out has one From, whatever came in.
    let (out, _) = rewrite::split(&forwarded).expect("forwarded headers parse");
    assert_eq!(rewrite::count_field(&out, "from"), 1);
    let replied = rewrite::reply(
        &fields,
        body,
        &Reply {
            alias: "alias@relay.example",
            to: "jane@sender.example",
            domain: "relay.example",
            message_id: "x",
            date: "Mon, 02 Nov 2026 10:00:00 +0000",
        },
    );
    let (out, _) = rewrite::split(&replied).expect("reply headers parse");
    assert_eq!(rewrite::count_field(&out, "from"), 1);
});
