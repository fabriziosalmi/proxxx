//! `--ipconfig`, `--net` and `--disk` values are parsed into typed specs and
//! printed back for PVE. Parsing never panics, and a parsed spec printed and
//! parsed again prints the same.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxxx::api::types::{Ipconfig, QemuDiskSpec, QemuNetSpec};

fn round_trip<T: std::str::FromStr + std::fmt::Display>(s: &str) {
    if let Ok(v) = s.parse::<T>() {
        let printed = v.to_string();
        let again = printed
            .parse::<T>()
            .unwrap_or_else(|_| panic!("printed form does not parse: {printed:?} (from {s:?})"));
        assert_eq!(
            again.to_string(),
            printed,
            "print/parse is not stable for {s:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    round_trip::<Ipconfig>(s);
    round_trip::<QemuNetSpec>(s);
    round_trip::<QemuDiskSpec>(s);
});
