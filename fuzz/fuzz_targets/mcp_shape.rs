//! An MCP string parameter with shape `Name` or `Upid` becomes a PVE path
//! segment. Whatever the shape accepts must stay one segment: no separator,
//! no relative segment, no percent-escape, no control character.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxxx::mcp::tools::Shape;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };
    for shape in [Shape::Name, Shape::Upid] {
        if shape.check(value).is_err() {
            continue;
        }
        assert!(
            !value.is_empty() && value.len() <= 256,
            "{shape:?} accepted length {}",
            value.len()
        );
        assert!(
            !value.contains(['/', '\\', '%', '?', '#', '&', '=']),
            "{shape:?} accepted a separator: {value:?}"
        );
        assert!(
            !value.chars().any(char::is_control),
            "{shape:?} accepted a control character: {value:?}"
        );
        assert!(
            value != "." && value != "..",
            "{shape:?} accepted a relative segment"
        );
        assert!(
            !value.chars().all(|c| c == '.'),
            "{shape:?} accepted only dots: {value:?}"
        );
    }
    // Shape::Any is documented as unconstrained.
    assert!(Shape::Any.check(value).is_ok());
});
