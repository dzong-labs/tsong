//! Normalizing query parameter and header names, so a refused name is
//! found however a downstream framework could spell it. The rules are
//! described in docs/notes/gateway-plan.md.

use std::char::ToLowercase;
use std::str::Chars;

/// `c` case-folded, as part of a name, keeping only ASCII letters and
/// digits. A character that Java, JavaScript or .NET upper- or lowercases
/// to ASCII letters folds to them, and so does a fullwidth form.
pub fn fold_name_char(c: char) -> impl Iterator<Item = char> {
    let folded = match ascii_case_mapping(c) {
        Some(letters) => Folded::Ascii(letters.chars()),
        None => {
            let c = match c {
                '\u{FF01}'..='\u{FF5E}' => char::from_u32(u32::from(c) - 0xFEE0).unwrap_or(c),
                c => c,
            };
            Folded::Lower(c.to_lowercase())
        }
    };
    folded.filter(char::is_ascii_alphanumeric)
}

/// The ASCII letters a non-ASCII character's upper- or lowercase mapping
/// holds in Java, JavaScript or .NET, lowercased: simple mappings such as
/// the dotless `ı` to `I`, and full ones such as `ß` to `SS` or the
/// ligature `ﬁ` to `FI`. Combining marks in a mapping are dropped.
fn ascii_case_mapping(c: char) -> Option<&'static str> {
    Some(match c {
        '\u{00DF}' => "ss",  // ß -> SS
        '\u{0130}' => "i",   // İ -> i̇
        '\u{0131}' => "i",   // ı -> I
        '\u{0149}' => "n",   // ŉ -> ʼN
        '\u{017F}' => "s",   // ſ -> S
        '\u{01F0}' => "j",   // ǰ -> J̌
        '\u{1E96}' => "h",   // ẖ -> H̱
        '\u{1E97}' => "t",   // ẗ -> T̈
        '\u{1E98}' => "w",   // ẘ -> W̊
        '\u{1E99}' => "y",   // ẙ -> Y̊
        '\u{1E9A}' => "a",   // ẚ -> Aʾ
        '\u{212A}' => "k",   // K -> k
        '\u{FB00}' => "ff",  // ﬀ -> FF
        '\u{FB01}' => "fi",  // ﬁ -> FI
        '\u{FB02}' => "fl",  // ﬂ -> FL
        '\u{FB03}' => "ffi", // ﬃ -> FFI
        '\u{FB04}' => "ffl", // ﬄ -> FFL
        '\u{FB05}' => "st",  // ﬅ -> ST
        '\u{FB06}' => "st",  // ﬆ -> ST
        _ => return None,
    })
}

/// A folded character: ASCII letters from the table, or a lowercasing.
enum Folded {
    Ascii(Chars<'static>),
    Lower(ToLowercase),
}

impl Iterator for Folded {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        match self {
            Self::Ascii(chars) => chars.next(),
            Self::Lower(chars) => chars.next(),
        }
    }
}

/// `name` normalized: each character folded, and everything but ASCII
/// letters and digits dropped, so `Access-Token` is `accesstoken`.
pub fn normalize_name(name: &str) -> String {
    name.chars().flat_map(fold_name_char).collect()
}
