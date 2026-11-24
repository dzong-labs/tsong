//! Normalizing query parameter names, so a refused name is found however a
//! downstream framework could spell it. The rules are described in
//! docs/notes/gateway-plan.md.

/// `c` case-folded, as part of a name, and kept only if it is an ASCII
/// letter or digit. The long s, the Kelvin sign and the fullwidth forms
/// fold to the ASCII letters and digits they stand for.
pub fn fold_name_char(c: char) -> impl Iterator<Item = char> {
    let c = match c {
        '\u{017F}' => 's',
        '\u{212A}' => 'k',
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(u32::from(c) - 0xFEE0).unwrap_or(c),
        c => c,
    };
    c.to_lowercase().filter(char::is_ascii_alphanumeric)
}

/// `name` normalized: each character folded, and everything but ASCII
/// letters and digits dropped, so `Access-Token` is `accesstoken`.
pub fn normalize_name(name: &str) -> String {
    name.chars().flat_map(fold_name_char).collect()
}
