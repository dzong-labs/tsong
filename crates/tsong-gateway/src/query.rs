//! Finding an `access_token` in a request's query (RFC 6750 section 2.3),
//! as some downstream framework could read it. The normalization is
//! described in docs/notes/gateway-plan.md.

use std::borrow::Cow;

/// `access_token`, as normalization leaves it.
const ACCESS_TOKEN: &[u8] = b"accesstoken";

/// The most decoding passes a name gets, so `%255F` decodes too.
const PASSES: usize = 3;

/// Whether `query` has an `access_token` parameter: pairs split on `&` or
/// `;`, each name percent-decoded and normalized.
pub(crate) fn has_access_token(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        query.split(['&', ';']).any(|pair| {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            reads_as_access_token(&percent_decoded(name.as_bytes()))
        })
    })
}

/// Whether the decoded name `name` normalizes to `accesstoken`, whole or
/// cut at its first NUL or `[`: case-folded and stripped of everything
/// but ASCII letters and digits. Both forms are read in one pass.
fn reads_as_access_token(name: &[u8]) -> bool {
    // Each byte yields at most one ASCII letter or digit.
    if name.len() < ACCESS_TOKEN.len() {
        return false;
    }
    let cut = name.iter().position(|&byte| byte == 0 || byte == b'[');
    let mut matched = 0;
    let mut cut_matches = None;
    let mut offset = 0;
    for chunk in name.utf8_chunks() {
        for (at, c) in chunk.valid().char_indices() {
            if cut == Some(offset + at) {
                cut_matches = Some(matched == ACCESS_TOKEN.len());
            }
            for folded in folded(c).filter(char::is_ascii_alphanumeric) {
                let expected = ACCESS_TOKEN.get(matched).copied().map(char::from);
                if expected != Some(folded) {
                    // The cut form ended before this, or shares the miss.
                    return cut_matches.unwrap_or(false);
                }
                matched += 1;
            }
        }
        offset += chunk.valid().len() + chunk.invalid().len();
    }
    matched == ACCESS_TOKEN.len() || cut_matches.unwrap_or(false)
}

/// `c` lowercased, with the two non-ASCII characters whose Unicode simple
/// case folding is an ASCII letter, the long s and the Kelvin sign, folded
/// to it.
fn folded(c: char) -> std::char::ToLowercase {
    match c {
        '\u{017F}' => 's'.to_lowercase(),
        '\u{212A}' => 'k'.to_lowercase(),
        c => c.to_lowercase(),
    }
}

/// `name` percent-decoded as some downstream could read it: `%XX`, and
/// IIS's `%uXXXX` as UTF-8, with `+` read as a space. Decoding repeats
/// while a `%` remains, up to [`PASSES`] passes. A malformed escape is
/// kept as it is. A name with no `%` is used as it is: `+` and space
/// normalize alike.
fn percent_decoded(name: &[u8]) -> Cow<'_, [u8]> {
    let mut decoded = Cow::Borrowed(name);
    for _ in 0..PASSES {
        if !decoded.contains(&b'%') {
            break;
        }
        decoded = Cow::Owned(decoded_once(&decoded));
    }
    decoded
}

/// `bytes` with one pass of escapes decoded.
fn decoded_once(bytes: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let rest = bytes.get(index + 1..).unwrap_or_default();
            if let Some(c) = wide(rest) {
                let mut utf8 = [0; 4];
                decoded.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
                index += 6;
                continue;
            }
            if let Some(value) = hex(rest.get(..2)).and_then(|value| u8::try_from(value).ok()) {
                decoded.push(value);
                index += 3;
                continue;
            }
        }
        decoded.push(if byte == b'+' { b' ' } else { byte });
        index += 1;
    }
    decoded
}

/// The character a `%uXXXX` escape names, from the bytes after its `%`.
fn wide(rest: &[u8]) -> Option<char> {
    let (&u, digits) = rest.split_first()?;
    if !u.eq_ignore_ascii_case(&b'u') {
        return None;
    }
    char::from_u32(hex(digits.get(..4))?)
}

/// The value of `digits`, when there are some and all are hex digits.
fn hex(digits: Option<&[u8]>) -> Option<u32> {
    digits?.iter().try_fold(0, |value: u32, &digit| {
        Some(value * 16 + char::from(digit).to_digit(16)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_read_as_access_token_are_found() {
        for query in [
            "access_token=x",
            "a=1&ACCESS_TOKEN",
            "a=1;access.token=x",
            "+access-token=x",
            "%20access__token=x",
            "access_token%00x=1",
            "access_token[]=x",
            "access%5Btoken=x",
            "acce%C5%BF%C5%BF_to%E2%84%AAen=x",
            "access%255Ftoken=x",
            "access%25255Ftoken=x",
            "access%u005Ftoken=x",
            "%U0061ccess_token=x",
            "access%FFtoken%FF=x",
        ] {
            assert!(has_access_token(Some(query)), "{query}");
        }
    }

    #[test]
    fn other_names_are_not() {
        for query in [
            "",
            "access",
            "x=access_token",
            "access_tokens=x",
            "my_access_token=x",
            "xaccess_token=x",
            "access_token_x=1",
            "access%5token=x",
            "access%u5Ftoken=x",
            "access%2525255Ftoken=x",
        ] {
            assert!(!has_access_token(Some(query)), "{query}");
        }
        assert!(!has_access_token(None));
    }
}
