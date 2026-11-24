//! Finding a refused parameter, such as `access_token` (RFC 6750 section
//! 2.3), in a request's query, as some downstream framework could read
//! it. The normalization is described in docs/notes/gateway-plan.md.

use std::borrow::Cow;

use tsong_config::fold_name_char;

/// The most decoding passes a name gets, so `%255F` decodes too.
const PASSES: usize = 3;

/// Whether `query` has a parameter named one of `refused`, each already
/// normalized: pairs split on `&` or `;`, each name percent-decoded and
/// normalized. Values aren't read, so a refused name inside another
/// parameter's encoded value isn't found.
pub(crate) fn has_refused_param(query: Option<&str>, refused: &[String]) -> bool {
    query.is_some_and(|query| {
        query.split(['&', ';']).any(|pair| {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            let name = percent_decoded(name.as_bytes());
            refused
                .iter()
                .any(|target| reads_as(&name, target.as_bytes()))
        })
    })
}

/// Whether the decoded name `name` normalizes to `target`, whole or cut
/// at its first NUL or `[`: case-folded and stripped of everything but
/// ASCII letters and digits. Both forms are read in one pass.
fn reads_as(name: &[u8], target: &[u8]) -> bool {
    // Each byte yields at most one ASCII letter or digit.
    if name.len() < target.len() {
        return false;
    }
    let cut = name.iter().position(|&byte| byte == 0 || byte == b'[');
    let mut matched = 0;
    let mut cut_matches = None;
    let mut offset = 0;
    for chunk in name.utf8_chunks() {
        for (at, c) in chunk.valid().char_indices() {
            if cut == Some(offset + at) {
                cut_matches = Some(matched == target.len());
            }
            for folded in fold_name_char(c) {
                let expected = target.get(matched).copied().map(char::from);
                if expected != Some(folded) {
                    // The cut form ended before this, or shares the miss.
                    return cut_matches.unwrap_or(false);
                }
                matched += 1;
            }
        }
        offset += chunk.valid().len() + chunk.invalid().len();
    }
    matched == target.len() || cut_matches.unwrap_or(false)
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
    use tsong_config::{ACCESS_TOKEN, default_refused_query_params, normalize_name};

    fn refused(query: &str) -> bool {
        let defaults: Vec<String> = std::iter::once(ACCESS_TOKEN.to_owned())
            .chain(default_refused_query_params())
            .map(|name| normalize_name(&name))
            .collect();
        has_refused_param(Some(query), &defaults)
    }

    #[test]
    fn names_that_read_as_a_refused_name_are_found() {
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
            "%uFF41ccess_token=x",
            "%EF%BC%A1ccess_token=x",
            "%EF%BC%A1CCESS%EF%BC%BFTOKEN=x",
            "private_token=x",
            "PRIVATE-TOKEN=x",
            "job_token=x",
            "Job.Token=x",
            "api_key=x",
            "API-KEY=x",
        ] {
            assert!(refused(query), "{query}");
        }
    }

    #[test]
    fn other_names_are_not() {
        for query in [
            "",
            "access",
            "x=access_token",
            "x=a%26access_token%3Dy",
            "access_tokens=x",
            "my_access_token=x",
            "xaccess_token=x",
            "access_token_x=1",
            "access%5token=x",
            "access%u5Ftoken=x",
            "access%2525255Ftoken=x",
            "token=x",
            "api=x",
        ] {
            assert!(!refused(query), "{query}");
        }
        assert!(!has_refused_param(None, &[normalize_name("access_token")]));
    }

    #[test]
    fn a_configured_name_is_found_as_the_defaults_are() {
        let refused = [normalize_name("X-Sig")];
        assert!(has_refused_param(Some("a=1&x_sig=2"), &refused));
        assert!(has_refused_param(Some("X%2ESIG=2"), &refused));
        assert!(!has_refused_param(Some("access_token=2"), &refused));
    }
}
