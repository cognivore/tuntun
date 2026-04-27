//! Cookie codec: encode `Set-Cookie` header values, parse inbound `Cookie:`
//! headers.
//!
//! This is intentionally a thin, allocation-light implementation. We only
//! handle the subset of [RFC 6265] that tuntun emits and accepts.
//!
//! Quoting and unquoting follow RFC 6265 §5.2: a cookie value may be wrapped
//! in matched DQUOTE characters; we strip them on parse and never emit them on
//! encode (we restrict the output to a sane RFC 6265 cookie-octet alphabet
//! instead).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `SameSite` directive for the cookie. See RFC 6265bis §5.4.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SameSitePolicy {
    Strict,
    Lax,
    None,
}

impl SameSitePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            SameSitePolicy::Strict => "Strict",
            SameSitePolicy::Lax => "Lax",
            SameSitePolicy::None => "None",
        }
    }
}

/// Cookie attribute set used to render `Set-Cookie` header values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieAttrs {
    pub domain: String,
    pub path: String,
    pub max_age_seconds: i64,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSitePolicy,
}

/// Workspace-default attributes per CLAUDE.md rule 5: `HttpOnly`, `Secure`,
/// `SameSite=Lax`, `Path=/`, `Max-Age=3600`. Caller picks the domain.
impl CookieAttrs {
    pub fn defaults_for_domain(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            path: "/".to_string(),
            max_age_seconds: 3_600,
            secure: true,
            http_only: true,
            same_site: SameSitePolicy::Lax,
        }
    }
}

/// Render a `Set-Cookie` header value. The returned string does NOT include
/// the leading `Set-Cookie:` token — only the value.
///
/// `name` and `value` are written as-is. We do not percent-encode them, but we
/// will not emit a malformed header: any byte forbidden by RFC 6265 §4.1.1 is
/// replaced with an underscore. The same goes for the `domain`/`path`
/// attributes.
pub fn encode_cookie(name: &str, value: &str, attrs: &CookieAttrs) -> String {
    let mut out = String::new();
    out.push_str(&sanitize_token(name));
    out.push('=');
    out.push_str(&sanitize_value(value));
    if !attrs.domain.is_empty() {
        out.push_str("; Domain=");
        out.push_str(&sanitize_attr(&attrs.domain));
    }
    if !attrs.path.is_empty() {
        out.push_str("; Path=");
        out.push_str(&sanitize_attr(&attrs.path));
    }
    out.push_str("; Max-Age=");
    out.push_str(&attrs.max_age_seconds.to_string());
    if attrs.secure {
        out.push_str("; Secure");
    }
    if attrs.http_only {
        out.push_str("; HttpOnly");
    }
    out.push_str("; SameSite=");
    out.push_str(attrs.same_site.as_str());
    out
}

/// Parse an inbound `Cookie:` request header value into a `name -> value` map.
///
/// Cookies are split on `;`, then each pair is split on the first `=`. Keys
/// and values are trimmed; surrounding double-quotes around the value are
/// stripped (RFC 6265 §5.2). Pairs without an `=` and pairs with empty names
/// are silently skipped.
pub fn parse_cookie_header(header: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in header.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((k, v)) = raw.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if k.is_empty() {
            continue;
        }
        let v = unquote(v.trim());
        out.insert(k.to_string(), v);
    }
    out
}

fn unquote(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Cookie name (token, RFC 6265 §4.1.1): no separators, no CTLs, no whitespace.
fn sanitize_token(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Cookie-value (RFC 6265 §4.1.1): printable US-ASCII, no `"`, `,`, `;`, `\`,
/// no whitespace.
fn sanitize_value(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c as u32) >= 0x21
                && (c as u32) <= 0x7E
                && !matches!(c, '"' | ',' | ';' | '\\' | ' ')
            {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Attribute value (Domain, Path): printable, no `;` (which would terminate
/// the attribute), no CTLs.
fn sanitize_attr(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c as u32) >= 0x20 && (c as u32) <= 0x7E && !matches!(c, ';') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs() -> CookieAttrs {
        CookieAttrs {
            domain: ".memorici.de".to_string(),
            path: "/".to_string(),
            max_age_seconds: 3_600,
            secure: true,
            http_only: true,
            same_site: SameSitePolicy::Lax,
        }
    }

    #[test]
    fn encode_emits_all_attributes() {
        let s = encode_cookie("session", "abc123", &attrs());
        assert!(s.starts_with("session=abc123"));
        assert!(s.contains("Domain=.memorici.de"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("Max-Age=3600"));
        assert!(s.contains("Secure"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("SameSite=Lax"));
    }

    #[test]
    fn encode_omits_secure_and_http_only_when_disabled() {
        let mut a = attrs();
        a.secure = false;
        a.http_only = false;
        let s = encode_cookie("k", "v", &a);
        assert!(!s.contains("Secure"));
        assert!(!s.contains("HttpOnly"));
    }

    #[test]
    fn encode_emits_same_site_strict_and_none() {
        let mut a = attrs();
        a.same_site = SameSitePolicy::Strict;
        assert!(encode_cookie("k", "v", &a).contains("SameSite=Strict"));
        a.same_site = SameSitePolicy::None;
        assert!(encode_cookie("k", "v", &a).contains("SameSite=None"));
    }

    #[test]
    fn encode_sanitizes_dangerous_characters() {
        // A semicolon in the value would terminate the cookie pair.
        let s = encode_cookie("a;b", "x;y", &attrs());
        assert!(!s.starts_with("a;b=x;y"));
        // We map disallowed chars to underscores.
        assert!(s.starts_with("a_b=x_y"));
    }

    #[test]
    fn encode_sanitizes_attribute_semicolon_and_ctl() {
        let mut a = attrs();
        a.domain = "evil;Path=/admin".to_string();
        a.path = "/foo\x07bar".to_string();
        let s = encode_cookie("k", "v", &a);
        assert!(!s.contains("evil;Path=/admin"));
        assert!(!s.contains('\x07'));
    }

    #[test]
    fn parse_extracts_pairs() {
        let m = parse_cookie_header("session=abc; csrf=def");
        assert_eq!(m.get("session").map(String::as_str), Some("abc"));
        assert_eq!(m.get("csrf").map(String::as_str), Some("def"));
    }

    #[test]
    fn parse_handles_extra_whitespace_and_empty_segments() {
        let m = parse_cookie_header("  ; a=1 ;   b = 2 ;;");
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn parse_strips_surrounding_quotes() {
        let m = parse_cookie_header("session=\"value with spaces\"");
        assert_eq!(
            m.get("session").map(String::as_str),
            Some("value with spaces")
        );
    }

    #[test]
    fn parse_skips_pairs_without_equals() {
        let m = parse_cookie_header("nope; ok=1");
        assert!(!m.contains_key("nope"));
        assert_eq!(m.get("ok").map(String::as_str), Some("1"));
    }

    #[test]
    fn parse_ignores_empty_keys() {
        let m = parse_cookie_header("=value; real=1");
        assert!(!m.contains_key(""));
        assert_eq!(m.get("real").map(String::as_str), Some("1"));
    }

    #[test]
    fn parse_keeps_value_with_internal_equals() {
        let m = parse_cookie_header("token=a=b=c");
        assert_eq!(m.get("token").map(String::as_str), Some("a=b=c"));
    }

    #[test]
    fn parse_empty_header_yields_empty_map() {
        let m = parse_cookie_header("");
        assert!(m.is_empty());
    }

    #[test]
    fn round_trip_simple() {
        let s = encode_cookie("session", "abc123", &attrs());
        // The Set-Cookie line is split into name=value (first segment) — that
        // is what a browser would echo back in `Cookie:`.
        let first_pair = s.split(';').next().expect("first segment");
        let m = parse_cookie_header(first_pair);
        assert_eq!(m.get("session").map(String::as_str), Some("abc123"));
    }

    #[test]
    fn defaults_for_domain_uses_workspace_policy() {
        let a = CookieAttrs::defaults_for_domain(".memorici.de");
        assert!(a.secure);
        assert!(a.http_only);
        assert_eq!(a.same_site, SameSitePolicy::Lax);
        assert_eq!(a.path, "/");
        assert_eq!(a.max_age_seconds, 3_600);
    }

    #[test]
    fn negative_max_age_is_emitted_verbatim() {
        // Max-Age=0 (or negative) is a valid way to delete a cookie.
        let mut a = attrs();
        a.max_age_seconds = -1;
        let s = encode_cookie("k", "v", &a);
        assert!(s.contains("Max-Age=-1"));
    }
}
