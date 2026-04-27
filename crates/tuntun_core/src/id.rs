//! Validated newtype identifier macros.
//!
//! Use [`define_id!`] for string-backed ids (with optional custom validator)
//! and [`define_numeric_id!`] for integer-backed ids with a range constraint.
//!
//! Every generated id type provides:
//!
//! - A fallible constructor `new(value)` that rejects invalid input
//! - An `as_str()` (or `value()`) accessor
//! - `Display`, `Debug`, `FromStr`, `Eq`, `Ord`, `Hash`
//! - Transparent `serde::Serialize` / `Deserialize`

use std::fmt;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    #[error("{0} must not be empty")]
    Empty(&'static str),

    #[error("{kind}: {reason} (value={value:?})")]
    Invalid {
        kind: &'static str,
        value: String,
        reason: &'static str,
    },

    #[error("{kind}: numeric value {value} out of range {min}..={max}")]
    OutOfRange {
        kind: &'static str,
        value: i128,
        min: i128,
        max: i128,
    },
}

/// Define a string-backed validated newtype identifier.
///
/// ```ignore
/// define_id!(pub TenantId);
/// define_id!(pub Subdomain, validate = validate_dns_label);
/// ```
#[macro_export]
macro_rules! define_id {
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident
        $(, validate = $validate:expr )?
        $(,)?
    ) => {
        $(#[$meta])*
        #[derive(
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            ::serde::Serialize,
        )]
        #[serde(transparent)]
        $vis struct $name(::std::string::String);

        impl $name {
            #[allow(dead_code)]
            pub fn new<S: ::core::convert::Into<::std::string::String>>(
                value: S,
            ) -> ::core::result::Result<Self, $crate::id::IdError> {
                let value: ::std::string::String = value.into();
                if value.is_empty() {
                    return ::core::result::Result::Err(
                        $crate::id::IdError::Empty(::core::stringify!($name)),
                    );
                }
                $(
                    let validator: fn(&str)
                        -> ::core::result::Result<(), &'static str> = $validate;
                    if let ::core::result::Result::Err(reason) = validator(&value) {
                        return ::core::result::Result::Err(
                            $crate::id::IdError::Invalid {
                                kind: ::core::stringify!($name),
                                value,
                                reason,
                            },
                        );
                    }
                )?
                ::core::result::Result::Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_inner(self) -> ::std::string::String {
                self.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}({:?})", ::core::stringify!($name), self.0)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::id::IdError;
            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let s = ::std::string::String::deserialize(d)?;
                Self::new(s).map_err(::serde::de::Error::custom)
            }
        }

        impl ::core::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

/// Define a numeric (integer-backed) validated newtype with a range constraint.
///
/// ```ignore
/// define_numeric_id!(pub ServicePort, u16, min = 1, max = u16::MAX);
/// ```
#[macro_export]
macro_rules! define_numeric_id {
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident, $repr:ty
        $(, min = $min:expr )?
        $(, max = $max:expr )?
        $(,)?
    ) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        #[serde(transparent)]
        $vis struct $name($repr);

        impl $name {
            #[allow(dead_code)]
            pub fn new(value: $repr) -> ::core::result::Result<Self, $crate::id::IdError> {
                let v_i128: i128 = ::core::convert::From::from(value);
                $(
                    let min_i128: i128 = ::core::convert::From::from($min as $repr);
                    if v_i128 < min_i128 {
                        return ::core::result::Result::Err(
                            $crate::id::IdError::OutOfRange {
                                kind: ::core::stringify!($name),
                                value: v_i128,
                                min: min_i128,
                                max: i128::MAX,
                            },
                        );
                    }
                )?
                $(
                    let max_i128: i128 = ::core::convert::From::from($max as $repr);
                    if v_i128 > max_i128 {
                        return ::core::result::Result::Err(
                            $crate::id::IdError::OutOfRange {
                                kind: ::core::stringify!($name),
                                value: v_i128,
                                min: i128::MIN,
                                max: max_i128,
                            },
                        );
                    }
                )?
                ::core::result::Result::Ok(Self(value))
            }

            #[must_use]
            pub fn value(self) -> $repr {
                self.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}({})", ::core::stringify!($name), self.0)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

#[allow(unused_imports)]
pub use define_id;
#[allow(unused_imports)]
pub use define_numeric_id;

// Validators used by ids.rs.

/// DNS label per RFC 1035: 1..=63 chars, lowercase alnum + hyphen, no leading
/// or trailing hyphen. Underscore is rejected (we do not target hosts named
/// like SRV records).
pub fn validate_dns_label(s: &str) -> Result<(), &'static str> {
    if s.len() > 63 {
        return Err("DNS label exceeds 63 characters");
    }
    let bytes = s.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return Err("DNS label must not start or end with hyphen");
    }
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if !ok {
            return Err("DNS label must be lowercase alnum or hyphen");
        }
    }
    Ok(())
}

/// Validate a fully-qualified domain: dot-separated DNS labels.
pub fn validate_domain(s: &str) -> Result<(), &'static str> {
    if s.len() > 253 {
        return Err("domain exceeds 253 characters");
    }
    if s.contains("..") {
        return Err("domain has empty label");
    }
    for label in s.split('.') {
        if label.is_empty() {
            return Err("domain has empty label");
        }
        validate_dns_label(label)?;
    }
    Ok(())
}

/// Tenant ids, project ids, service names: lowercase alnum + hyphen, 1..=64.
pub fn validate_slug(s: &str) -> Result<(), &'static str> {
    if s.len() > 64 {
        return Err("slug exceeds 64 characters");
    }
    let bytes = s.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return Err("slug must not start or end with hyphen");
    }
    for &b in bytes {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if !ok {
            return Err("slug must be lowercase alnum or hyphen");
        }
    }
    Ok(())
}

/// Secret-key namespaces: alnum + hyphen + slash + underscore + period.
pub fn validate_secret_key(s: &str) -> Result<(), &'static str> {
    if s.len() > 256 {
        return Err("secret key exceeds 256 characters");
    }
    for &b in s.as_bytes() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'/' | b'.');
        if !ok {
            return Err("secret key has invalid character");
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct DisplayValidator(pub fn(&str) -> Result<(), &'static str>);

impl fmt::Display for DisplayValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<validator>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_label_ok() {
        assert!(validate_dns_label("blog").is_ok());
        assert!(validate_dns_label("blog-prod").is_ok());
        assert!(validate_dns_label("blog123").is_ok());
    }

    #[test]
    fn dns_label_rejects_bad() {
        assert!(validate_dns_label("Blog").is_err());
        assert!(validate_dns_label("blog_prod").is_err());
        assert!(validate_dns_label("-blog").is_err());
        assert!(validate_dns_label("blog-").is_err());
        assert!(validate_dns_label(&"a".repeat(64)).is_err());
    }

    #[test]
    fn domain_ok() {
        assert!(validate_domain("memorici.de").is_ok());
        assert!(validate_domain("foo.bar.example.com").is_ok());
    }

    #[test]
    fn domain_rejects_bad() {
        assert!(validate_domain("foo..bar").is_err());
        assert!(validate_domain("FOO.com").is_err());
    }
}
