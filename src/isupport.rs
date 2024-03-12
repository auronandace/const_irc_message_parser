//! Methods for parsing and extracting information from an [`ISupportToken`].
//!
//! ## Purpose
//!
//! An IRC server advertises the features it supports in the `RPL_ISUPPORT` (`005`) numeric [`IrcMsg`](crate::IrcMsg).
//! Each [`ISupportToken`] represents the setting or unsetting of the specified feature.
//! If an IRC client or bot supports that feature they can use the [`ISupportToken`] to enable it.
//! If an IRC server unsets a feature the client must no loger use it until it is set again.
//! These [`ISupportToken`]s can be used for keeping track of appliction state for the advertised features.
//! The first and trailing parameter in the `RPL_ISUPPORT` (`005`) numeric [`IrcMsg`](crate::IrcMsg) are not
//! [`ISupportToken`]s. All the [`Parameters`](crate::Parameters) inbetween them are.

use crate::ContentType;

/// A single ISUPPORT token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ISupportToken<'msg> {
    parameter: ContentType<'msg>,
    value: Option<ContentType<'msg>>,
    set: bool,
}

impl<'msg> ISupportToken<'msg> {
    /// Generates an [`ISupportToken`] from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is empty, the parameter or value contains an invalid byte as per the
    /// [specification], the lack of a parameter before the `=` or the presence of an `=` if the token starts with `-`.
    ///
    /// [specification]: <https://modern.ircdocs.horse/#rplisupport-005>
    pub const fn parse(input: &'msg[u8]) -> Result<Self, ISupportTokenError> {
        if input.is_empty() {return Err(ISupportTokenError::EmptyInput);}
        let mut copy = input;
        let mut set = true;
        if input[0] == b'-' {
            set = false;
            (_, copy) = input.split_at(1);
        }
        let mut index = 0;
        let mut equals_present = false;
        let mut equals_index = 0;
        while index < copy.len() {
            if !equals_present && copy[index] == b'=' {
                if !set {return Err(ISupportTokenError::ValueNotPermittedOnNegatedToken);}
                equals_present = true; equals_index = index;
            } else if !equals_present && is_invalid_parameter_byte(copy[index]) {
                return Err(ISupportTokenError::InvalidParameterByte(copy[index]));
            } else if equals_present && is_invalid_value_byte(copy[index]) {
                return Err(ISupportTokenError::InvalidValueByte(copy[index]));
            }
            index += 1;
        }
        let (parameter, value) = if equals_present {
            if equals_index == 0 {return Err(ISupportTokenError::NoParameterBeforeEquals);}
            let (first, second) = copy.split_at(equals_index);
            let (_, after) = second.split_at(1);
            (ContentType::new(first), if after.is_empty() {None} else {Some(ContentType::new(after))})
        } else {
            (ContentType::new(copy), None)
        };
        Ok(ISupportToken{parameter, value, set})
    }
    /// Returns the parameter of the [`ISupportToken`] as a [`ContentType`].
    #[must_use]
    pub const fn parameter(&self) -> ContentType {
        self.parameter
    }
    /// Returns the value of the [`ISupportToken`] as a [`ContentType`] if it exists.
    #[must_use]
    pub const fn value(&self) -> Option<ContentType> {
        self.value
    }
    /// Check whether the [`ISupportToken`] is set.
    #[must_use]
    pub const fn is_set(&self) -> bool {
        self.set
    }
}

impl<'msg> core::fmt::Display for ISupportToken<'msg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.is_set() {write!(f, "-")?;}
        if let Some(value) = self.value() {write!(f, "{}={}", self.parameter, value)}
        else {write!(f, "{}", self.parameter())}
    }
}

const fn is_invalid_parameter_byte(input: u8) -> bool {
    !input.is_ascii_uppercase() && !input.is_ascii_digit()
}

const fn is_invalid_value_byte(input: u8) -> bool {
    !input.is_ascii_alphanumeric() && !matches!(input, b'!'..=b'/' | b'\x20' | b'\x5c' | b'\x3d' | b':'..=b'<' |
        b'>'..=b'@' | b'[' | b']'..=b'`' | b'{'..=b'~')
}

/// The possible types of errors when parsing a single [`ISupportToken`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ISupportTokenError {
    /// The input is empty.
    EmptyInput,
    /// Lack of a parameter before specifying a value.
    NoParameterBeforeEquals,
    /// A token starting with `-` should never have a value.
    ValueNotPermittedOnNegatedToken,
    /// Use of an invalid byte when parsing the parameter.
    InvalidParameterByte(u8),
    /// Use of an invalid byte when parsing the value.
    InvalidValueByte(u8),
}

#[cfg(test)]
mod const_tests {
    use crate::const_tests::is_identical;
    use super::ISupportToken;
    #[test]
    const fn parse_token() {
        assert!(ISupportToken::parse(b"-FNC").is_ok());
        assert!(ISupportToken::parse(b"-FNC=").is_err());
        assert!(ISupportToken::parse(b"-fnc").is_err());
        assert!(ISupportToken::parse(b"ACCOUNTEXTBAN=a").is_ok());
        assert!(ISupportToken::parse(b"ACCOUNTEXTBAN=\0a").is_err());
        assert!(ISupportToken::parse(b"PREFIX=(ov)@+").is_ok());
    }
    #[test]
    const fn get_parameter() {
        let token = ISupportToken::parse(b"PREFIX=(ov)@+");
        assert!(token.is_ok());
        if let Ok(token) = token {assert!(is_identical(token.parameter().as_bytes(), b"PREFIX"));}
    }
    #[test]
    const fn get_value() {
        let token = ISupportToken::parse(b"PREFIX=(ov)@+");
        assert!(token.is_ok());
        if let Ok(token) = token {
            let value = token.value();
            assert!(value.is_some());
            if let Some(value) = value {assert!(is_identical(value.as_bytes(), b"(ov)@+"));}
        }
    }
    #[test]
    const fn check_set() {
        let token = ISupportToken::parse(b"PREFIX=(ov)@+");
        assert!(token.is_ok());
        if let Ok(token) = token {assert!(token.is_set());}
    }
}
