//! Methods for parsing and extracting information from an [`ISupportToken`] or creating one.
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

use crate::{ContentType, is_identical};

/// A single ISUPPORT token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ISupportToken<'msg> {
    set: bool,
    parameter: ContentType<'msg>,
    equals_present: bool,
    value: Option<ContentType<'msg>>,
}

impl<'msg> ISupportToken<'msg> {
    /// Creates an [`ISupportToken`].
    ///
    /// Intended to be used by servers.
    /// 
    /// Not currently validated against known tokens so it is possible to create invalid but correctly formed tokens.
    /// 
    /// To create a token with an equals but no value you need to pass in `Some("")` for `value`.
    /// 
    /// # Errors
    ///
    /// Will return `Err` if the parameter is empty, set is `false` but value is not `None`, the parameter
    /// or the value contains an invalid byte as per the [specification].
    /// 
    /// [specification]: <https://modern.ircdocs.horse/#rplisupport-005>
    pub const fn new(set: bool, parameter: &'msg str, value: Option<&'msg str>) -> Result<Self, ISupportTokenError> {
        if parameter.is_empty() {return Err(ISupportTokenError::EmptyParameter);}
        let (parameter, value, equals_present) = {
            let param_bytes = parameter.as_bytes();
            if let Some(byte) = invalid_parameter_byte(param_bytes) {
                return Err(ISupportTokenError::InvalidParameterByte(byte));
            }
            if let Some(value) = value {
                if !set {return Err(ISupportTokenError::ValueNotPermittedOnNegatedToken);}
                if value.is_empty() {
                    (ContentType::new(param_bytes), None, true)
                } else {
                    let val_bytes = value.as_bytes();
                    if let Some(byte) = invalid_value_byte(val_bytes) {
                        return Err(ISupportTokenError::InvalidValueByte(byte));
                    }
                    (ContentType::new(param_bytes), Some(ContentType::new(val_bytes)), true)
                }
            } else {(ContentType::new(param_bytes), None, false)}
        };
        Ok(ISupportToken {set, parameter, equals_present, value})
    }
    /// Generates an [`ISupportToken`] from a slice of bytes.
    ///
    /// Intended to be used by clients or bots.
    /// 
    /// Not currently validated against known tokens so it is possible to create invalid but correctly formed tokens.
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
        Ok(ISupportToken{set, parameter, equals_present, value})
    }
    /// Generates an [`ISupportToken`] from a [`ContentType`].
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is empty, the parameter or value contains an invalid byte as per the
    /// [specification], the lack of a parameter before the `=` or the presence of an `=` if the token starts with `-`.
    ///
    /// [specification]: <https://modern.ircdocs.horse/#rplisupport-005>
    pub const fn from_contenttype(input: ContentType<'msg>) -> Result<Self, ISupportTokenError> {
        match input {
            ContentType::StringSlice(str) => Self::parse(str.as_bytes()),
            ContentType::NonUtf8ByteSlice(bytes) => Self::parse(bytes),
        }
    }
    /// Checks a slice of [`ISupportToken`]s for duplicate parameters.
    ///
    /// An IRC server should not send the same [`ISupportToken`] in a single `RPL_ISUPPORT` (`005`)
    /// numeric [`IrcMsg`](crate::IrcMsg).
    #[must_use]
    pub const fn contains_duplicate_parameters(tokens: &[Self]) -> bool {
        let mut index = 0;
        while index < tokens.len() {
            let mut inner_index = 0;
            while inner_index < tokens.len() {
                if index != inner_index {
                    let outer = tokens[index].parameter;
                    let inner = tokens[inner_index].parameter;
                    if is_identical(outer.as_bytes(), inner.as_bytes()) {return true;}
                }
                inner_index += 1;
            }
            index += 1;
        }
        false
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

impl core::fmt::Display for ISupportToken<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.is_set() {write!(f, "-")?;}
        if let Some(value) = self.value() {write!(f, "{}={}", self.parameter, value)}
        else if self.equals_present {write!(f, "{}=", self.parameter)}
        else {write!(f, "{}", self.parameter())}
    }
}

const fn is_invalid_parameter_byte(input: u8) -> bool {
    !input.is_ascii_uppercase() && !input.is_ascii_digit()
}

const fn invalid_parameter_byte(input: &[u8]) -> Option<u8> {
    let mut index = 0;
    while index < input.len() {
        if is_invalid_parameter_byte(input[index]) {return Some(input[index]);}
        index += 1;
    }
    None
}

const fn is_invalid_value_byte(input: u8) -> bool {
    !input.is_ascii_alphanumeric() && !matches!(input, b'!'..=b'/' | b'\x20' | b'\x5c' | b'\x3d' | b':'..=b'<' |
        b'>'..=b'@' | b'[' | b']'..=b'`' | b'{'..=b'~')
}

const fn invalid_value_byte(input: &[u8]) -> Option<u8> {
    let mut index = 0;
    while index < input.len() {
        if is_invalid_value_byte(input[index]) {return Some(input[index]);}
        index += 1;
    }
    None
}

/// The possible types of errors when parsing or creating a single [`ISupportToken`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ISupportTokenError {
    /// The input is empty.
    EmptyInput,
    /// The parameter is empty.
    EmptyParameter,
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
    use crate::{ContentType, is_identical};
    use super::ISupportToken;
    #[test]
    const fn create_token() {
        assert!(ISupportToken::new(true, "ACCOUNTEXTBAN", Some("a")).is_ok());   // set with value
        assert!(ISupportToken::new(true, "ACCOUNTEXTBAN", Some("")).is_ok());    // set and value is empty
        assert!(ISupportToken::new(true, "ACCOUNTEXTBAN", None).is_ok());        // value is none
        assert!(ISupportToken::new(true, "ACCOUNTEXtBAN", Some("a")).is_err());  // lowercase in parameter
        assert!(ISupportToken::new(true, "ACCOUNTEXTBAN", Some("\0")).is_err()); // invalid value byte
        assert!(ISupportToken::new(false, "ACCOUNTEXTBAN", Some("a")).is_err()); // unset with value
        assert!(ISupportToken::new(false, "ACCOUNTEXTBAN", Some("")).is_err());  // unset and value is empty
    }
    #[test]
    const fn parse_token() {
        assert!(ISupportToken::parse(b"-FNC").is_ok());               // unset
        assert!(ISupportToken::parse(b"PREFIX=(ov)@+").is_ok());      // set with value
        assert!(ISupportToken::parse(b"-FNC=").is_err());             // unset with equals
        assert!(ISupportToken::parse(b"-fnc").is_err());              // invalid parameter byte (lowercase)
        assert!(ISupportToken::parse(b"ACCOUNTEXTBAN=\0a").is_err()); // invalid value byte (null)
    }
    #[test]
    const fn parse_token_from_contenttype() {
        assert!(ISupportToken::from_contenttype(ContentType::new(b"ACCOUNTEXTBAN=a")).is_ok());
        assert!(ISupportToken::from_contenttype(ContentType::new(&[0, 159, 146, 150])).is_err());
    }
    #[test]
    const fn duplicate_parameter_check() {
        let token1 = ISupportToken {set: true, parameter: ContentType::new(b"ABC"), equals_present: false, value: None};
        let token2 = ISupportToken {set: true, parameter: ContentType::new(b"FNC"), equals_present: false, value: None};
        let token3 = ISupportToken {set: true, parameter: ContentType::new(b"FNC"), equals_present: false, value: None};
        assert!(ISupportToken::contains_duplicate_parameters(&[token1, token2, token3]));
        assert!(!ISupportToken::contains_duplicate_parameters(&[token1, token2]));
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
