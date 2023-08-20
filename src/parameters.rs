//! Methods for parsing and extracting information from [`Parameters`].

use crate::ContentType;

/// All the parameters of an [`IrcMsg`](crate::IrcMsg).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters<'msg> {
    amount: usize,
    content: ContentType<'msg>,
}

impl<'msg> Parameters<'msg> {
    /// Generates [`Parameters`] from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input contains an invalid character as per the [IRC Client Protocol Specification].
    ///
    /// [IRC Client Protocol Specification]: <https://modern.ircdocs.horse/#parameters>
    pub const fn parse(input: &'msg [u8]) -> Result<Option<Self>, ParametersError> {
        if input.is_empty() {return Ok(None);}
        let mut amount = 1;
        let mut previous_char = b'\0';
        let mut trailing_parameter = false;
        let mut index = 0;
        while index < input.len() {
            if input[index] == b'\0' || input[index] == b'\r' || input[index] == b'\n' {
                return Err(ParametersError::InvalidByte(input[index]));
            } else if (previous_char == b' ' || index == 0) && input[index] == b':' {
                trailing_parameter = true;
            } else if !trailing_parameter && input[index] == b' ' {
                amount += 1;
            }
            previous_char = input[index];
            index += 1;
        }
        Ok(Some(Parameters{amount, content: ContentType::new(input)}))
    }
    /// Returns the amount of parameters in [`Parameters`].
    #[must_use]
    pub const fn count(&self) -> usize {
        self.amount
    }
    /// Returns all the parameters as a [`ContentType`](crate::ContentType).
    ///
    /// This includes the `:` before the last parameter if present.
    #[must_use]
    pub const fn content(&self) -> ContentType {
        self.content
    }
    /// Returns the first parameter as a [`ContentType`](crate::ContentType).
    ///
    /// Does not include `:` for the trailing parameter.
    #[must_use]
    pub const fn extract_first(&self) -> ContentType {
        match self.extract_specific(0) {
            Some(output) => output,
            None => unreachable!(),
        }
    }
    /// Returns the last parameter as a [`ContentType`](crate::ContentType).
    ///
    /// Does not include `:` for the trailing parameter.
    #[must_use]
    pub const fn extract_last(&self) -> ContentType {
        match self.extract_specific(self.amount-1) {
            Some(output) => output,
            None => unreachable!(),
        }
    }
    /// Returns the requested parameter as a [`ContentType`](crate::ContentType) at the specified index.
    ///
    /// Index starts at 0. If out of bounds it returns `None`. Does not include `:` for the trailing parameter.
    #[must_use]
    pub const fn extract_specific(&self, target_index: usize) -> Option<ContentType> {
        if target_index > self.amount {return None;}
        let bytes = self.content.as_bytes();
        let mut current_param = 1;
        let mut param_started = false;
        let mut param_start = 0;
        let mut param_end = 0;
        let mut last_param = false;
        let mut previous_byte = b'\0';
        let mut index = 0;
        while index < bytes.len() {
            if target_index == current_param - 1 && !param_started {
                param_started = true;
                param_start = index;
            }
            if bytes[index] == b' ' && !last_param {
                current_param += 1;
            } else if bytes[index] == b':' && (previous_byte == b' ' || index == 0) {
                last_param = true;
            }
            if param_started && current_param == target_index + 2 {param_end = index; break;}
            previous_byte = bytes[index];
            param_end = index;
            index += 1;
        }
        let (_, rest) = bytes.split_at(param_start);
        param_end -= param_start;
        let param = if last_param {
            rest
        } else {
            let (p, _) = rest.split_at(param_end);
            p
        };
        if param[0] == b':' {
            match param.split_first() {
                Some((_, output)) => Some(ContentType::new(output)),
                None => unreachable!(),
            }
        } else {
            Some(ContentType::new(param))
        }
    }
    /// Checks whether the [`Parameters`] contains non-utf8 bytes.
    #[must_use]
    pub const fn is_valid_uft8(&self) -> bool {
        match self.content {
            ContentType::StringSlice(_) => true,
            ContentType::NonUtf8ByteSlice(_) => false,
        }
    }
}

impl<'msg> core::fmt::Display for Parameters<'msg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.content)
    }
}

/// The possible types of errors when parsing [`Parameters`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParametersError {
    /// Use of an invalid byte when parsing [`Parameters`].
    InvalidByte(u8),
}

#[cfg(test)]
mod const_tests {
    use crate::{ContentType, const_tests::is_identical};
    use super::Parameters;
    #[test]
    const fn get_first() {
        let params = Parameters{amount: 3, content: ContentType::new(b"* LS :multi-prefix sasl")};
        let first_param = params.extract_first();
        let first = first_param.as_bytes();
        assert!(first[0] == b'*');
        assert!(first.len() == 1);
        let params = Parameters{amount: 1, content: ContentType::new(b":")};
        let first_param = params.extract_first();
        let first = first_param.as_bytes();
        assert!(first.is_empty());
        assert!(first.len() == 0);
    }
    #[test]
    const fn get_last() {
        let params = Parameters{amount: 3, content: ContentType::new(b"* LS :multi-prefix sasl")};
        let last_param = params.extract_last();
        let last = last_param.as_bytes();
        assert!(last.len() == 17);
        assert!(is_identical(last, b"multi-prefix sasl"));
        let params = Parameters{amount: 1, content: ContentType::new(b":multi-prefix sasl")};
        let last_param = params.extract_last();
        let last = last_param.as_bytes();
        assert!(last.len() == 17);
        assert!(is_identical(last, b"multi-prefix sasl"));
    }
    #[test]
    const fn get_specific() {
        let params = Parameters{amount: 3, content: ContentType::new(b"* LS :multi-prefix sasl")};
        let first_param = params.extract_specific(0);
        assert!(first_param.is_some());
        if let Some(first_param) = first_param {
            let first = first_param.as_bytes();
            assert!(first[0] == b'*');
            assert!(first.len() == 1);
        }
        let second_param = params.extract_specific(1);
        assert!(second_param.is_some());
        if let Some(second_param) = second_param {
            let second = second_param.as_bytes();
            assert!(is_identical(second, b"LS"));
            assert!(second.len() == 2);
        }
        let last_param = params.extract_specific(2);
        assert!(last_param.is_some());
        if let Some(last_param) = last_param {
            let last = last_param.as_bytes();
            assert!(is_identical(last, b"multi-prefix sasl"));
            assert!(last.len() == 17);
        }
        let out_of_bounds_param = params.extract_specific(9);
        assert!(out_of_bounds_param.is_none());
    }
    #[test]
    const fn parameters_uft8() {
        let input = b"* LS :multi-prefix sasl";
        let params = Parameters::parse(input);
        assert!(params.is_ok());
        if let Ok(params) = params {
            assert!(params.is_some());
            if let Some(params) = params {assert!(params.is_valid_uft8());}
        }
        let input = &[159, 146, 150];
        let params = Parameters::parse(input);
        assert!(params.is_ok());
        if let Ok(params) = params {
            assert!(params.is_some());
            if let Some(params) = params {assert!(!params.is_valid_uft8());}
        }
    }
    #[test]
    const fn parsing_parameters() {
        let input = b"* LS :multi-prefix sasl";
        let params = Parameters::parse(input);
        assert!(params.is_ok());
        if let Ok(params) = params {
            assert!(params.is_some());
            if let Some(params) = params {
                assert!(params.amount == 3);
                assert!(is_identical(params.content.as_bytes(), input));
            }
        }
        assert!(Parameters::parse(b"\0\0\0\0").is_err());
    }
}