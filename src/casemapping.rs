//! Method for checking equivalency of slices using [`IrcCaseMapping`].
//!
//! ## Purpose
//!
//! IRC servers advertise which casemapping approach they use in the `RPL_ISUPPORT` (`005`) numeric [`IrcMsg`](crate::IrcMsg).
//! A `CASEMAPPING` [`ISupportToken`](crate::isupport::ISupportToken) will specify which approach the server uses.
//! The casemapping is performed on client names, server names and channel names.
//! Enforcing casemapping can prevent confusion.

/// The possible casemapping approaches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrcCaseMapping {
    /// Lowercase and uppercase ascii letters are considered equivalent.
    Ascii,
    /// Same as ascii but with the following additions:
    ///
    /// `{` is lowercase of `[`.\
    /// `}` is lowercase of `]`.\
    /// `|` is lowercase of `\`.\
    /// `^` is lowercase of `~`.
    Rfc1459,
    /// Same as rfc1459 but excludes `^` and `~`.
    Rfc1459Strict,
}

impl IrcCaseMapping {
    /// Check if both slices are equivalent according to the casemapping aproach.
    #[must_use]
    pub const fn is_equivalent(&self, first: &[u8], second: &[u8]) -> bool {
        if first.len() != second.len() {return false;}
        let mut index = 0;
        while index < first.len() {
            if first[index].is_ascii_alphabetic() && second[index].is_ascii_alphabetic() {
                if first[index].eq_ignore_ascii_case(&second[index]) {return false;}
            } else if first[index] != second[index] {
                match self {
                    Self::Ascii => return false,
                    Self::Rfc1459 => if !IrcCaseMapping::rfc1459_is_equivalent(first[index], second[index], false) {
                        return false;
                    },
                    Self::Rfc1459Strict => if !IrcCaseMapping::rfc1459_is_equivalent(first[index], second[index], true) {
                        return false;
                    },
                }
            }
            index += 1;
        }
        true
    }
    const fn rfc1459_is_equivalent(first: u8, second: u8, strict: bool) -> bool {
        match (first, second) {
            (b'{', b'[') | (b'[', b'{') | (b'}', b']') | (b']', b'}') | (b'|', b'\\') | (b'\\', b'|') => true,
            (b'^', b'~') | (b'~', b'^') if !strict => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod const_tests {
    use crate::casemapping::IrcCaseMapping;
    #[test]
    const fn is_equal_ascii() {
        let first = b"bob";
        let second = b"BOB";
        let casemapping = IrcCaseMapping::Ascii;
        assert!(casemapping.is_equivalent(first, second));
    }
    #[test]
    const fn is_equal_rfc1459() {
        let first = b"^ob";
        let second = b"~oB";
        let casemapping = IrcCaseMapping::Rfc1459;
        assert!(casemapping.is_equivalent(first, second));
    }
    #[test]
    const fn is_equal_rfc1459_strict() {
        let first = b"{ob";
        let second = b"[oB";
        let casemapping = IrcCaseMapping::Rfc1459Strict;
        assert!(casemapping.is_equivalent(first, second));
    }
    #[test]
    const fn bad_len() {
        let first = b"bob";
        let second = b"BOBBY";
        let casemapping = IrcCaseMapping::Ascii;
        assert!(!casemapping.is_equivalent(first, second));
    }
    #[test]
    const fn not_equal_ascii() {
        let first = b"bob";
        let second = b"B0B";
        let casemapping = IrcCaseMapping::Ascii;
        assert!(!casemapping.is_equivalent(first, second));
    }
    #[test]
    const fn not_equal_rfc1459() {
        let first = b"^ob";
        let second = b"#oB";
        let casemapping = IrcCaseMapping::Rfc1459;
        assert!(!casemapping.is_equivalent(first, second));
    }
    #[test]
    const fn not_equal_rfc1459_strict() {
        let first = b"^ob";
        let second = b"~oB";
        let casemapping = IrcCaseMapping::Rfc1459Strict;
        assert!(!casemapping.is_equivalent(first, second));
    }
}
