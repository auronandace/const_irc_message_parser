//! Methods for parsing and extracting information from [`Source`].
//!
//! ## Purpose
//!
//! [`Source`] is part of the [IRC Message Protocol].
//! The [`Source`] occurs after the [`Tags`](crate::Tags) and before the [`Command`](crate::Command).
//! Since [`Tags`](crate::Tags) are optional it is possible for the [`Source`] to be the first
//! component of an [`IrcMsg`](crate::IrcMsg).
//! It identifies the [`Origin`] of where the message was generated.
//! IRC servers are always responsible for generating the [`Source`] on behalf of the client
//! and can choose whether or not to send it with an [`IrcMsg`](crate::IrcMsg).
//! IRC clients must never include the [`Source`] when sending an [`IrcMsg`](crate::IrcMsg) but must
//! be able to process every [`IrcMsg`](crate::IrcMsg) with or without [`Source`].
//!
//! [IRC Message Protocol]: <https://modern.ircdocs.horse/#source>

use crate::ContentType;

/// The source of an [`IrcMsg`](crate::IrcMsg).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source<'msg> {
    prefix: char,
    from: Origin<'msg>,
}

impl<'msg> Source<'msg> {
    /// Generates a [`Source`] from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is empty, doesn't start with `:` or contains an invalid character
    /// as per the [IRC Client Protocol Specification].
    ///
    /// [IRC Client Protocol Specification]: <https://modern.ircdocs.horse/#source>
    pub const fn parse(mut input: &'msg [u8]) -> Result<Self, SourceError> {
        if input.is_empty() {return Err(SourceError::EmptyInput);}
        let prefix = if input[0] == b':' {':'} else {return Err(SourceError::InvalidStartingPrefix(input[0]))};
        let (mut nick_end, mut user_end, mut probably_servername) = (0, 0, false);
        let (mut user_prefix, mut user, mut host_prefix, mut host) = (false, None, false, None);
        let mut index = 0;
        while index < input.len() {
            if is_invalid_byte(input[index]) {
                return Err(SourceError::InvalidByte(input[index]));
            } else if input[index] == b'!' {
                user_prefix = true;
                nick_end = index - 1;
            } else if input[index] == b'@' && user_prefix {
                host_prefix = true;
                user_end = index - nick_end - 2;
            } else if input[index] == b'@' && !user_prefix {
                host_prefix = true;
                nick_end = index - 1;
            } else if input[index] == b'.' && !user_prefix && !host_prefix {
                probably_servername = true;
            }
            index += 1;
        }
        if let Some((_, rest)) = input.split_first() {input = rest;} // remove starting ':'
        let from = if probably_servername {
            Origin::Servername(Servername(ContentType::new(input)))
        } else if user_prefix && host_prefix {
            let (nick, rest) = input.split_at(nick_end);
            if nick.is_empty() {return Err(SourceError::InvalidNickByte(33));} // '!' parsed as user prefix
            if is_invalid_nick_starting_byte(nick[0]) {return Err(SourceError::InvalidNickStartingByte(nick[0]));}
            if let Some(byte) = invalid_nick_byte(nick) {return Err(SourceError::InvalidNickByte(byte));}
            input = rest;
            if let Some((_, rest)) = input.split_first() {input = rest;} // remove '!'
            let (u, rest) = input.split_at(user_end);
            if u.is_empty() {return Err(SourceError::InvalidNickByte(33));} // '!' parsed as user prefix
            user = Some(ContentType::new(u));
            input = rest;
            if let Some((_, rest)) = input.split_first() {input = rest;} // remove '@'
            if input.is_empty() {return Err(SourceError::InvalidNickByte(64));} // '@' parsed as host prefix
            host = Some(ContentType::new(input));
            Origin::Nickname(Nickname{nick: ContentType::new(nick), user, host})
        } else if user_prefix {
            let (nick, rest) = input.split_at(nick_end);
            if nick.is_empty() {return Err(SourceError::InvalidNickByte(33));} // '!' parsed as user prefix
            if is_invalid_nick_starting_byte(nick[0]) {return Err(SourceError::InvalidNickStartingByte(nick[0]));}
            if let Some(byte) = invalid_nick_byte(nick) {return Err(SourceError::InvalidNickByte(byte));}
            input = rest;
            if let Some((_, rest)) = input.split_first() {input = rest;} // remove '!'
            if input.is_empty() {return Err(SourceError::InvalidNickByte(33));} // '!' parsed as user prefix
            user = Some(ContentType::new(input));
            Origin::Nickname(Nickname{nick: ContentType::new(nick), user, host})
        } else if host_prefix {
            let (nick, rest) = input.split_at(nick_end);
            if nick.is_empty() {return Err(SourceError::InvalidNickByte(64));} // '@' parsed as host prefix
            if is_invalid_nick_starting_byte(nick[0]) {return Err(SourceError::InvalidNickStartingByte(nick[0]));}
            if let Some(byte) = invalid_nick_byte(nick) {return Err(SourceError::InvalidNickByte(byte));}
            input = rest;
            if let Some((_, rest)) = input.split_first() {input = rest;} // remove '@'
            if input.is_empty() {return Err(SourceError::InvalidNickByte(64));} // '@' parsed as host prefix
            host = Some(ContentType::new(input));
            Origin::Nickname(Nickname{nick: ContentType::new(nick), user, host})
        } else {
            if is_invalid_nick_starting_byte(input[0]) {return Err(SourceError::InvalidNickStartingByte(input[0]));}
            if let Some(byte) = invalid_nick_byte(input) {return Err(SourceError::InvalidNickByte(byte));}
            Origin::Nickname(Nickname{nick: ContentType::new(input), user, host})
        };
        Ok(Source{prefix, from})
    }
    /// The mandatory prefix character `:`.
    #[must_use]
    pub const fn prefix(&self) -> char {
        self.prefix
    }
    /// Extract the [`Origin`] of [`Source`].
    #[must_use]
    pub const fn origin(&self) -> Origin {
        self.from
    }
}

impl core::fmt::Display for Source<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{}", self.prefix, self.from)
    }
}

const fn is_invalid_byte(input: u8) -> bool {
    match input {
        // null ('\0'), linefeed ('\n'), carriage return ('\r'), space (' ')
        0 | 10 | 13 | 32 => true,
        _ => false,
    }
}

const fn is_invalid_nick_starting_byte(input: u8) -> bool {
    match input {
        // dollar ('$'), colon (':')
        36 | 58 => true,
        _ => false,
    }
}

const fn invalid_nick_byte(input: &[u8]) -> Option<u8> {
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            // space (' '), exclamation mark ('!'), asterisk ('*'), comma (','), question mark ('?'), at ('@')
            32 | 33 | 42 | 44 | 63 | 64 => return Some(input[index]),
            _ => {},
        }
        index += 1;
    }
    None
}

/// Indicates where the [`IrcMsg`](crate::IrcMsg) was originally generated.
///
/// An IRC client must never send an [`IrcMsg`](crate::IrcMsg) with [`Source`] but must
/// be able to process an [`IrcMsg`](crate::IrcMsg) with or without [`Source`].
/// An IRC server is always responsible for generating the [`Source`] and can
/// chose whether or not to send it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin<'msg> {
    /// The name of the server where the [`IrcMsg`](crate::IrcMsg) originated from.
    Servername(Servername<'msg>),
    /// The nickname and possibly user and host details where the [`IrcMsg`](crate::IrcMsg) originated from.
    Nickname(Nickname<'msg>),
}

impl Origin<'_> {
    /// Checks whether the [`Source`] contains non-utf8 bytes.
    #[must_use]
    pub const fn is_valid_utf8(&self) -> bool {
        match self {
            Self::Servername(servername) => servername.0.is_valid_utf8(),
            Self::Nickname(nickname) => {
                let valid_user = if let Some(user) = nickname.user {user.is_valid_utf8()} else {true};
                let valid_host = if let Some(host) = nickname.host {host.is_valid_utf8()} else {true};
                nickname.nick.is_valid_utf8() && valid_user && valid_host
            },
        }
    }
}

impl core::fmt::Display for Origin<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Origin::Servername(servername) => write!(f, "{servername}"),
            Origin::Nickname(nickname) => write!(f, "{nickname}"),
        }
    }
}

/// The name of the server where the [`IrcMsg`](crate::IrcMsg) originated from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Servername<'msg>(ContentType<'msg>);

impl Servername<'_> {
    /// Extract the server name from the [`Source`].
    #[must_use]
    pub const fn content(&self) -> ContentType {
        self.0
    }
}

impl core::fmt::Display for Servername<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The nickname and possibly user and host details where the [`IrcMsg`](crate::IrcMsg) originated from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nickname<'msg> {
    nick: ContentType<'msg>,
    user: Option<ContentType<'msg>>,
    host: Option<ContentType<'msg>>,
}

impl Nickname<'_> {
    /// Extract the nick from the [`Source`].
    #[must_use]
    pub const fn nick(&self) -> ContentType {
        self.nick
    }
    /// Extract the user from the [`Source`] if it exists.
    #[must_use]
    pub const fn user(&self) -> Option<ContentType> {
        self.user
    }
    /// Extract the host from the [`Source`] if it exists.
    #[must_use]
    pub const fn host(&self) -> Option<ContentType> {
        self.host
    }
}

impl core::fmt::Display for Nickname<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.user.is_some() && self.host.is_some() {
            write!(f, "{}!{}@{}", self.nick, self.user.as_ref().unwrap(), self.host.as_ref().unwrap())
        } else if self.user.is_some() {
            write!(f, "{}!{}", self.nick, self.user.as_ref().unwrap())
        } else if self.host.is_some() {
            write!(f, "{}@{}", self.nick, self.host.as_ref().unwrap())
        } else {
            write!(f, "{}", self.nick)
        }
    }
}

/// The possible types of errors when parsing [`Source`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// The byte slice input is empty.
    EmptyInput,
    /// The first byte was not `:`.
    InvalidStartingPrefix(u8),
    /// Use of an invalid byte when parsing [`Source`].
    InvalidByte(u8),
    /// Use of an invalid starting byte for [`Nickname`].
    InvalidNickStartingByte(u8),
    /// Use of an invalid byte in the [`Nickname`].
    InvalidNickByte(u8),
}

#[cfg(test)]
mod const_tests {
    use crate::{const_tests::is_nick, ContentType, is_identical};
    use super::{Origin, Nickname, Servername, Source};
    const fn is_same_content(first: ContentType, second: &str) -> bool {
        match first {
            ContentType::StringSlice(s) => is_identical(s.as_bytes(), second.as_bytes()),
            ContentType::NonUtf8ByteSlice(b) => is_identical(b, second.as_bytes()),
        }
    }
    #[test]
    const fn source_utf8() {
        let src = Source{prefix: ':', from: Origin::Servername(Servername(ContentType::StringSlice("blah")))};
        assert!(src.from.is_valid_utf8());
        let src = Source{prefix: ':', from: Origin::Nickname(Nickname{
            nick: ContentType::StringSlice("blah"),
            user: None,
            host: None,
        })};
        assert!(src.from.is_valid_utf8());
    }
    #[test]
    const fn parsing_source() {
        assert!(Source::parse(b":dave").is_ok());
        assert!(Source::parse(b":dave!d@david").is_ok());
        assert!(Source::parse(b":dave!d").is_ok());
        assert!(Source::parse(b":dave@david").is_ok());
        assert!(Source::parse(b":d:ave").is_ok());
        assert!(Source::parse(b":example.com").is_ok());
        assert!(Source::parse(b":!").is_err());      // empty nick, empty user
        assert!(Source::parse(b":@").is_err());      // empty nick, empty host
        assert!(Source::parse(b":!@").is_err());     // empty nick, empty user, empty host
        assert!(Source::parse(b":dave!").is_err());  // empty user
        assert!(Source::parse(b":dave!@").is_err()); // empty user, empty host
        assert!(Source::parse(b":bob!d@").is_err()); // empty host
        assert!(Source::parse(b":bob@").is_err());   // empty host
        assert!(Source::parse(b":!dave@").is_err()); // empty nick, empty host
        assert!(Source::parse(b":!@dave").is_err()); // empty nick, empty user
        assert!(Source::parse(b": dave").is_err());  // space not permitted in nick
        assert!(Source::parse(b"::dave").is_err());  // colon not permitted as starting char in nick
        assert!(Source::parse(b":d?ve").is_err());   // question mark not permitted in nick
        let input = b":goliath!bob@david";
        let source = Source::parse(input);
        assert!(source.is_ok());
        if let Ok(src) = Source::parse(input) {
            assert!(is_nick(src.from));
            if let Origin::Nickname(n) = src.from {
                assert!(is_same_content(n.nick, "goliath"));
                assert!(n.user.is_some());
                if let Some(user) = n.user {assert!(is_same_content(user, "bob"));}
                assert!(n.host.is_some());
                if let Some(host) = n.host {assert!(is_same_content(host, "david"));}
            }
        }
        let input = ":example.com".as_bytes();
        let source = Source::parse(input);
        assert!(source.is_ok());
        if let Ok(src) = Source::parse(input) {
            assert!(!is_nick(src.from));
            if let Origin::Servername(s) = src.from {assert!(is_same_content(s.0, "example.com"));}
        }
    }
}
