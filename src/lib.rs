//! # Const IRC Message Parser
//!
//! A crate that allows you to parse a slice of bytes into a whole [`IrcMsg`] or parse a
//! slice of bytes into the individual components that make up an [`IrcMsg`]. It also
//! allows you to extract whichever portion of the message you want.
//!
//! This is a `#![no_std]` crate that does not require [alloc] and has no dependencies.
//!
//! ## Motivation
//!
//! I wanted to see how much of an IRC message parser can be written in a [const context]. Every public
//! and private function is const. I was even able to make all the tests const functions even
//! though it ends up being more verbose. The only exceptions are the Display impls as functions on Traits are
//! not yet allowed to be const ([click here for details]). I am also unaware of how to
//! test Display impls in a const manner for code coverage. Suggestions welcome.
//!
//! ## Usage
//!
//! Ensure you have a single message as a slice of bytes from your network.
//! Feed that single slice into the parser without the trailing carriage return and line feed to create an [`IrcMsg`].
//! Use the provided methods to extract the information desired for an IRC client, server or bot.
//!
//! [click here for details]: <https://github.com/rust-lang/rust/issues/103265>
//! [alloc]: <https://doc.rust-lang.org/alloc/index.html>
//! [const context]: <https://doc.rust-lang.org/reference/const_eval.html>
#![no_std]
#![allow(clippy::module_name_repetitions)]

use tags::{Tags, TagsError};
use source::{Source, SourceError};
use command::{Command, CommandError};
use parameters::{Parameters, ParametersError};

pub mod tags;
pub mod source;
pub mod command;
pub mod parameters;
pub mod formatting;
pub mod isupport;

/// A single IRC Message created from a slice of bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrcMsg<'msg> {
    tags: Option<Tags<'msg>>,
    source: Option<Source<'msg>>,
    command: Command<'msg>,
    parameters: Option<Parameters<'msg>>,
}

impl<'msg> IrcMsg<'msg> {
    /// Generates an [`IrcMsg`] from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is empty or any of the [`IrcMsg`] components fail to parse.
    pub const fn parse(input: &'msg[u8]) -> Result<Self, IrcMsgError> {
        if input.is_empty() {return Err(IrcMsgError::EmptyInput);}
        let (mut tags, mut tag_present, mut after_tag_end, mut tag_finished) = (None, false, 0, false);
        let (mut source, mut source_present, mut after_source_end, mut source_finished) = (None, false, 0, false);
        let (mut command_started, mut after_command_end) = (false, 0);
        let (mut parameters, mut parameters_started) = (None, false);
        let mut copy = input;
        let mut index = 0;
        while index < input.len() {
            if index == 0 && input[index] == b'@' {
                tag_present = true;
            } else if index == 0 && input[index] == b':' {
                source_present = true;
            } else if index == 0 && input[index] != b':' && input[index] != b'@' {
                command_started = true;
            } else if tag_finished && !command_started && !source_present && input[index] == b':' {
                source_present = true;
            } else if tag_present && !tag_finished && input[index] == b' ' {
                tag_finished = true;
                after_tag_end = index + 1;
                let (t, rest) = input.split_at(index);
                copy = remove_possible_leading_space(rest);
                match Tags::parse(t) {
                    Ok(all_tags) => tags = Some(all_tags),
                    Err(e) => return Err(IrcMsgError::Tags(e)),
                }
            } else if source_present && !source_finished && input[index] == b' ' {
                source_finished = true;
                after_source_end = index + 1;
                let (s, rest) = copy.split_at(index - after_tag_end);
                copy = remove_possible_leading_space(rest);
                match Source::parse(s) {
                    Ok(src) => source = Some(src),
                    Err(e) => return Err(IrcMsgError::Source(e)),
                }
                command_started = true;
            } else if command_started && !parameters_started && input[index] == b' ' {
                parameters_started = true;
                let (c, _) = if source_present {copy.split_at(index - after_source_end)}
                else {copy.split_at(index - after_tag_end)};
                copy = c;
                after_command_end = index + 1;
            } else if tag_finished && !source_present && !command_started {
                command_started = true;
            } else if parameters_started {break;}
            index += 1;
        }
        let command = if parameters_started {
            let (_, p) = input.split_at(after_command_end);
            match Parameters::parse(p) {
                Ok(params) => {
                    parameters = params;
                    if let Some(params) = params {
                        match Command::parse(copy, params.count()) {
                            Ok(cmd) => cmd,
                            Err(e) => return Err(IrcMsgError::Command(e)),
                        }
                    } else {unreachable!();}
                },
                Err(e) => return Err(IrcMsgError::Parameters(e)),
            }
        } else {
            match Command::parse(copy, 0) {
                Ok(cmd) => cmd,
                Err(e) => return Err(IrcMsgError::Command(e)),
            }
        };
        Ok(Self{tags, source, command, parameters})
    }
    /// Generates a utf8-only [`IrcMsg`] from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is empty, contains non-utf8 bytes 
    /// or any of the [`IrcMsg`] components fail to parse.
    pub const fn parse_utf8_only(input: &'msg[u8]) -> Result<Self, IrcMsgError> {
        match Self::parse(input) {
            Ok(msg) => {
                match ContentType::new(input) {
                    ContentType::StringSlice(_) => Ok(msg),
                    ContentType::NonUtf8ByteSlice(_) => Err(IrcMsgError::NonUtf8Message),
                }
            },
            Err(e) => Err(e),
        }
    }
    /// Extract the [`Tags`] from an [`IrcMsg`] if they exist.
    #[must_use]
    pub const fn tags(&self) -> Option<Tags> {
        self.tags
    }
    /// Extract the [`Source`] from an [`IrcMsg`] if it exists.
    #[must_use]
    pub const fn source(&self) -> Option<Source> {
        self.source
    }
    /// Extract the [`Command`] from an [`IrcMsg`].
    #[must_use]
    pub const fn command(&self) -> Command {
        self.command
    }
    /// Extract the [`Parameters`] from an [`IrcMsg`] if they exist.
    #[must_use]
    pub const fn parameters(&self) -> Option<Parameters> {
        self.parameters
    }
    /// Strips the [`Tags`] from an [`IrcMsg`].
    ///
    /// If a client doesn't support [IRC Tags] you can strip them from the [`IrcMsg`].
    /// Probably most useful for IRC server software as IRC servers should never send
    /// clients messages with [`Tags`] unless the client indicates their support for them.
    ///
    /// [IRC Tags]: <https://ircv3.net/specs/extensions/message-tags.html>
    #[must_use]
    pub const fn strip_tags(mut self) -> Self {
        if self.tags.is_some() {self.tags = None;}
        self
    }
}

impl<'msg> core::fmt::Display for IrcMsg<'msg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(tags) = self.tags {write!(f, "{tags} ")?;}
        if let Some(source) = self.source {write!(f, "{source} ")?;}
        let cmd = match self.command {Command::Named(inner) | Command::Numeric(inner) => inner};
        if let Some(params) = self.parameters {write!(f, "{cmd} {params}")} else {write!(f, "{cmd}")}
    }
}

/// The possible types of errors when parsing an [`IrcMsg`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrcMsgError<'msg> {
    /// An error occurred in parsing the [`Tags`].
    Tags(TagsError),
    /// An error occurred in parsing the [`Source`].
    Source(SourceError),
    /// An error occurred in parsing the [`Command`].
    Command(CommandError<'msg>),
    /// An error occurred in parsing the [`Parameters`].
    Parameters(ParametersError),
    /// A part of the message contains non-utf8 bytes.
    NonUtf8Message,
    /// The byte slice input is empty.
    EmptyInput,
}

const fn remove_possible_leading_space(input: &[u8]) -> &[u8] {
    if input[0] == b' ' {if let Some((_, rest)) = input.split_first() {return rest;}}
    input
}

/// A wrapper containing either a string slice or a non-utf8 slice of bytes.
///
/// # Motivation
///
/// It is possible for an [`IrcMsg`] to contain non-utf8 bytes and still be valid.
/// I wanted to provide the option to create such messages to allow the user of this library to
/// decide what they want to do with the content.
///
/// # Limitations
///
/// I cannot use [from_utf8_lossy] in a `#![no_std]` and const context to display the contents of
/// a non-utf8 slice of bytes with replacement characters in this library.
/// The user of this library is not under the same restriction.
/// The [Display] impl thus prints the array of bytes the same way as deriving [Debug] does.
///
/// [from_utf8_lossy]: <https://doc.rust-lang.org/std/string/struct.String.html#method.from_utf8_lossy>
/// [Display]: <https://doc.rust-lang.org/core/fmt/trait.Display.html>
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentType<'msg> {
    /// A utf8 string slice.
    StringSlice(&'msg str),
    /// A non-utf8 slice of bytes.
    NonUtf8ByteSlice(&'msg [u8]),
}

impl<'msg> ContentType<'msg> {
    const fn new(input: &'msg [u8]) -> Self {
        if let Ok(output) = core::str::from_utf8(input) {Self::StringSlice(output)}
        else {Self::NonUtf8ByteSlice(input)}
    }
    /// Checks if inner contents are valid utf8.
    #[must_use]
    pub const fn is_valid_utf8(&self) -> bool {
        match self {
            Self::StringSlice(_) => true,
            Self::NonUtf8ByteSlice(_) => false,
        }
    }
    /// Returns the inner contents as an array of bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            ContentType::StringSlice(slice) => slice.as_bytes(),
            ContentType::NonUtf8ByteSlice(b) => b,
        }
    }
}

impl<'msg> core::fmt::Display for ContentType<'msg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StringSlice(output) => write!(f, "{output}"),
            Self::NonUtf8ByteSlice(output) => write!(f, "{output:?}"),
        }
    }
}

const fn is_identical(first: &[u8], second: &[u8]) -> bool {
    if first.len() == second.len() {
        let mut index = 0;
        while index < first.len() {
            if first[index] != second[index] {return false;}
            index += 1;
        }
        return true;
    }
    false
}

#[cfg(test)]
mod const_tests {
    use crate::{remove_possible_leading_space, ContentType, IrcMsg, source::Origin, command::Command, is_identical};
    pub const fn is_nick(input: Origin) -> bool {
        match input {
            Origin::Servername(_) => false,
            Origin::Nickname(_) => true,
        }
    }
    const fn is_named(input: Command) -> bool {
        match input {
            Command::Named(_) => true,
            Command::Numeric(_) => false,
        }
    }
    #[test]
    const fn removing_first_space() {
        assert!(!is_identical(b" whatever", remove_possible_leading_space(b" whatever")));
        assert!(is_identical(b"whatever", remove_possible_leading_space(b"whatever")));
    }
    #[test]
    const fn displaying_nonutf8() {
        assert!(!ContentType::new(&[0, 159, 146, 150]).is_valid_utf8());
        assert!(is_identical(ContentType::new(&[0, 159, 146, 150]).as_bytes(), &[0, 159, 146, 150]));
        assert!(ContentType::new(b"whatever").is_valid_utf8());
    }
    #[test]
    const fn remove_tags() {
        let msg = IrcMsg::parse(b"@id=234AB :dan!d@localhost PRIVMSG #chan :Hey what's up!");
        assert!(msg.is_ok());
        if let Ok(mut msg) = msg {
            msg = msg.strip_tags();
            assert!(msg.tags.is_none());
        }
    }
    #[test]
    const fn get_command() {
        let msg = IrcMsg::parse(b"INFO");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {
            assert!(is_named(msg.command()));
            if let Command::Named(cmd) = msg.command {assert!(is_identical(cmd.as_bytes(), b"INFO"));}
        }
    }
    #[test]
    const fn get_parameters() {
        let msg = IrcMsg::parse(b":dan!d@localhost PRIVMSG #chan :Yo!");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {assert!(msg.parameters().is_some());}
        let msg = IrcMsg::parse(b"INFO");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {assert!(msg.parameters().is_none());}
    }
    #[test]
    const fn parsing_ircmsg() {
        assert!(IrcMsg::parse(b"@id=2\034AB :dan!d@localhost PRIVMSG #chan :Hey what's up!").is_err());
        assert!(IrcMsg::parse(b"@id=234AB :dan!d@lo\0calhost PRIVMSG #chan :Hey what's up!").is_err());
        assert!(IrcMsg::parse(b"@id=234AB :dan!d@localhost PRI\0VMSG #chan :Hey what's up!").is_err());
        assert!(IrcMsg::parse(b"@id=234AB :dan!d@localhost PRIVMSG #ch\0an :Hey what's up!").is_err());
        assert!(IrcMsg::parse(b"PRIVMSG").is_err());
        assert!(IrcMsg::parse_utf8_only(&[80, 82, 73, 86, 77, 83, 71, 32, 35, 97, 97, 32, 58, 159, 146, 150]).is_err());
        assert!(IrcMsg::parse_utf8_only(&[0, 159, 146, 150]).is_err());
        assert!(IrcMsg::parse(b"INFO").is_ok());
        assert!(IrcMsg::parse(&[]).is_err());
        let msg = IrcMsg::parse(b"@id=234AB :dan!d@localhost PRIVMSG #chan :Hey what's up!");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {
            assert!(msg.tags.is_some());
            if let Some(tags) = msg.tags {
                assert!(tags.count() == 1);
                assert!(is_identical(tags.content().as_bytes(), b"@id=234AB"));
                let only_tag = tags.extract_first();
                assert!(!only_tag.is_client_only_tag());
                assert!(only_tag.vendor().is_none());
                assert!(is_identical(only_tag.key_name().as_bytes(), b"id"));
                assert!(only_tag.escaped_value().is_some());
                if let Some(ev) = only_tag.escaped_value() {assert!(is_identical(ev.as_bytes(), b"234AB"));}
            }
            assert!(msg.source.is_some());
            if let Some(src) = msg.source() {
                assert!(src.prefix() == ':');
                assert!(is_nick(src.origin()));
                if let Origin::Nickname(n_source) = src.origin() {
                    assert!(is_identical(n_source.nick().as_bytes(), b"dan"));
                    assert!(n_source.user_prefix().is_some());
                    if let Some(user_prefix) = n_source.user_prefix() {assert!(user_prefix == '!');}
                    assert!(n_source.user().is_some());
                    if let Some(user) = n_source.user() {assert!(is_identical(user.as_bytes(), b"d"));}
                    assert!(n_source.host_prefix().is_some());
                    if let Some(host_prefix) = n_source.host_prefix() {assert!(host_prefix == '@');}
                    assert!(n_source.host().is_some());
                    if let Some(host) = n_source.host() {assert!(is_identical(host.as_bytes(), b"localhost"));}
                }
            }
            assert!(is_named(msg.command));
            if let Command::Named(cmd) = msg.command {assert!(is_identical(cmd.as_bytes(), b"PRIVMSG"));}
            assert!(msg.parameters.is_some());
            if let Some(params) = msg.parameters {
                assert!(params.count() == 2);
                assert!(is_identical(params.content().as_bytes(), b"#chan :Hey what's up!"));
                let first_param = params.extract_first();
                assert!(is_identical(first_param.as_bytes(), b"#chan"));
                let last_param = params.extract_last();
                assert!(is_identical(last_param.as_bytes(), b"Hey what's up!"));
            }
        }
        let msg = IrcMsg::parse(b"@time=2023-10-29T19:28:04.424Z PING :tantalum.libera.chat");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {
            assert!(msg.tags().is_some());
            if let Some(tags) = msg.tags {
                assert!(tags.count() == 1);
                assert!(is_identical(tags.content().as_bytes(), b"@time=2023-10-29T19:28:04.424Z"));
                let only_tag = tags.extract_first();
                assert!(!only_tag.is_client_only_tag());
                assert!(only_tag.vendor().is_none());
                assert!(is_identical(only_tag.key_name().as_bytes(), b"time"));
                assert!(only_tag.escaped_value().is_some());
                if let Some(ev) = only_tag.escaped_value() {
                    assert!(is_identical(ev.as_bytes(), b"2023-10-29T19:28:04.424Z"));
                }
            }
            assert!(msg.source().is_none());
            assert!(is_named(msg.command));
            if let Command::Named(cmd) = msg.command {assert!(is_identical(cmd.as_bytes(), b"PING"));}
            assert!(msg.parameters.is_some());
            if let Some(params) = msg.parameters() {
                assert!(params.count() == 1);
                assert!(is_identical(params.content().as_bytes(), b":tantalum.libera.chat"));
            }
        }
        let msg = IrcMsg::parse(b"@time=2023-10-29T19:30:19.424Z ERROR :Closing Link");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {
            assert!(msg.tags().is_some());
            if let Some(tags) = msg.tags {
                assert!(tags.count() == 1);
                assert!(is_identical(tags.content().as_bytes(), b"@time=2023-10-29T19:30:19.424Z"));
                let only_tag = tags.extract_first();
                assert!(!only_tag.is_client_only_tag());
                assert!(only_tag.vendor().is_none());
                assert!(is_identical(only_tag.key_name().as_bytes(), b"time"));
                assert!(only_tag.escaped_value().is_some());
                if let Some(ev) = only_tag.escaped_value() {
                    assert!(is_identical(ev.as_bytes(), b"2023-10-29T19:30:19.424Z"));
                }
            }
            assert!(msg.source().is_none());
            assert!(is_named(msg.command));
            if let Command::Named(cmd) = msg.command {assert!(is_identical(cmd.as_bytes(), b"ERROR"));}
            assert!(msg.parameters.is_some());
            if let Some(params) = msg.parameters() {
                assert!(params.count() == 1);
                assert!(is_identical(params.content().as_bytes(), b":Closing Link"));
            }
        }
        let msg = IrcMsg::parse_utf8_only(b":irc.example.com CAP LS * :multi-prefix extended-join sasl");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {
            assert!(msg.tags().is_none());
            assert!(msg.source.is_some());
            if let Some(src) = msg.source {
                assert!(src.prefix() == ':');
                assert!(!is_nick(src.origin()));
                if let Origin::Servername(s_source) = src.origin() {
                    assert!(is_identical(s_source.content().as_bytes(), b"irc.example.com"));
                }
            }
            assert!(is_named(msg.command));
            if let Command::Named(cmd) = msg.command {assert!(is_identical(cmd.as_bytes(), b"CAP"));}
            assert!(msg.parameters.is_some());
            if let Some(params) = msg.parameters {
                assert!(params.count() == 3);
                assert!(is_identical(params.content().as_bytes(), b"LS * :multi-prefix extended-join sasl"));
                let first_param = params.extract_first();
                assert!(is_identical(first_param.as_bytes(), b"LS"));
                let second_param = params.extract_specific(1);
                assert!(second_param.is_some());
                if let Some(sp) = second_param {assert!(is_identical(sp.as_bytes(), b"*"));}
                let last_param = params.extract_last();
                assert!(is_identical(last_param.as_bytes(), b"multi-prefix extended-join sasl"));
            }
        }
        let msg = IrcMsg::parse(b"CAP REQ :sasl");
        assert!(msg.is_ok());
        if let Ok(msg) = msg {
            assert!(msg.tags.is_none());
            assert!(msg.source.is_none());
            assert!(is_named(msg.command));
            if let Command::Named(cmd) = msg.command {assert!(is_identical(cmd.as_bytes(), b"CAP"));}
            assert!(msg.parameters.is_some());
            if let Some(params) = msg.parameters {
                assert!(params.count() == 2);
                assert!(is_identical(params.content().as_bytes(), b"REQ :sasl"));
                let first_param = params.extract_first();
                assert!(is_identical(first_param.as_bytes(), b"REQ"));
                let last_param = params.extract_last();
                assert!(is_identical(last_param.as_bytes(), b"sasl"));
            }
        }
    }
}
