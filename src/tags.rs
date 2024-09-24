//! Methods for parsing and extracting information from [`Tags`].
//!
//! ## Purpose
//!
//! [`Tags`] are an optional extension to the IRC message format defined in the [Message Tag Specification].
//! They always occur at the start of an [`IrcMsg`](crate::IrcMsg), if present, before the [`Source`](crate::Source).
//! They are intended to supply extra information about a message in the form of metadata.
//! The metadata they contain gets used in many optional features.
//! An IRC server must not include [`Tags`] in an [`IrcMsg`](crate::IrcMsg) sent to an IRC client unless
//! the client has specifically enabled support via [capability negotiation].
//!
//! [Message Tag Specification]: <https://ircv3.net/specs/extensions/message-tags.html>
//! [capability negotiation]: <https://ircv3.net/specs/extensions/capability-negotiation.html>

/// All the tags of an [`IrcMsg`](crate::IrcMsg).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tags<'msg> {
    amount: usize,
    content: &'msg str,
}

impl<'msg> Tags<'msg> {
    /// Generates [`Tags`] from a slice of bytes.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is empty, only contains the leading `@`, doesn't start
    /// with the leading `@`, or contains non-utf8 bytes. It will also return `Err` if the
    /// `key_name` or `escaped_value` of any [`Tag`] contains invalid bytes as per the [Message Tag Specification].
    ///
    /// [Message Tag Specification]: <https://ircv3.net/specs/extensions/message-tags.html>
    pub const fn parse(input: &'msg [u8]) -> Result<Self, TagsError> {
        if input.is_empty() {return Err(TagsError::EmptyInput);}
        else if input.len() > 8190 {return Err(TagsError::TagBytesExceededBy(input.len() - 8190));}
        else if input[0] != b'@' {return Err(TagsError::InvalidStartingPrefix(input[0]));}
        else if input.len() == 1 {return Err(TagsError::NoTags);}
        match core::str::from_utf8(input) {
            Ok(content) => {
                let mut amount = 0;
                let end_of_tags = input.len() - 1;
                let mut escaped_value_started = false;
                let mut previous_semicolon = true;
                let mut index = 0;
                while index < input.len() {
                    if input[index] == b';' || index == end_of_tags {
                        if previous_semicolon {return Err(TagsError::EmptyKeyName);}
                        previous_semicolon = true;
                        amount += 1;
                        escaped_value_started = false;
                    } else if input[index] == b'=' && !escaped_value_started {
                        escaped_value_started = true;
                        previous_semicolon = false;
                    } else if escaped_value_started && is_invalid_escaped_value_byte(input[index]) {
                        return Err(TagsError::InvalidEscapedValueByte(input[index]));
                    } else {
                        previous_semicolon = false;
                    }
                    index += 1;
                }
                Ok(Tags{amount, content})
            },
            Err(_) => Err(TagsError::NotUtf8),
        }
    }
    /// Returns the amount of tags in [`Tags`].
    #[must_use]
    pub const fn count(&self) -> usize {
        self.amount
    }
    /// Returns all the tags as a string slice.
    ///
    /// This includes the leading `@` but excludes the trailing space.
    #[must_use]
    pub const fn content(&self) -> &str {
        self.content
    }
    /// Returns the first [`Tag`] from all the [`Tags`].
    #[must_use]
    pub const fn extract_first(&self) -> Tag {
        match self.extract_specific(0) {
            Some(tag) => tag,
            None => unreachable!(),
        }
    }
    /// Returns the last [`Tag`] from all the [`Tags`].
    #[must_use]
    pub const fn extract_last(&self) -> Tag {
        match self.extract_specific(self.amount-1) {
            Some(tag) => tag,
            None => unreachable!(),
        }
    }
    /// Returns the requested [`Tag`] at the specified index.
    ///
    /// Index starts at 0. If out of bounds it returns `None`.
    #[must_use]
    pub const fn extract_specific(&self, target_index: usize) -> Option<Tag> {
        if target_index > self.amount {return None;}
        let bytes = self.content.as_bytes();
        let mut current_tag = 0;
        let mut current_tag_start = 1;
        let mut tag = Tag {client_prefix: false, vendor: None, key_name: "", escaped_value: None};
        let mut copy = bytes;
        let mut offset = 0;
        let mut key_name_start = 0;
        let mut index = 0;
        while index < bytes.len() {
            if current_tag == target_index {
                if bytes[index] == b'+' {
                    tag.client_prefix = true;
                } else if bytes[index] == b'/' {
                    if tag.client_prefix {
                        (_, copy) = bytes.split_at(current_tag_start + 1);
                        offset = current_tag_start + 1;
                    } else {
                        (_, copy) = bytes.split_at(current_tag_start);
                        offset = current_tag_start;
                    }
                    (copy, _) = copy.split_at((index) - offset);
                    if let Ok(vendor) = core::str::from_utf8(copy) {tag.vendor = Some(vendor);}
                    (_, copy) = bytes.split_at(index + 1);
                    offset = index + 1;
                    key_name_start = offset;
                } else if bytes[index] == b'=' {
                    if tag.vendor.is_some() {
                        (copy, _) = copy.split_at(index - offset);
                        if let Ok(key_name) = core::str::from_utf8(copy) {tag.key_name = key_name;}
                    } else {
                        (_, copy) = bytes.split_at(current_tag_start);
                        (copy, _) = copy.split_at(index - 1);
                        if let Ok(key_name) = core::str::from_utf8(copy) {tag.key_name = key_name;}
                    }
                    if index + 1 == bytes.len() - 1 {break;}
                    offset = index + 1; // start of escaped_value
                } else if bytes[index] == b';' || index == bytes.len() - 1 {
                    if !tag.key_name.is_empty() {
                        (_, copy) = bytes.split_at(offset);
                        if index != bytes.len() - 1 {(copy, _) = copy.split_at(index - offset);}
                        if let Ok(ev) = core::str::from_utf8(copy) {tag.escaped_value = Some(ev);}
                    } else if tag.vendor.is_some() {
                        (_, copy) = bytes.split_at(key_name_start);
                        if index != bytes.len() - 1 {(copy, _) = copy.split_at(index - key_name_start);}
                        if let Ok(key_name) = core::str::from_utf8(copy) {tag.key_name = key_name;}
                    } else {
                        (_, copy) = bytes.split_at(current_tag_start);
                        if index != bytes.len() - 1 {(copy, _) = copy.split_at(index - current_tag_start);}
                        if let Ok(key_name) = core::str::from_utf8(copy) {tag.key_name = key_name;}
                    }
                    break;
                }
            } else if bytes[index] == b';' {
                current_tag += 1;
                current_tag_start = index + 1;
            }
            index += 1;
        }
        Some(tag)
    }
}

impl<'msg> core::fmt::Display for Tags<'msg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.content)
    }
}

/// A single tag extracted from all the [`Tags`] of an [`IrcMsg`](crate::IrcMsg).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tag<'msg> {
    client_prefix: bool,
    vendor: Option<&'msg str>,
    key_name: &'msg str,
    escaped_value: Option<&'msg str>,
}

impl<'msg> Tag<'msg> {
    /// Check if the [`Tag`] is a client only tag.
    ///
    /// Vendors can have a client only prefix denoted by `+`.
    /// In the absence of a `vendor` this will return `false`.
    #[must_use]
    pub const fn is_client_only_tag(&self) -> bool {
        self.client_prefix
    }
    /// Return the `vendor` of a [`Tag`] if it exists.
    #[must_use]
    pub const fn vendor(&self) -> Option<&str> {
        self.vendor
    }
    /// Return the `key_name` of a [`Tag`].
    #[must_use]
    pub const fn key_name(&self) -> &str {
        self.key_name
    }
    /// Return the `escaped_value` of a [`Tag`] if it exists.
    #[must_use]
    pub const fn escaped_value(&self) -> Option<&str> {
        self.escaped_value
    }
}

impl<'msg> core::fmt::Display for Tag<'msg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let cp = if self.client_prefix {"+"} else {""};
        let (v, slash) = if let Some(vendor) = self.vendor {(vendor, "/")} else {("", "")};
        let (esc, eq) = if let Some(ev) = self.escaped_value {(ev, "=")} else {("", "")};
        write!(f, "{}{}{}{}{}{}", cp, v, slash, self.key_name, eq, esc)
    }
}

const fn is_invalid_escaped_value_byte(input: u8) -> bool {
    match input {
        // null ('\0'), linefeed ('\n'), carriage return ('\r'), space (' ')
        0 | 10 | 13 | 32 => true,
        _ => false,
    }
}

/// The possible types of errors when parsing [`Tags`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagsError {
    /// The byte slice input is empty.
    EmptyInput,
    /// The first byte was not `@`.
    InvalidStartingPrefix(u8),
    /// The amount of bytes greater than the maximum permitted for [`Tags`].
    TagBytesExceededBy(usize),
    /// No bytes after the initial `@`.
    NoTags,
    /// No key name detected before `;` or end of tags.
    EmptyKeyName,
    /// Use of an invalid byte in the escaped value.
    InvalidEscapedValueByte(u8),
    /// A part of the [`Tags`] contains non-utf8 bytes.
    NotUtf8,
}

#[cfg(test)]
mod const_tests {
    use crate::is_identical;
    use super::Tags;
    #[test]
    const fn parsing_tags() {
        assert!(Tags::parse(b"@aaa=bbb;ccc;example.com/ddd=eee").is_ok());
        assert!(Tags::parse(b"@aaa=bbb;ccc;example.com/ddd=").is_ok());
        assert!(Tags::parse(b"@aaa=bbb;;example.com/ddd=").is_err());
        assert!(Tags::parse(b"@aaa=b\0b;ccc;example.com/ddd=eee").is_err());
        assert!(Tags::parse(b"").is_err());
        assert!(Tags::parse(&[b'@', 0, 159, 146, 150]).is_err());
    }
    #[test]
    const fn get_specific() {
        let tags = Tags::parse(b"@aaa=bbb;ccc;example.com/ddd");
        assert!(tags.is_ok());
        if let Ok(tags) = tags {
            assert!(tags.amount == 3);
            let first_tag = tags.extract_specific(0);
            assert!(first_tag.is_some());
            if let Some(first_tag) = first_tag {
                assert!(!first_tag.client_prefix);
                assert!(first_tag.vendor.is_none());
                assert!(first_tag.key_name.len() == 3);
                assert!(is_identical(first_tag.key_name.as_bytes(), b"aaa"));
                assert!(first_tag.escaped_value.is_some());
                if let Some(ev) = first_tag.escaped_value {
                    assert!(ev.len() == 3);
                    assert!(is_identical(ev.as_bytes(), b"bbb"));
                }
            }
            let second_tag = tags.extract_specific(1);
            assert!(second_tag.is_some());
            if let Some(second_tag) = second_tag {
                assert!(!second_tag.client_prefix);
                assert!(second_tag.vendor.is_none());
                assert!(second_tag.key_name.len() == 3);
                assert!(is_identical(second_tag.key_name.as_bytes(), b"ccc"));
                assert!(second_tag.escaped_value.is_none());
            }
            let last_tag = tags.extract_specific(2);
            assert!(last_tag.is_some());
            if let Some(last_tag) = last_tag {
                assert!(!last_tag.client_prefix);
                assert!(last_tag.vendor.is_some());
                if let Some(vendor) = last_tag.vendor {
                    assert!(vendor.len() == 11);
                    assert!(is_identical(vendor.as_bytes(), b"example.com"));
                }
                assert!(last_tag.key_name.len() == 3);
                assert!(is_identical(last_tag.key_name.as_bytes(), b"ddd"));
                assert!(last_tag.escaped_value.is_none());
            }
            let out_of_bounds_tag = tags.extract_specific(9);
            assert!(out_of_bounds_tag.is_none());
        }
    }
    #[test]
    const fn get_first() {
        let tags = Tags::parse(b"@aaa=bbb");
        assert!(tags.is_ok());
        if let Ok(tags) = tags {
            let first_tag = tags.extract_first();
            assert!(!first_tag.client_prefix);
            assert!(first_tag.vendor.is_none());
            assert!(first_tag.key_name.len() == 3);
            assert!(is_identical(first_tag.key_name.as_bytes(), b"aaa"));
            assert!(first_tag.escaped_value.is_some());
            if let Some(ev) = first_tag.escaped_value {
                assert!(ev.len() == 3);
                assert!(is_identical(ev.as_bytes(), b"bbb"));
            }
        }
    }
    #[test]
    const fn get_last() {
        let tags = Tags::parse(b"@+example.com/ddd=eee");
        assert!(tags.is_ok());
        if let Ok(tags) = tags {
            let last_tag = tags.extract_last();
            assert!(last_tag.client_prefix);
            assert!(last_tag.vendor.is_some());
            if let Some(vendor) = last_tag.vendor {
                assert!(vendor.len() == 11);
                assert!(is_identical(vendor.as_bytes(), b"example.com"));
            }
            assert!(last_tag.key_name.len() == 3);
            assert!(is_identical(last_tag.key_name.as_bytes(), b"ddd"));
            assert!(last_tag.escaped_value.is_some());
            if let Some(ev) = last_tag.escaped_value {
                assert!(ev.len() == 3);
                assert!(is_identical(ev.as_bytes(), b"eee"));
            }
        }
    }
}
