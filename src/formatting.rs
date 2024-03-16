//! Methods for detecting, extracting and separating an [`IrcFmtByte`].
//!
//! ## Purpose
//!
//! IRC messages can contain formatting bytes to indicate the application of formatting to text.
//! Both [`IrcFmtByte::Colour`] and [`IrcFmtByte::HexColour`] may have bytes after them that are
//! to be interperated as colours rather than part of the message content.
//! Detecting these bytes allows you to decide what to do when they are encountered.
//! The [specification] indicates where they are likely to be encountered within an [`IrcMsg`](crate::IrcMsg).
//!
//! [specification]: <https://modern.ircdocs.horse/formatting>

/// A part of the input split up.
pub type MsgPart<'input> = &'input [u8];
/// A [`MsgPart`] wrapped in an [`Option`].
pub type OptMsgPart<'input> = Option<MsgPart<'input>>;
/// The contents of foreground and background colours if present.
pub type OptIrcColours<'input> = Option<(MsgPart<'input>, OptMsgPart<'input>)>;

/// A byte that indicates formatting to apply to text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrcFmtByte {
    /// Toggle bold formatting. [`u8`] value of `2` (byte `\x02`).
    Bold,
    /// Toggle italic formatting. [`u8`] value of `29` (byte `\x1d`).
    Italics,
    /// Toggle underline formatting. [`u8`] value of `31` (byte `\x1f`).
    Underline,
    /// Toggle strikethrough formatting. [`u8`] value of `30` (byte `\x1e`).
    Strikethrough,
    /// Toggle monospace formatting. [`u8`] value of `17` (byte `\x11`).
    Monospace,
    /// Reset or apply foreground/background colours using irc colour codes. [`u8`] value of `3` (byte `\x03`).
    ///
    /// Valid colour codes are `0`-`99`.
    /// `0`-`15` are usually author defined.
    /// `16`-`98` are specified.
    /// `99` indicates a resetting to the default colour.
    /// No colour codes after the colour byte indicates a colour reset.
    /// Background colour cannot be specified without first specifying a foreground colour followed by a comma.
    Colour,
    /// Reset or apply foreground/background colours using hex values. [`u8`] value of `4` (byte `\x04`).
    ///
    /// `6` hexadecimal digits, `2` each representing the red, green and blue values.
    /// No colour codes after the colour byte indicates a colour reset.
    /// Background colour cannot be specified without first specifying a foreground colour followed by a comma.
    HexColour,
    /// Toggle reversing the colour. [`u8`] value of `22` (byte `\x16`).
    ReverseColour,
    /// Reset all formatting to default. [`u8`] value of `15` (byte `\x0f`).
    Reset,
}

impl IrcFmtByte {
    const fn detect(input: u8) -> Option<Self> {
        match input {
            2 => Some(Self::Bold),
            3 => Some(Self::Colour),
            4 => Some(Self::HexColour),
            15 => Some(Self::Reset),
            17 => Some(Self::Monospace),
            22 => Some(Self::ReverseColour),
            29 => Some(Self::Italics),
            30 => Some(Self::Strikethrough),
            31 => Some(Self::Underline),
            _ => None,
        }
    }
    /// Checks whether the `input` contains an [`IrcFmtByte`].
    #[must_use]
    pub const fn contains_irc_formatting(input: &[u8]) -> bool {
        let mut index = 0;
        while index < input.len() {
            if Self::detect(input[index]).is_some() {return true;}
            index += 1;
        }
        false
    }
    /// Returns both the [`IrcFmtByte`] and the `index` it occurs at if present.
    ///
    /// The `nth` parameter is a 0 based index.
    #[must_use]
    pub const fn find_nth_fmt_byte_and_position(input: &[u8], nth: usize) -> Option<(Self, usize)> {
        let (mut index, mut count) = (0, 0);
        while index < input.len() {
            if let Some(fb) = Self::detect(input[index]) {
                if count == nth {return Some((fb, index));}
                count += 1;
            }
            index += 1;
        }
        None
    }
    /// Counts each [`IrcFmtByte`] in `input`.
    ///
    /// The count does not contain the bytes that represent irc colour codes or hex values.
    #[must_use]
    pub const fn count_fmt_bytes(input: &[u8]) -> usize {
        let (mut index, mut count) = (0, 0);
        while index < input.len() {
            if Self::detect(input[index]).is_some() {count += 1;}
            index += 1;
        }
        count
    }
    /// Returns message parts split both sides of the [`IrcFmtByte`] along with the byte and colours if present.
    ///
    /// If `input` is empty it returns `None`.
    ///
    /// Output is split into 4 parts:
    ///
    /// 1 - All bytes before the first [`IrcFmtByte`]. `None` if the first byte is the [`IrcFmtByte`].
    ///
    /// 2 - The [`IrcFmtByte`] if present.
    ///
    /// 3 - The colours specified for [`IrcFmtByte::Colour`] or [`IrcFmtByte::HexColour`] if present.
    ///
    /// 4 - All bytes after the colours if present including further formatting bytes. `None` if the last byte is part of a colour or the [`IrcFmtByte`].
    #[must_use]
    pub const fn split_at_first_fmt_byte(input: &[u8]) -> Option<(OptMsgPart, Option<Self>, OptIrcColours, OptMsgPart)> {
        if input.is_empty() {return None;} // already made sure input is not empty
        if Self::contains_irc_formatting(input) {
            let mut index = 0;
            while index < input.len() {
                if let Some(fb) = Self::detect(input[index]) {
                    let (before, including) = input.split_at(index); // including = 1 or more bytes
                    let before = if before.is_empty() {None} else {Some(before)};
                    if let Some((_, after)) = including.split_first() { // always happens even if after is empty
                        match fb {
                            Self::Bold | Self::Italics | Self::Underline | Self::Strikethrough | Self::Monospace |
                            Self::ReverseColour | Self::Reset => {
                                let after = if after.is_empty() {None} else {Some(after)};
                                return Some((before, Some(fb), None, after));
                            },
                            Self::Colour => {
                                if after.is_empty() {
                                    return Some((before, Some(fb), None, None));
                                } else if let Some(codes) = Self::irc_colour_codes(after) {
                                    match codes {
                                        ColourCodeSize::SingleDigit => {
                                            let (colours, after_code) = Self::one_colour(after, 1);
                                            return Some((before, Some(fb), colours, after_code));
                                        },
                                        ColourCodeSize::DoubleDigit => {
                                            let (colours, after_code) = Self::one_colour(after, 2);
                                            return Some((before, Some(fb), colours, after_code));
                                        },
                                        ColourCodeSize::SingleAndSingle => {
                                            let (colours, after_codes) = Self::two_colours(after, 1, 1);
                                            return Some((before, Some(fb), colours, after_codes));
                                        },
                                        ColourCodeSize::SingleAndDouble => {
                                            let (colours, after_codes) = Self::two_colours(after, 1, 2);
                                            return Some((before, Some(fb), colours, after_codes));
                                        },
                                        ColourCodeSize::DoubleAndSingle => {
                                            let (colours, after_codes) = Self::two_colours(after, 2, 1);
                                            return Some((before, Some(fb), colours, after_codes));
                                        },
                                        ColourCodeSize::DoubleAndDouble => {
                                            let (colours, after_codes) = Self::two_colours(after, 2, 2);
                                            return Some((before, Some(fb), colours, after_codes));
                                        },
                                    }
                                }
                                return Some((before, Some(fb), None, Some(after)));
                            },
                            Self::HexColour => {
                                if after.is_empty() {
                                    return Some((before, Some(fb), None, None));
                                } else if after.len() > 5 {
                                    let (first_colour, comma_onwards) = after.split_at(6);
                                    if is_hex_colour(first_colour) {
                                        if comma_onwards.len() > 6 {
                                            if let Some((comma, after_comma)) = comma_onwards.split_first() {
                                                if *comma == b',' {
                                                    let (second_colour, onwards) = after_comma.split_at(6);
                                                    if is_hex_colour(second_colour) {
                                                        let onwards = if onwards.is_empty() {None} else {Some(onwards)};
                                                        let colours = Some((first_colour, Some(second_colour)));
                                                        return Some((before, Some(fb), colours, onwards));
                                                    }
                                                }
                                            }
                                        }
                                        let rest = if comma_onwards.is_empty() {None} else {Some(comma_onwards)};
                                        return Some((before, Some(fb), Some((first_colour, None)), rest));
                                    }
                                }
                                return Some((before, Some(fb), None, Some(after)));
                            },
                        }
                    }
                }
                index += 1;
            }
        }
        Some((Some(input), None, None, None))
    }
    const fn one_colour(after: &[u8], index: usize) -> (OptIrcColours, OptMsgPart) {
        let (code, after_code) = after.split_at(index);
        (Some((code, None)), if after_code.is_empty() {None} else {Some(after_code)})
    }
    const fn two_colours(after: &[u8], first_split: usize, last_split: usize) -> (OptIrcColours, OptMsgPart) {
        let (foreground, comma_onwards) = after.split_at(first_split);
        let (_, after_comma) = comma_onwards.split_at(1);
        let (background, after_codes) = after_comma.split_at(last_split);
        (Some((foreground, Some(background))), if after_codes.is_empty() {None} else {Some(after_codes)})
    }
    const fn irc_colour_codes(input: &[u8]) -> Option<ColourCodeSize> {
        let mut index = 0;
        let (mut foreground_first, mut foreground_second) = (false, false);
        let mut comma = false;
        let (mut background_first, mut background_second) = (false, false);
        while index < input.len() {
            match index {
                0 => if input[index].is_ascii_digit() {foreground_first = true;} else {break;},
                1 => {
                    if input[index].is_ascii_digit() {foreground_second = true;}
                    else if input[index] == b',' {comma = true;}
                    else {break;}
                },
                2 => {
                    if input[index].is_ascii_digit() {background_first = true;}
                    else if input[index] == b',' {comma = true;}
                    else {break;}
                },
                3 => {
                    if input[index].is_ascii_digit() && foreground_first && foreground_second && comma {
                        background_first = true;
                    } else if input[index].is_ascii_digit() && foreground_first && !foreground_second && comma
                    && background_first {background_second = true;
                    } else {break;}
                },
                4 => if input[index].is_ascii_digit() {background_second = true;} else {break;},
                _ => break,
            }
            index += 1;
        }
        match (foreground_first, foreground_second, comma, background_first, background_second) {
            (true, false, true | false, false, false) => Some(ColourCodeSize::SingleDigit),
            (true, true, true | false, false, false) => Some(ColourCodeSize::DoubleDigit),
            (true, false, true, true, false) => Some(ColourCodeSize::SingleAndSingle),
            (true, false, true, true, true) => Some(ColourCodeSize::SingleAndDouble),
            (true, true, true, true, false) => Some(ColourCodeSize::DoubleAndSingle),
            (true, true, true, true, true) => Some(ColourCodeSize::DoubleAndDouble),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColourCodeSize {
    SingleDigit,
    DoubleDigit,
    SingleAndSingle,
    SingleAndDouble,
    DoubleAndSingle,
    DoubleAndDouble,
}

const fn is_hex_colour(input: &[u8]) -> bool {
    let mut index = 0;
    while index < input.len() {
        if !input[index].is_ascii_hexdigit() {return false;}
        index += 1;
    }
    true
}

#[cfg(test)]
mod const_tests {
    use crate::is_identical;
    use super::IrcFmtByte;
    #[test]
    const fn detect_irc_formatting() {
        assert!(IrcFmtByte::contains_irc_formatting(b"Hey \x0366,88wha\x0399t's\x0400ff07,6672f4 u\x0fp!"));
        assert!(!IrcFmtByte::contains_irc_formatting(b"Hey what's up!"));
    }
    #[test]
    const fn count_irc_formatting_bytes() {
        assert!(IrcFmtByte::count_fmt_bytes(b"\x02\x1d\x1f\x1e\x11\x16\x037\x04\x0f") == 9);
    }
    #[test]
    const fn find_nth_fmt_byte() {
        let result = IrcFmtByte::find_nth_fmt_byte_and_position(b"Hey \x0366,88wha\x0399t's\x0400ff07 u\x0fp!", 1);
        assert!(result.is_some());
        if let Some((fb, index)) = result {
            if let IrcFmtByte::Colour = fb {assert!(true);}
            assert!(index == 13);
        }
        assert!(IrcFmtByte::find_nth_fmt_byte_and_position(b"Hey what's up!", 1).is_none());
    }
    #[test]
    const fn splitting_messages() {
        assert!(IrcFmtByte::split_at_first_fmt_byte(&[]).is_none());
        let input = b"Hey what's up!";
        let output = IrcFmtByte::split_at_first_fmt_byte(input);
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(msg) = before {assert!(is_identical(input, msg));}
            assert!(fb.is_none());
            assert!(colours.is_none());
            assert!(after.is_none());
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey wh\x11at's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey wh"));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Monospace = fb {assert!(true);}}
            assert!(colours.is_none());
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"at's up!"));}
        }
    }
    #[test]
    const fn splitting_messages_colours() {
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x037what's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"7"));
                assert!(bg.is_none());
            }
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"what's up!"));}
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x0377what's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"77"));
                assert!(bg.is_none());
            }
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"what's up!"));}
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x037,8what's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"7"));
                assert!(bg.is_some());
                if let Some(bg) = bg {assert!(is_identical(bg, b"8"));}
            }
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"what's up!"));}
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x0376,8what's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"76"));
                assert!(bg.is_some());
                if let Some(bg) = bg {assert!(is_identical(bg, b"8"));}
            }
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"what's up!"));}
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x0376,88what's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"76"));
                assert!(bg.is_some());
                if let Some(bg) = bg {assert!(is_identical(bg, b"88"));}
            }
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"what's up!"));}
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x037,88what's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"7"));
                assert!(bg.is_some());
                if let Some(bg) = bg {assert!(is_identical(bg, b"88"));}
            }
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"what's up!"));}
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x03");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_none());
            assert!(after.is_none());
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x03!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::Colour = fb {assert!(true);}}
            assert!(colours.is_none());
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"!"));}
        }
    }
    #[test]
    const fn splitting_messages_hex() {
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x04787878what's up!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::HexColour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"787878"));
                assert!(bg.is_none());
            }
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"what's up!"));}
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x04787878,ffaabb");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::HexColour = fb {assert!(true);}}
            assert!(colours.is_some());
            if let Some((fg, bg)) = colours {
                assert!(is_identical(fg, b"787878"));
                assert!(bg.is_some());
                if let Some(bg) = bg {assert!(is_identical(bg, b"ffaabb"));}
            }
            assert!(after.is_none());
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x04");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::HexColour = fb {assert!(true);}}
            assert!(colours.is_none());
            assert!(after.is_none());
        }
        let output = IrcFmtByte::split_at_first_fmt_byte(b"Hey \x04!");
        assert!(output.is_some());
        if let Some((before, fb, colours, after)) = output {
            assert!(before.is_some());
            if let Some(before) = before {assert!(is_identical(before, b"Hey "));}
            assert!(fb.is_some());
            if let Some(fb) = fb {if let IrcFmtByte::HexColour = fb {assert!(true);}}
            assert!(colours.is_none());
            assert!(after.is_some());
            if let Some(after) = after {assert!(is_identical(after, b"!"));}
        }
    }
}
