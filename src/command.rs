//! Method for parsing and extracting a [`Command`].
//!
//! ## Purpose
//!
//! [`Command`] is part of the [IRC Message Protocol].
//! It must never be empty.
//! The [`Command`] occurs after the [`Source`](crate::Source) and before the [`Parameters`](crate::Parameters).
//! Since both [`Tags`](crate::Tags) and [`Source`](crate::Source) are optional it is possible for [`Command`]
//! to be the first component in an [`IrcMsg`](crate::IrcMsg).
//! It can either be a `Named` or a `Numeric` command.
//! A `Numeric` is a 3 digit string representing a reply or an error to a `Named` command.
//! Some `Named` commands are only available after successful [capability negotiation].
//! For such commands an IRC server must never send them to an IRC client if the client doesn't indicate support
//! through the `CAP` command.
//! Some commands do not require any [`Parameters`](crate::Parameters) but most do.
//! The amount of [`Parameters`](crate::Parameters) and what they mean depends on the [`Command`].
//!
//! [IRC Message Protocol]: <https://modern.ircdocs.horse/#command>
//! [capability negotiation]: <https://ircv3.net/specs/extensions/capability-negotiation.html>

/// The command of an [`IrcMsg`](crate::IrcMsg).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command<'msg> {
    /// A [`Command`] in the form of a word.
    Named(&'msg str),
    /// A 3 digit number represented as a string.
    Numeric(&'msg str),
}

impl<'msg> Command<'msg> {
    /// Generates a [`Command`] from a slice of bytes and number of [`Parameters`](crate::Parameters).
    ///
    /// # Errors
    ///
    /// Will return `Err` if the input is empty, contains anything but ascii alphanumeric characters,
    /// is an unsupported `Named`/`Numeric` command or is provided too few parameters.
    /// Please file a bug report if you want to add support for a missing `Named`/`Numeric`
    /// command or the parameters required are too low.
    #[allow(clippy::too_many_lines)]
    pub const fn parse(input: &'msg [u8], params_amount: usize) -> Result<Self, CommandError> {
        if input.is_empty() {return Err(CommandError::EmptyInput);}
        let mut number_count = 0;
        let mut index = 0;
        while index < input.len() {
            if is_invalid_char(input[index]) {return Err(CommandError::InvalidByte(input[index]));}
            if input[index].is_ascii_digit() {number_count += 1;}
            index += 1;
        }
        if let Ok(cmd) = core::str::from_utf8(input) {
            if cmd.len() == 3 && number_count == 3 {
                let mut unhandled = false;
                match input {
                    b"042" | // RPL_YOURID/RPL_YOURUUID
                    b"250" | // RPL_STATSCONN/RPL_STATSDLINE
                    b"302"   // RPL_USERHOST
                    => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));},
                    b"001" | // RPL_WELCOME
                    b"002" | // RPL_YOURHOST
                    b"003" | // RPL_CREATED
                    b"005" | // RPL_ISUPPORT
                    b"105" | // RPL_REMOTEISUPPORT
                    b"203" | // RPL_TRACEUNKNOWN
                    b"221" | // RPL_UMODEIS
                    b"251" | // RPL_LUSERCLIENT
                    b"255" | // RPL_LUSERME
                    b"256" | // RPL_ADMINME
                    b"257" | // RPL_ADMINLOC1
                    b"258" | // RPL_ADMINLOC2
                    b"259" | // RPL_ADMINEMAIL
                    b"265" | // RPL_LOCALUSERS
                    b"266" | // RPL_GLOBALUSERS
                    b"271" | // RPL_SILELIST
                    b"272" | // RPL_ENDOFSILELIST
                    b"281" | // RPL_ACCEPTLIST/RPL_ENDOFGLIST
                    b"282" | // RPL_ENDOFACCEPT/RPL_JUPELIST
                    b"305" | // RPL_UNAWAY
                    b"306" | // RPL_NOWAWAY
                    b"321" | // RPL_LISTSTART
                    b"323" | // RPL_LISTEND
                    b"336" | // RPL_INVITELIST (not 346)
                    b"337" | // RPL_ENDOFINVITELIST (not 347)
                    b"354" | // RPL_WHOSPCRPL
                    b"371" | // RPL_INFO
                    b"372" | // RPL_MOTD
                    b"374" | // RPL_ENDOFINFO
                    b"375" | // RPL_MOTDSTART
                    b"376" | // RPL_ENDOFMOTD
                    b"381" | // RPL_YOUREOPER
                    b"406" | // ERR_WASNOSUCHNICK
                    b"409" | // ERR_NOORIGIN
                    b"410" | // ERR_INVALIDCAPCMD
                    b"417" | // ERR_INPUTTOOLONG
                    b"422" | // ERR_NOMOTD
                    b"451" | // ERR_NOTREGISTERED
                    b"456" | // ERR_ACCEPTFULL
                    b"462" | // ERR_ALREADYREGISTERED
                    b"464" | // ERR_PASSWDMISMATCH
                    b"465" | // ERR_YOUREBANNEDCREEP
                    b"476" | // ERR_BADCHANMASK
                    b"481" | // ERR_NOPRIVILEGES
                    b"483" | // ERR_CANTKILLSERVER
                    b"491" | // ERR_NOOPERHOST
                    b"501" | // ERR_UMODEUNKOWNFLAG
                    b"502" | // ERR_USERSDONTMATCH
                    b"511" | // ERR_SILELISTFULL
                    b"670" | // RPL_STARTTLS
                    b"691" | // ERR_STARTTLS
                    b"716" | // RPL_TARGUMODEG
                    b"717" | // RPL_TARGNOTIFY
                    b"730" | // RPL_MONONLINE
                    b"731" | // RPL_MONOFFLINE
                    b"732" | // RPL_MONLIST
                    b"733" | // RPL_ENDOFMONLIST
                    b"759" | // RPL_ETRACEEND
                    b"902" | // ERR_NICKLOCKED
                    b"903" | // RPL_SASLSUCCESS
                    b"904" | // ERR_SASLFAIL
                    b"905" | // ERR_SASLTOOLONG
                    b"906" | // ERR_SASLABORTED
                    b"907"   // ERR_SASLALREADY
                    => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));},
                    b"200" | // RPL_TRACELINK
                    b"201" | // RPL_TRACECONNECTING
                    b"202" | // RPL_TRACEHANDSHAKE
                    b"204" | // RPL_TRACEOPERATOR
                    b"205" | // RPL_TRACEUSER
                    b"208" | // RPL_TRACENEWTYPE
                    b"209" | // RPL_TRACECLASS
                    b"252" | // RPL_LUSEROP
                    b"253" | // RPL_LUSERUNKNOWN
                    b"254" | // RPL_LUSERCHANNELS
                    b"261" | // RPL_TRACELOG
                    b"263" | // RPL_TRYAGAIN
                    b"276" | // RPL_WHOISCERTFP
                    b"301" | // RPL_AWAY
                    b"307" | // RPL_WHOISREGNICK
                    b"313" | // RPL_WHOISOPERATOR
                    b"315" | // RPL_ENDOFWHO
                    b"318" | // RPL_ENDOFWHOIS
                    b"319" | // RPL_WHOISCHANNELS
                    b"320" | // RPL_WHOISSPECIAL
                    b"324" | // RPL_CHANNELMODEIS
                    b"329" | // RPL_CREATIONTIME
                    b"331" | // RPL_NOTOPIC
                    b"332" | // RPL_TOPIC
                    b"333" | // RPL_TOPICWHOTIME
                    b"335" | // RPL_WHOISBOT
                    b"338" | // RPL_WHOISACTUALLY
                    b"341" | // RPL_INVITING
                    b"346" | // RPL_INVEXLIST (not 336)
                    b"347" | // RPL_ENDOFINVEXLIST (not 337)
                    b"348" | // RPL_EXCEPTLIST
                    b"349" | // RPL_ENDOFEXCEPTLIST
                    b"365" | // RPL_ENDOFLINKS
                    b"366" | // RPL_ENDOFNAMES
                    b"367" | // RPL_BANLIST
                    b"368" | // RPL_ENDOFBANLIST
                    b"369" | // RPL_ENDOFWHOWAS
                    b"378" | // RPL_WHOISHOST
                    b"379" | // RPL_WHOISMODES
                    b"382" | // RPL_REHASHING
                    b"391" | // RPL_TIME
                    b"396" | // RPL_HOSTHIDDEN/RPL_VISIBLEHOST/RPL_YOURDISPLAYEDHOST
                    b"400" | // ERR_UNKNOWNERROR
                    b"401" | // ERR_NOSUCHNICK
                    b"402" | // ERR_NOSUCHSERVER
                    b"403" | // ERR_NOSUCHCHANNEL
                    b"404" | // ERR_CANNOTSENDTOCHAN
                    b"405" | // ERR_TOOMANYCHANNELS
                    b"421" | // ERR_UNKNOWNCOMMAND
                    b"432" | // ERR_ERRONEUSNICKNAME
                    b"433" | // ERR_NICKNAMEINUSE
                    b"442" | // ERR_NOTONCHANNEL
                    b"457" | // ERR_ACCEPTEXIST
                    b"458" | // ERR_ACCEPTNOT
                    b"461" | // ERR_NEEDMOREPARAMS
                    b"471" | // ERR_CHANNELISFULL
                    b"472" | // ERR_UNKNOWNMODE
                    b"473" | // ERR_INVITEONLYCHAN
                    b"474" | // ERR_BANNEDFROMCHAN
                    b"475" | // ERR_BADCHANNELKEY
                    b"482" | // ERR_CHANOPRIVSNEEDED
                    b"524" | // ERR_HELPNOTFOUND
                    b"525" | // ERR_INVALIDKEY
                    b"671" | // RPL_WHOISSECURE
                    b"704" | // RPL_HELPSTART
                    b"705" | // RPL_HELPTXT
                    b"706" | // RPL_ENDOFHELP
                    b"718" | // RPL_UMODEGMSG
                    b"723" | // ERR_NOPRIVS
                    b"901" | // RPL_LOGGEDOUT
                    b"908" | // RPL_SASLMECHS
                    b"950" | // RPL_UNSILENCED
                    b"951" | // RPL_SILENCED
                    b"952"   // ERR_SILENCE
                    => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));},
                    b"010" | // RPL_BOUNCE (possibly RPL_REDIR)
                    b"262" | // RPL_TRACEEND/RPL_ENDOFTRACE/RPL_TRACEPING
                    b"312" | // RPL_WHOISSERVER
                    b"322" | // RPL_LIST
                    b"330" | // RPL_WHOISACCOUNT
                    b"351" | // RPL_VERSION
                    b"353" | // RPL_NAMREPLY
                    b"364" | // RPL_LINKS
                    b"441" | // ERR_USERNOTINCHANNEL
                    b"443" | // ERR_USERONCHANNEL
                    b"734" | // ERR_MONLISTFULL
                    b"900"   // RPL_LOGGEDIN
                    => if params_amount < 4 {return Err(CommandError::MinimumArgsRequired(4, cmd));},
                    b"004" | // RPL_MYINFO
                    b"206" | // RPL_TRACESERVER
                    b"207" | // RPL_TRACESERVICE
                    b"317" | // RPL_WHOISIDLE
                    b"696"   // ERR_INVALIDMODEPARAM
                    => if params_amount < 5 {return Err(CommandError::MinimumArgsRequired(5, cmd));},
                    b"311" | // RPL_WHOISUSER
                    b"314"   // RPL_WHOWASUSER
                    => if params_amount < 6 {return Err(CommandError::MinimumArgsRequired(6, cmd));},
                    b"709"   // RPL_ETRACE
                    => if params_amount < 7 {return Err(CommandError::MinimumArgsRequired(7, cmd));},
                    b"352" | // RPL_WHOREPLY
                    b"708"   // RPL_ETRACEFULL
                    => if params_amount < 8 {return Err(CommandError::MinimumArgsRequired(8, cmd));},
                    _ => unhandled = true,
                }
                if unhandled {return Err(CommandError::UnhandledNumeric(cmd));}
                return Ok(Self::Numeric(cmd));
            } else if number_count > 0 {return Err(CommandError::NumberInNamedCommand(cmd));}
            match &command_to_uppercase_bytes(input) {
                b"INFO00000000" => return Ok(Self::Named("INFO")),
                b"LUSERS000000" => return Ok(Self::Named("LUSERS")),
                b"REHASH000000" => return Ok(Self::Named("REHASH")),
                b"RESTART00000" => return Ok(Self::Named("RESTART")),
                b"LINKS0000000" => return Ok(Self::Named("LINKS")),
                b"QUIT00000000" => return Ok(Self::Named("QUIT")),
                b"MOTD00000000" => return Ok(Self::Named("MOTD")),
                b"VERSION00000" => return Ok(Self::Named("VERSION")),
                b"ADMIN0000000" => return Ok(Self::Named("ADMIN")),
                b"TIME00000000" => return Ok(Self::Named("TIME")),
                b"HELP00000000" => return Ok(Self::Named("HELP")),
                b"AWAY00000000" => return Ok(Self::Named("AWAY")),
                b"LIST00000000" => return Ok(Self::Named("LIST")),
                b"ACK000000000" => return Ok(Self::Named("ACK")),
                b"ACCEPT000000" => return Ok(Self::Named("ACCEPT")),
                b"SILENCE00000" => return Ok(Self::Named("SILENCE")),
                b"DIE000000000" => return Ok(Self::Named("DIE")),
                b"TRACE0000000" => return Ok(Self::Named("TRACE")),
                b"ETRACE000000" => return Ok(Self::Named("ETRACE")),
                b"PASS00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("PASS"));},
                b"NICK00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("NICK"));},
                b"PING00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("PING"));},
                b"ERROR0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("ERROR"));},
                b"NAMES0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("NAMES"));},
                b"WHO000000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("WHO"));},
                b"WALLOPS00000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("WALLOPS"));},
                b"AUTHENTICATE" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("AUTHENTICATE"));},
                b"ACCOUNT00000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("ACCOUNT"));},
                b"CAP000000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("CAP"));},
                b"MODE00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("MODE"));},
                b"PONG00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("PONG"));},
                b"JOIN00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("JOIN"));},
                b"PART00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("PART"));},
                b"TOPIC0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("TOPIC"));},
                b"STATS0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("STATS"));},
                b"WHOIS0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("WHOIS"));},
                b"WHOWAS000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("WHOWAS"));},
                b"CONNECT00000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("CONNECT"));},
                b"USERHOST0000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("USERHOST"));},
                b"TAGMSG000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("TAGMSG"));},
                b"BATCH0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("BATCH"));},
                b"SETNAME00000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("SETNAME"));},
                b"MONITOR00000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("MONITOR"));},
                b"OPER00000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("OPER"));},
                b"INVITE000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("INVITE"));},
                b"PRIVMSG00000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("PRIVMSG"));},
                b"NOTICE000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("NOTICE"));},
                b"KILL00000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("KILL"));},
                b"SQUIT0000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("SQUIT"));},
                b"KICK00000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("KICK"));},
                b"CHGHOST00000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("CHGHOST"));},
                b"FAIL00000000" => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));}
                                   else {return Ok(Self::Named("FAIL"));},
                b"WARN00000000" => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));}
                                   else {return Ok(Self::Named("WARN"));},
                b"NOTE00000000" => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));}
                                   else {return Ok(Self::Named("NOTE"));},
                b"CPRIVMSG0000" => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));}
                                   else {return Ok(Self::Named("CPRIVMSG"));},
                b"CNOTICE00000" => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));}
                                   else {return Ok(Self::Named("CNOTICE"));},
                b"USER00000000" => if params_amount < 4 {return Err(CommandError::MinimumArgsRequired(4, cmd));}
                                   else {return Ok(Self::Named("USER"));},
                b"WEBIRC000000" => if params_amount < 4 {return Err(CommandError::MinimumArgsRequired(4, cmd));}
                                   else {return Ok(Self::Named("WEBIRC"));},
                _ => return Err(CommandError::UnhandledNamed(cmd)),
            }
        }
        unreachable!();
    }
}

impl<'msg> core::fmt::Display for Command<'msg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {Self::Named(inner) | Self::Numeric(inner) => write!(f, "{inner}")}
    }
}

/// The possible types of errors when parsing [`Command`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError<'msg> {
    /// The byte slice input is empty.
    EmptyInput,
    /// Use of an invalid byte when parsing [`Command`].
    InvalidByte(u8),
    /// A [`Command`] cannot be a mixture of numbers and letters.
    NumberInNamedCommand(&'msg str),
    /// The minimum required number of arguments for the specific [`Command`].
    MinimumArgsRequired(u8, &'msg str),
    /// A `Numeric` [`Command`] not currently supported by this parser.
    UnhandledNumeric(&'msg str),
    /// A `Named` [`Command`] not currently supported by this parser.
    UnhandledNamed(&'msg str),
}

const fn is_invalid_char(input: u8) -> bool {
    !input.is_ascii_alphanumeric()
}

const fn command_to_uppercase_bytes(input: &[u8]) -> [u8; 12] {
    let mut output = [b'0'; 12];
    let mut index = 0;
    while index < input.len() {
        if input[index].is_ascii_lowercase() {output[index] = input[index].to_ascii_uppercase();}
        else {output[index] = input[index];}
        index += 1;
    }
    output
}

#[cfg(test)]
mod const_tests {
    use crate::const_tests::is_identical;
    use super::{Command, command_to_uppercase_bytes};
    #[test]
    const fn parsing_command() {
        assert!(Command::parse(b"302", 1).is_ok());
        assert!(Command::parse(b"907", 2).is_ok());
        assert!(Command::parse(b"908", 3).is_ok());
        assert!(Command::parse(b"900", 4).is_ok());
        assert!(Command::parse(b"696", 5).is_ok());
        assert!(Command::parse(b"314", 6).is_ok());
        assert!(Command::parse(b"709", 7).is_ok());
        assert!(Command::parse(b"352", 8).is_ok());
        assert!(Command::parse(b"3027", 1).is_err());
        assert!(Command::parse(b"999", 1).is_err());
        assert!(Command::parse(b"info", 0).is_ok());
        assert!(Command::parse(b"LuSeRS", 0).is_ok());
        assert!(Command::parse(b"REHASH", 0).is_ok());
        assert!(Command::parse(b"RESTART", 0).is_ok());
        assert!(Command::parse(b"LINKs", 0).is_ok());
        assert!(Command::parse(b"QUIT", 0).is_ok());
        assert!(Command::parse(b"MOTD", 0).is_ok());
        assert!(Command::parse(b"VERSION", 0).is_ok());
        assert!(Command::parse(b"ADMIN", 0).is_ok());
        assert!(Command::parse(b"TIME", 0).is_ok());
        assert!(Command::parse(b"HELP", 0).is_ok());
        assert!(Command::parse(b"AWAY", 0).is_ok());
        assert!(Command::parse(b"LIST", 0).is_ok());
        assert!(Command::parse(b"ACK", 0).is_ok());
        assert!(Command::parse(b"ACCEPT", 0).is_ok());
        assert!(Command::parse(b"SILENCE", 0).is_ok());
        assert!(Command::parse(b"DIE", 0).is_ok());
        assert!(Command::parse(b"TRACE", 0).is_ok());
        assert!(Command::parse(b"ETRACE", 0).is_ok());
        assert!(Command::parse(b"PASS", 1).is_ok());
        assert!(Command::parse(b"PASS", 0).is_err());
        assert!(Command::parse(b"NICK", 1).is_ok());
        assert!(Command::parse(b"NICK", 0).is_err());
        assert!(Command::parse(b"PING", 1).is_ok());
        assert!(Command::parse(b"PING", 0).is_err());
        assert!(Command::parse(b"ERROR", 1).is_ok());
        assert!(Command::parse(b"ERROR", 0).is_err());
        assert!(Command::parse(b"NAMES", 1).is_ok());
        assert!(Command::parse(b"NAMES", 0).is_err());
        assert!(Command::parse(b"WHO", 1).is_ok());
        assert!(Command::parse(b"WHO", 0).is_err());
        assert!(Command::parse(b"WALLOPS", 1).is_ok());
        assert!(Command::parse(b"WALLOPS", 0).is_err());
        assert!(Command::parse(b"AUTHENTICATE", 1).is_ok());
        assert!(Command::parse(b"AUTHENTICATE", 0).is_err());
        assert!(Command::parse(b"ACCOUNT", 1).is_ok());
        assert!(Command::parse(b"ACCOUNT", 0).is_err());
        assert!(Command::parse(b"CAP", 1).is_ok());
        assert!(Command::parse(b"CAP", 0).is_err());
        assert!(Command::parse(b"MODE", 1).is_ok());
        assert!(Command::parse(b"MODE", 0).is_err());
        assert!(Command::parse(b"PONG", 1).is_ok());
        assert!(Command::parse(b"PONG", 0).is_err());
        assert!(Command::parse(b"JOIN", 1).is_ok());
        assert!(Command::parse(b"JOIN", 0).is_err());
        assert!(Command::parse(b"PART", 1).is_ok());
        assert!(Command::parse(b"PART", 0).is_err());
        assert!(Command::parse(b"TOPIC", 1).is_ok());
        assert!(Command::parse(b"TOPIC", 0).is_err());
        assert!(Command::parse(b"STATS", 1).is_ok());
        assert!(Command::parse(b"STATS", 0).is_err());
        assert!(Command::parse(b"WHOIS", 1).is_ok());
        assert!(Command::parse(b"WHOIS", 0).is_err());
        assert!(Command::parse(b"WHOWAS", 1).is_ok());
        assert!(Command::parse(b"WHOWAS", 0).is_err());
        assert!(Command::parse(b"CONNECT", 1).is_ok());
        assert!(Command::parse(b"CONNECT", 0).is_err());
        assert!(Command::parse(b"USERHOST", 1).is_ok());
        assert!(Command::parse(b"USERHOST", 0).is_err());
        assert!(Command::parse(b"TAGMSG", 1).is_ok());
        assert!(Command::parse(b"TAGMSG", 0).is_err());
        assert!(Command::parse(b"BATCH", 1).is_ok());
        assert!(Command::parse(b"BATCH", 0).is_err());
        assert!(Command::parse(b"SETNAME", 1).is_ok());
        assert!(Command::parse(b"SETNAME", 0).is_err());
        assert!(Command::parse(b"MONITOR", 1).is_ok());
        assert!(Command::parse(b"MONITOR", 0).is_err());
        assert!(Command::parse(b"OPER", 2).is_ok());
        assert!(Command::parse(b"OPER", 0).is_err());
        assert!(Command::parse(b"INVITE", 2).is_ok());
        assert!(Command::parse(b"INVITE", 0).is_err());
        assert!(Command::parse(b"PRIVMSG", 2).is_ok());
        assert!(Command::parse(b"PRIVMSG", 0).is_err());
        assert!(Command::parse(b"NOTICE", 2).is_ok());
        assert!(Command::parse(b"NOTICE", 0).is_err());
        assert!(Command::parse(b"KILL", 2).is_ok());
        assert!(Command::parse(b"KILL", 0).is_err());
        assert!(Command::parse(b"SQUIT", 2).is_ok());
        assert!(Command::parse(b"SQUIT", 0).is_err());
        assert!(Command::parse(b"KICK", 2).is_ok());
        assert!(Command::parse(b"KICK", 0).is_err());
        assert!(Command::parse(b"CHGHOST", 2).is_ok());
        assert!(Command::parse(b"CHGHOST", 0).is_err());
        assert!(Command::parse(b"FAIL", 3).is_ok());
        assert!(Command::parse(b"FAIL", 0).is_err());
        assert!(Command::parse(b"WARN", 3).is_ok());
        assert!(Command::parse(b"WARN", 0).is_err());
        assert!(Command::parse(b"NOTE", 3).is_ok());
        assert!(Command::parse(b"NOTE", 0).is_err());
        assert!(Command::parse(b"CPRIVMSG", 3).is_ok());
        assert!(Command::parse(b"CPRIVMSG", 0).is_err());
        assert!(Command::parse(b"CNOTICE", 3).is_ok());
        assert!(Command::parse(b"CNOTICE", 0).is_err());
        assert!(Command::parse(b"USER", 4).is_ok());
        assert!(Command::parse(b"USER", 0).is_err());
        assert!(Command::parse(b"WEBIRC", 4).is_ok());
        assert!(Command::parse(b"WEBIRC", 0).is_err());
        assert!(Command::parse(b"EXCELLENT", 0).is_err());
    }
    #[test]
    const fn uppercasing() {
        let input = b"INFO";
        let output = command_to_uppercase_bytes(input);
        assert!(output.len() == 12);
        assert!(is_identical(&output, &[b'I', b'N', b'F', b'O', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0']));
    }
}