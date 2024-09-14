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
                    b"006" | // RPL_MAP (unreal)
                    b"007" | // RPL_MAPEND/RPL_ENDMAP (unreal)
                    b"008" | // RPL_SNOMASK/RPL_SNOMASKIS (ircu)
                    b"009" | // RPL_STATMEMTOT (ircu)
                    b"014" | // RPL_YOURCOOKIE
                    b"015" | // RPL_MAP (ircu)
                    b"016" | // RPL_MAPMORE (ircu)
                    b"017" | // RPL_MAPEND/RPL_ENDMAP (ircu)
                    b"030" | // RPL_APASSWARN_SET (ircu)
                    b"031" | // RPL_APASSWARN_SECRET (ircu)
                    b"032" | // RPL_APASSWARN_CLEAR (ircu)
                    b"042" | // RPL_YOURID/RPL_YOURUUID (IRCnet/inspircd)
                    b"050" | // RPL_ATTEMPTINGJUNC (aircd)
                    b"051" | // RPL_ATTEMPTINGREROUTE (aircd)
                    b"210" | // RPL_TRACERECONNECT (RFC2812) (conflicts: RPL_STATS (aircd) RPL_STATSHELP (unreal))
                    b"217" | // RPL_STATSQLINE (RFC1459) (conflict: RPL_STATSPLINE (ircu))
                    b"220" | // RPL_STATSPLINE (hybrid) (conflicts: RPL_STATSBLINE (bahamut, unreal) RPL_STATSWLINE (nefarious))
                    b"222" | // RPL_MODLIST (conflicts: RPL_SQLINE_NICK (unreal) RPL_STATSBLINE (bahamut) RPL_STATSJLINE (ircu) RPL_CODEPAGE (rusnet-ircd))
                    b"223" | // RPL_STATSELINE (bahamut) (conflicts: RPL_STATSGLINE (unreal) RPL_CHARSET (rusnet-ircd))
                    b"224" | // RPL_STATSFLINE (hybrid, bahamut) (conflict: RPL_STATSTLINE (unreal))
                    b"225" | // RPL_STATSDLINE (hybrid) (conflicts: RPL_STATSCLONE (bahamut) RPL_STATSELINE (unreal) (depreciated: RPL_STATSZLINE (bahamut)))
                    b"226" | // RPL_STATSCOUNT (bahamut) (conflicts: RPL_STATSALINE (hybrid) RPL_STATSNLINE (unreal))
                    b"227" | // RPL_STATSGLINE (bahamut) (conflicts: RPL_STATSVLINE (unreal) RPL_STATSBLINE (rizon))
                    b"228" | // RPL_STATSQLINE (ircu) (conflicts: RPL_STATSBANVER (unreal) RPL_STATSCOUNT (oftc-hybrid))
                    b"229" | // RPL_STATSSPAMF (unreal)
                    b"230" | // RPL_STATSEXCEPTTKL (unreal)
                    b"231" | // RPL_SERVICEINFO (RFC1459) depreciated
                    b"232" | // RPL_ENDOFSERVICES (RFC1459) depreciated (conflict: RPL_RULES (unreal))
                    b"233" | // RPL_SERVICE (RFC1459) depreciated
                    b"236" | // RPL_STATSVERBOSE (ircu)
                    b"237" | // RPL_STATSENGINE (ircu)
                    b"238" | // RPL_STATSFLINE (ircu)
                    b"239" | // RPL_STATSIAUTH (IRCnet)
                    b"240" | // RPL_STATSVLINE (RFC2812) (conflict: RPL_STATSXLINE (austhex))
                    b"245" | // RPL_STATSSLINE (bahamut) (conflict: RPL_STATSTLINE (hybrid?))
                    b"246" | // RPL_STATSPING (RFC2812) (conflicts: RPL_STATSSERVICE (hybrid) RPL_STATSTLINE (ircu) RPL_STATSULINE (bahamut))
                    b"247" | // RPL_STATSBLINE (RFC2812) (conflicts: RPL_STATSXLINE (unreal) RPL_STATSGLINE (ircu))
                    b"248" | // RPL_STATSULINE (ircu) (conflict: RPL_STATSDEFINE (IRCnet))
                    b"249" | // RPL_STATSDEBUG (hybrid) (conflict: RPL_STATSULINE)
                    b"250" | // RPL_STATSDLINE (RFC2812) (conflict: RPL_STATSCONN (ircu))
                    b"264" | // RPL_USINGSSL (rusnet-ircd)
                    b"267" | // RPL_START_NETSTAT (aircd)
                    b"268" | // RPL_NETSTAT (aircd)
                    b"269" | // RPL_END_NETSTAT (aircd)
                    b"270" | // RPL_PRIVS (ircu) (conflict & depreciated: RPL_MAPUSERS (inspircd old))
                    b"273" | // RPL_NOTIFY (aircd)
                    b"274" | // RPL_ENDNOTIFY (aircd) (conflict: RPL_STATSDELTA (IRCnet))
                    b"275" | // RPL_STATSDLINE (ircu) (conflict: RPL_USINGSSL (bahamut))
                    b"277" | // RPL_VCHANLIST (hybrid) depreciated
                    b"278" | // RPL_VCHANHELP (hybrid) depreciated
                    b"280" | // RPL_GLIST (ircu)
                    b"283" | // RPL_ALIST (conflict: RPL_ENDOFJUPELIST (ircu))
                    b"284" | // RPL_ENDOFALIST (conflict: RPL_FEATURE (ircu))
                    b"285" | // RPL_GLIST_HASH (conflicts: RPL_CHANINFO_HANDLE (aircd) RPL_NEWHOSTIS (quakenet))
                    b"286" | // RPL_CHANINFO_USERS (aircd) (conflict: RPL_CHKHEAD (quakenet))
                    b"287" | // RPL_CHANINFO_CHOPS (aircd) (conflict: RPL_CHANUSER (quakenet))
                    b"288" | // RPL_CHANINFO_VOICES (aircd) (conflict: RPL_PATCHHEAD (quakenet))
                    b"289" | // RPL_CHANINFO_AWAY (aircd) (conflict: RPL_PATCHCON (quakenet))
                    b"290" | // RPL_CHANINFO_OPERS (aircd) (conflicts: RPL_DATASTR (quakenet) RPL_HELPHDR (unreal))
                    b"291" | // RPL_CHANINFO_BANNED (aircd) (conflicts: RPL_ENDOFCHECK (quakenet) RPL_HELPOP (unreal))
                    b"292" | // RPL_CHANINFO_BANS (aircd) (conflicts: RPL_HELPTLR (unreal) ERR_SEARCHNOMATCH (nefarious))
                    b"293" | // RPL_CHANINFO_INVITE (aircd) (conflict: RPL_HELPHLP (unreal))
                    b"294" | // RPL_CHANINFO_INVITES (aircd) (conflict: RPL_HELPFWD (unreal))
                    b"295" | // RPL_CHANINFO_KICK (aircd) (conflict: RPL_HELPIGN (unreal))
                    b"296" | // RPL_CHANINFO_KICKS (aircd)
                    b"299" | // RPL_END_CHANINFO (aircd)
                    b"300" | // RPL_NONE (RFC1459)
                    b"302" | // RPL_USERHOST (RFC1459)
                    b"303" | // RPL_ISON (RFC1459)
                    b"308" | // RPL_NOTIFYACTION (aircd) (conflicts: RPL_WHOISADMIN (bahamut) RPL_RULESSTART (unreal)/RPL_RULESTART (inspircd))
                    b"309" | // RPL_NICKTRACE (aircd) (conflicts: RPL_WHOISSADMIN (bahamut) RPL_ENDOFRULES (unreal)/RPL_RULESEND (inspircd) RPL_WHOISHELPER (austhex) RPL_WHOISSERVICE (oftc-hybrid))
                    b"310" | // RPL_WHOISSVCMSG (bahamut) (conflicts: RPL_WHOISHELPOP (unreal) RPL_WHOISSERVICE (austhex))
                    b"316" | // RPL_WHOISPRIVDEAF (nefarious) (conflict & depreciated: RPL_WHOISCHANOP (RFC1459))
                    b"326" | // RPL_NOCHANPASS
                    b"327" | // RPL_CHPASSUNKNOWN (conflict: RPL_WHOISHOST (rusnet-ircd))
                    b"328" | // RPL_CHANNEL_URL (bahamut)/RPL_CHANNELURL (charybdis)
                    b"334" | // RPL_LISTUSAGE (ircu) (conflicts: RPL_COMMANDSYNTAX (bahamut) RPL_LISTSYNTAX (unreal))
                    b"339" | // RPL_BADCHANPASS (conflict: RPL_WHOISMARKS (nefarious))
                    b"343" | // RPL_WHOISKILL (nefarious) (conflict: RPL_WHOISOPERNAME (snircd))
                    b"344" | // RPL_WHOISCOUNTRY (inspircd) (conflicts: RPL_REOPLIST (IRCnet) RPL_QUIETLIST (oftc-hybrid))
                    b"345" | // RPL_INVITED (gamesurge)/RPL_ISSUEDINVITE (ircu) (conflicts: RPL_ENDOFREOPLIST (IRCnet) RPL_ENDOFQUIETLIST (oftc-hybrid))
                    b"355" | // RPL_NAMREPLY_ (quakenet)/RPL_DELNAMREPLY (ircu)
                    b"357" | // RPL_MAP (austhex)
                    b"358" | // RPL_MAPMORE (austhex)
                    b"359" | // RPL_MAPEND/RPL_ENDMAP (austhex)
                    b"360" | // RPL_WHOWASREAL (charybdis) depreciated
                    b"361" | // RPL_KILLDONE (RFC1459)
                    b"362" | // RPL_CLOSING (RFC1459)
                    b"363" | // RPL_CLOSEEND (RFC1459)
                    b"373" | // RPL_INFOSTART (RFC1459) depreciated
                    b"377" | // RPL_KICKEXPIRED (aircd) (conflict & deprecated: RPL_SPAM (austhex))
                    b"380" | // RPL_BANLINKED (aircd) (conflict: RPL_YOURHELPER (austhex))
                    b"383" | // RPL_YOURESERVICE (RFC2812)
                    b"384" | // RPL_MYPORTIS (RFC1459) depreciated
                    b"385" | // RPL_NOTOPERANYMORE (austhex)
                    b"386" | // RPL_QLIST (unreal) (conflicts: RPL_IRCOPS (ultimate) RPL_IRCOPSHEADER (nefarious) depreciated: RPL_RSACHALLENGE (hybrid))
                    b"387" | // RPL_ENDOFQLIST (unreal) (conflicts: RPL_ENDOFIRCOPS (ultimate) RPL_IRCOPS (nefarious))
                    b"388" | // RPL_ALIST (unreal) (conflict: RPL_ENDOFIRCOPS (nefarious))
                    b"389" | // RPL_ENDOFALIST (unreal)
                    b"398" | // RPL_STATSSLINE (snirc)
                    b"399" | // RPL_USINGSLINE (snirc) (conflict: RPL_CLONES (inspircd))
                    b"419" | // ERR_LENGTHTRUNCATED (aircd)
                    b"425" | // ERR_NOOPERMOTD (unreal)
                    b"429" | // ERR_TOOMANYAWAY (bahamut)
                    b"430" | // ERR_EVENTNICKCHANGE (austhex)
                    b"434" | // ERR_SERVICENAMEINUSE (austhex) (conflicts: ERR_NORULES (unreal) ERR_NONICKWHILEBAN (oftc-hybrid))
                    b"435" | // ERR_SERVICECONFUSED (unreal) (conflict: ERR_BANONCHAN (bahamut)/ERR_BANNICKCHANGE (ratbox) depreciated: ERR_NICKONBAN (oftc-hybrid))
                    b"438" | // ERR_NICKTOOFAST (ircu)/ERR_NCHANGETOOFAST (unreal) (conflict: ERR_DEAD (IRCnet))
                    b"439" | // ERR_TARGETTOOFAST (ircu)/ERR_TARGETTOFAST/RPL_INVTOOFAST/RPL_MSGTOOFAST
                    b"440" | // ERR_SERVICESDOWN (bahamut)/ERR_REG_UNAVAILABLE (ergo)
                    b"447" | // ERR_NONICKCHANGE (unreal)/ERR_CANTCHANGENICK (inspircd)
                    b"449" | // ERR_NOTIMPLEMENTED (undernet)
                    b"452" | // ERR_IDCOLLISION
                    b"453" | // ERR_NICKLOST
                    b"455" | // ERR_HOSTILENAME (unreal)
                    b"459" | // ERR_NOHIDING (unreal)
                    b"460" | // ERR_NOTFORHALFOPS (unreal)
                    b"466" | // ERR_YOUWILLBEBANNED (RFC1459) depreciated
                    b"468" | // ERR_INVALIDUSERNAME (ircu) (conflicts: ERR_ONLYSERVERSCANCHANGE (bahamut) ERR_NOCODEPAGE (rusnet-ircd))
                    b"469" | // ERR_LINKSET (unreal)
                    b"470" | // ERR_LINKCHANNEL (unreal) (conflicts: ERR_KICKEDFROMCHAN (aircd) ERR_7BIT (rusnet-ircd))
                    b"479" | // ERR_BADCHANNAME (hybrid) (conflicts: ERR_LINKFAIL (unreal) ERR_NOCOLOR (rusnet-ircd))
                    b"480" | // ERR_NOULINE (austhex) (conflicts: ERR_CANNOTKNOCK (unreal) ERR_THROTTLE (ratbox)/ERR_NEEDTOWAIT (bahamut) ERR_NOWALLOP (rusnet-ircd) ERR_SSLONLYCHAN (oftc-hybrid))
                    b"486" | // ERR_NONONREG (unreal)/ERR_ACCOUNTONLY (conflicts: ERR_RLINED (rusnet-ircd) depreciated: ERR_HTMDISABLED (unreal))
                    b"487" | // ERR_CHANTOORECENT (IRCnet) (conflicts: ERR_MSGSERVICES (bahamut) ERR_NOTFORUSERS (unreal) ERR_NONONSSL (ChatIRCd))
                    b"488" | // ERR_TSLESSCHAN (IRCnet) (conflicts: ERR_HTMDISABLED (unreal) ERR_NOSSL (bahamut))
                    b"489" | // ERR_SECUREONLYCHAN (unreal)/ERR_SSLONLYCHAN (conflict: ERR_VOICENEEDED (undernet))
                    b"490" | // ERR_ALLMUSTSSL (inspIRCd) (conflicts: ERR_NOSWEAR (unreal) ERR_MAXMSGSENT (bahamut))
                    b"492" | // ERR_NOSERVICEHOST (RFC1459) depreciated (conflicts: ERR_NOCTCP (hybrid)/ERR_NOCTCPALLOWED (inspIRCd) ERR_CANNOTSENDTOUSER (charybdis))
                    b"493" | // ERR_NOSHAREDCHAN (bahamut) (conflict: ERR_NOFEATURE (ircu))
                    b"494" | // ERR_BADFEATVALUE (ircu) (conflict: ERR_OWNMODE (bahamut) ERR_INVITEREMOVED (inspIRCd))
                    b"495" | // ERR_BADLOGTYPE (ircu) (conflict & depreciated: ERR_DELAYREJOIN (inspIRCd))
                    b"496" | // ERR_BADLOGSYS (ircu)
                    b"497" | // ERR_BADLOGVALUE (ircu)
                    b"498" | // ERR_ISOPERLCHAN (ircu)
                    b"499" | // ERR_CHANOWNPRIVNEEDED (unreal)
                    b"500" | // ERR_TOOMANYJOINS (unreal) (conflicts: ERR_NOREHASHPARAM (rusnet-ircd) ERR_CANNOTSETMODDER (inspIRCd))
                    b"504" | // ERR_USERNOTONSERV (conflict: ERR_LAST_ERR_MSG (bahamut))
                    b"505" | // ERR_NOTINVITED (inspIRCd) (conflict & depreciated: ERR_LAST_ERR_MSG (oftc-hybrid))
                    b"512" | // ERR_TOOMANYWATCH (bahamut)/ERR_NOTIFYFULL (aircd) (conflicts: ERR_NOSUCHGLINE (ircu) depreciated: ERR_NEEDPONG (oftc-hybrid))
                    b"513" | // ERR_BADPING (ircu)/ERR_WRONGPONG (charybdis)/ERR_NEEDPONG (ultimate)
                    b"514" | // ERR_TOOMANYDCC (bahamut) (conflicts: ERR_NOSUCHJUPE (ircu) depreciated: ERR_INVALID_ERROR (ircu))
                    b"515" | // ERR_BADEXPIRE (ircu)
                    b"516" | // ERR_DONTCHEAT (ircu)
                    b"518" | // ERR_NOINVITE (unreal) (conflict: ERR_LONGMASK (ircu))
                    b"519" | // ERR_ADMONLY (unreal) (conflict: ERR_TOOMANYUSERS (ircu))
                    b"520" | // ERR_OPERONLY (unreal)/ERR_OPERONLYCHAN (hybrid)/ERR_CANTJOINOPERSONLY (inspIRCd) (conflicts: ERR_MASKTOOWIDE (ircu) depreciated: ERR_WHOTRUNC (austhex))
                    b"521" | // ERR_LISTSYNTAX (bahamut) (conflict: ERR_NOSUCHGLINE (nefarious))
                    b"522" | // ERR_WHOSYNTAX (bahamut)
                    b"524" | // ERR_QUARANTINED (ircu) (conflicts: ERR_OPERSVERIFY (unreal) ERR_HELPNOTFOUND (hybrid))
                    b"525" | // ERR_INVALIDKEY (ircu) (conflict & depreciated: ERR_REMOTEPFX)
                    b"530" | // ERR_BADHOSTMASK (snircd)
                    b"550" | // ERR_BADHOSTMASK (quakenet)
                    b"551" | // ERR_HOSTUNAVAIL (quakenet)
                    b"552" | // ERR_USINGSLINE (quakenet)
                    b"553" | // ERR_STATSSLINE (quakenet)
                    b"560" | // ERR_NOTLOWEROPLEVEL (ircu)
                    b"561" | // ERR_NOTMANAGER (ircu)
                    b"562" | // ERR_CHANSECURED (ircu)
                    b"563" | // ERR_UPASSSET (ircu)
                    b"564" | // ERR_UPASSNOTSET (ircu)
                    b"565" | // ERR_NOMANAGER_LONG (ircu) depreciated
                    b"566" | // ERR_NOMANAGER (ircu)
                    b"567" | // ERR_UPASS_SAME_APASS (ircu)
                    b"568" | // ERR_LASTERROR (ircu) (conflict: RPL_NOOMOTD (nefarious))
                    b"573" | // ERR_CANNOTSENDRP (ergo)
                    b"597" | // RPL_REAWAY (unreal)
                    b"603" | // RPL_WATCHSTAT (unreal)
                    b"606" | // RPL_WATCHLIST (unreal)
                    b"607" | // RPL_ENDOFWATCHLIST (unreal)
                    b"608" | // RPL_WATCHCLEAR (ultimate)/RPL_CLEARWATCH (unreal)
                    b"610" | // RPL_MAPMORE (unreal) (conflict: RPL_ISOPER (ultimate))
                    b"611" | // RPL_ISLOCOP (ultimate)
                    b"612" | // RPL_ISNOTOPER (ultimate)
                    b"613" | // RPL_ENDOFISOPER (ultimate)
                    b"615" | // RPL_MAPMORE (ptlink) (conflict: RPL_WHOISMODES (ultimate))
                    b"616" | // RPL_WHOISHOST (ultimate)
                    b"617" | // RPL_WHOISSSLFP (nefarious) (conflicts: RPL_DCCSTATUS (bahamut) RPL_WHOISBOT (ultimate))
                    b"618" | // RPL_DCCLIST (bahamut)
                    b"619" | // RPL_ENDOFDCCLIST (bahamut) (conflict: RPL_WHOWASHOST (ultimate))
                    b"620" | // RPL_DCCINFO (bahamut) (conflict: RPL_RULESSTART (ultimate))
                    b"621" | // RPL_RULES (ultimate)
                    b"622" | // RPL_ENDOFRULES (ultimate)
                    b"623" | // RPL_MAPMORE (ultimate)
                    b"624" | // RPL_OMOTDSTART (ultimate)
                    b"625" | // RPL_OMOTD (ultimate)
                    b"626" | // RPL_ENDOFOMOTD (ultimate)
                    b"630" | // RPL_SETTINGS (ultimate)
                    b"631" | // RPL_ENDOFSETTINGS (ultimate)
                    b"640" | // RPL_DUMPING (unreal) depreciated
                    b"641" | // RPL_DUMPRPL (unreal) depreciated
                    b"642" | // RPL_EODUMP (unreal) depreciated
                    b"687" | // RPL_YOURLANGUAGESARE (ergo)
                    b"727" | // RPL_TESTMASKGECOS (ratbox) (conflict: RPL_ISCAPTURED (oftc-hybrid))
                    b"728" | // RPL_QUIETLIST (charybdis) (conflict: RPL_ISUNCAPTURED (ofc-hybrid))
                    b"744" | // ERR_TOPICLOCK (inspIRCd)
                    b"762" | // RPL_METADATAEND (IRCv3)
                    b"771" | // RPL_XINFO (ithildin)
                    b"773" | // RPL_XINFOSTART (ithildin)
                    b"774" | // RPL_XINFOEND (ithildin)
                    b"802" | // RPL_CHECK (inspIRCd)
                    b"975" | // RPL_LOADEDMODULE (inspIRCd) (conflict: ERR_LASTERROR (nefarious))
                    b"981" | // ERR_TOOMANYLANGUAGES (ergo)
                    b"982" | // ERR_NOLANGUAGE (ergo)
                    b"999"   // ERR_NUMERIC_ERR (bahamut)/ERR_NUMERICERR/ERR_LAST_ERR_MSG (depreciated: RPL_ENDOFDCCALLOWHELP (inspIRCd))
                    => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));},
                    b"001" | // RPL_WELCOME
                    b"002" | // RPL_YOURHOST/RPL_YOURHOSTIS
                    b"003" | // RPL_CREATED/RPL_SERVERCREATED
                    b"005" | // RPL_ISUPPORT/RPL_PROTOCTL (depreciated: RPL_BOUNCE moved to 010)
                    b"018" | // RPL_MAPUSERS (inspircd)
                    b"020" | // RPL_HELLO (rusnet-ircd)
                    b"105" | // RPL_REMOTEISUPPORT (unreal)
                    b"203" | // RPL_TRACEUNKNOWN (RFC1459)
                    b"221" | // RPL_UMODEIS (RFC1459)
                    b"242" | // RPL_STATSUPTIME (RFC1459)
                    b"251" | // RPL_LUSERCLIENT (RFC1459)
                    b"255" | // RPL_LUSERME (RFC1459)
                    b"256" | // RPL_ADMINME (RFC1459)
                    b"257" | // RPL_ADMINLOC1 (RFC1459)
                    b"258" | // RPL_ADMINLOC2 (RFC1459)
                    b"259" | // RPL_ADMINEMAIL (RFC1459)
                    b"265" | // RPL_LOCALUSERS/RPL_CURRENT_LOCAL (bahamut)
                    b"266" | // RPL_GLOBALUSERS/RPL_CURRENT_GLOBAL (bahamut)
                    b"271" | // RPL_SILELIST (ircu)
                    b"272" | // RPL_ENDOFSILELIST (ircu)
                    b"281" | // RPL_ACCEPTLIST (conflict: RPL_ENDOFGLIST (ircu))
                    b"282" | // RPL_ENDOFACCEPT (conflict: RPL_JUPELIST (ircu))
                    b"304" | // RPL_TEXT (unreal)
                    b"305" | // RPL_UNAWAY (RFC1459)
                    b"306" | // RPL_NOWAWAY (RFC1459)
                    b"321" | // RPL_LISTSTART (RFC1459) depreciated
                    b"323" | // RPL_LISTEND (RFC1459)
                    b"336" | // RPL_INVITELIST (hybrid not 346) (conflict: RPL_WHOISBOT (nefarious))
                    b"337" | // RPL_ENDOFINVITELIST (hybrid not 347) (conflict: RPL_WHOISTEXT (older hybrid?))
                    b"340" | // RPL_USERIP (ircu)
                    b"354" | // RPL_WHOSPCRPL (ircu)/RPL_RWHOREPLY (bahamut)
                    b"371" | // RPL_INFO (RFC1459)
                    b"372" | // RPL_MOTD (RFC1459)
                    b"374" | // RPL_ENDOFINFO (RFC1459)
                    b"375" | // RPL_MOTDSTART (RFC1459)
                    b"376" | // RPL_ENDOFMOTD (RFC1459)
                    b"381" | // RPL_YOUREOPER (RFC1459)/RPL_YOUAREOPER (inspircd)
                    b"392" | // RPL_USERSSTART (RFC1459)
                    b"393" | // RPL_USERS (RFC1459)
                    b"394" | // RPL_ENDOFUSERS (RFC1459)
                    b"395" | // RPL_NOUSERS (RFC1459)
                    b"406" | // ERR_WASNOSUCHNICK (RFC1459)
                    b"409" | // ERR_NOORIGIN (RFC1459)
                    b"410" | // ERR_INVALIDCAPCMD (undernet?)/ERR_INVALIDCAPSUBCOMMAND (inspircd)/ERR_UNKNOWNCAPCMD (ircu)
                    b"411" | // ERR_NORECIPIENT (RFC1459)
                    b"412" | // ERR_NOTEXTTOSEND (RFC1459)
                    b"417" | // ERR_INPUTTOOLONG (ircu)
                    b"420" | // ERR_AMBIGUOUSCOMMAND (inspircd)
                    b"422" | // ERR_NOMOTD (RFC1459)
                    b"424" | // ERR_FILEERROR (RFC1459)
                    b"431" | // ERR_NONICKNAMEGIVEN (RFC1459)
                    b"436" | // ERR_ERR_NICKCOLLISION (RFC1459)
                    b"445" | // ERR_SUMMONDISABLED (RFC1459)
                    b"446" | // ERR_USERSDISABLED (RFC1459)
                    b"448" | // ERR_FORBIDDENCHANNEL (unreal)
                    b"451" | // ERR_NOTREGISTERED (RFC1459)
                    b"456" | // ERR_ACCEPTFULL
                    b"462" | // ERR_ALREADYREGISTERED (RFC1459)/ERR_ALREADYREGISTRED
                    b"463" | // ERR_NOPERMFORHOST (RFC1459)
                    b"464" | // ERR_PASSWDMISMATCH (RFC1459)
                    b"465" | // ERR_YOUREBANNEDCREEP (RFC1459)
                    b"481" | // ERR_NOPRIVILEGES (RFC1459)
                    b"483" | // ERR_CANTKILLSERVER (RFC1459)/ERR_KILLDENY (unreal)
                    b"484" | // ERR_RESTRICTED (RFC2812) (conflicts: ERR_ISCHANSERVICE (undernet) ERR_DESYNC (bahamut) ERR_ATTACKDENY (unreal))
                    b"485" | // ERR_UNIQOPRIVSNEEDED (RFC2812) (conflicts: ERR_KILLDENY (unreal) ERR_CANTKICKADMIN (PTlink) ERR_ISREALSERVICE (quakenet) ERR_CHANBANREASON (hybrid) depreciated: ERR_BANNEDNICK (ratbox))
                    b"491" | // ERR_NOOPERHOST (RFC1459)
                    b"501" | // ERR_UMODEUNKOWNFLAG (RFC1459) (conflict: ERR_UNKNOWNSNOMASK (inspIRCd))
                    b"502" | // ERR_USERSDONTMATCH (RFC1459)
                    b"503" | // ERR_GHOSTEDCLIENT (hybrid) depreciated (conflict & depreciated: ERR_VWORLDWARN (austhex))
                    b"511" | // ERR_SILELISTFULL (ircu)
                    b"523" | // ERR_WHOLIMEXCEED (bahamut)
                    b"526" | // ERR_PFXUNROUTABLE depreciated
                    b"653" | // RPL_UNINVITED (inspIRCd)
                    b"670" | // RPL_STARTTLS (IRCv3)
                    b"672" | // RPL_UNKNOWNMODES (ithildin) (conflict: RPL_WHOISREALIP (rizon)/RPL_WHOISCGI (plexus))
                    b"673" | // RPL_CANNOTSETMODES (ithildin)
                    b"674" | // RPL_WHOISYOURID (ChatIRCd)
                    b"690" | // ERR_REDIRECT (inspIRCd)
                    b"691" | // ERR_STARTTLS (IRCv3)
                    b"700" | // RPL_COMMANDS (inspIRCd)
                    b"701" | // RPL_COMMANDSEND (inspIRCd)
                    b"702" | // RPL_MODLIST (ratbox) (conflict & depreciated: RPL_COMMANDS (inspIRCd))
                    b"703" | // RPL_ENDOFMODLIST (ratbox) (conflict & depreciated: RPL_COMMANDSEND (inspIRCd))
                    b"715" | // ERR_KNOCKDISABLED (ratbox) (conflicts: ERR_TOOMANYINVITE (hybrid) RPL_INVITETHROTTLE (rizon))
                    b"716" | // RPL_TARGUMODEG (ratbox)/ERR_TARGUMODEG
                    b"717" | // RPL_TARGNOTIFY (ratbox)
                    b"720" | // RPL_OMOTDSTART (ratbox)
                    b"721" | // RPL_OMOTD (ratbox)
                    b"722" | // RPL_ENDOFOMOTD (ratbox)
                    b"730" | // RPL_MONONLINE (ratbox)
                    b"731" | // RPL_MONOFFLINE (ratbox)
                    b"732" | // RPL_MONLIST (ratbox)
                    b"733" | // RPL_ENDOFMONLIST (ratbox)
                    b"740" | // RPL_RSACHALLENGE2 (ratbox)
                    b"741" | // RPL_ENDOFRSACHALLENGE2 (ratbox)
                    b"750" | // RPL_SCANMATCHED (ratbox)
                    b"759" | // RPL_ETRACEEND (irc2.11)
                    b"764" | // ERR_METADATALIMIT (IRCv3)
                    b"765" | // ERR_TARGETINVALID (IRCv3)
                    b"767" | // ERR_KEYINVALID (IRCv3)
                    b"902" | // ERR_NICKLOCKED (IRCv3)
                    b"903" | // RPL_SASLSUCCESS (IRCv3)
                    b"904" | // ERR_SASLFAIL (IRCv3)
                    b"905" | // ERR_SASLTOOLONG (IRCv3)
                    b"906" | // ERR_SASLABORTED (IRCv3)
                    b"907" | // ERR_SASLALREADY (IRCv3)
                    b"944" | // RPL_IDLETIMESET (inspIRCd)
                    b"948" | // ERR_INVALIDIDLETIME (inspIRCd)
                    b"961" | // RPL_PROPLIST (inspIRCd)
                    b"990" | // RPL_DCCALLOWSTART (inspIRCd)
                    b"992" | // RPL_DCCALLOWEND (inspIRCd)
                    b"998"   // ERR_UNKNOWNDCCALLOWCMD (inspIRCd) (depreciated: RPL_DCCALLOWHELP (inspIRCd))
                    => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));},
                    b"043" | // RPL_SAVENICK (IRCnet)
                    b"200" | // RPL_TRACELINK (RFC1459)
                    b"201" | // RPL_TRACECONNECTING (RFC1459)
                    b"202" | // RPL_TRACEHANDSHAKE (RFC1459)
                    b"204" | // RPL_TRACEOPERATOR (RFC1459)
                    b"205" | // RPL_TRACEUSER (RFC1459)
                    b"208" | // RPL_TRACENEWTYPE (RFC1459)
                    b"209" | // RPL_TRACECLASS (RFC2812)
                    b"212" | // RPL_STATSCOMMANDS (RFC1459)
                    b"219" | // RPL_ENDOFSTATS (RFC1459)
                    b"252" | // RPL_LUSEROP (RFC1459)
                    b"253" | // RPL_LUSERUNKNOWN (RFC1459)
                    b"254" | // RPL_LUSERCHANNELS (RFC1459)
                    b"261" | // RPL_TRACELOG (RFC1459)
                    b"263" | // RPL_TRYAGAIN/RPL_LOAD2HI/RPL_LOAD_THROTTLED (RFC2812)
                    b"276" | // RPL_WHOISCERTFP (oftc-hybrid) (conflicts: RPL_STATSRLINE (ircu) depreciated: RPL_VCHANEXIST (hybrid))
                    b"301" | // RPL_AWAY (RFC1459)
                    b"307" | // RPL_USERIP (conflicts: RPL_WHOISREGNICK (bahamut) RPL_SUPERHOST (austhex))
                    b"313" | // RPL_WHOISOPERATOR (RFC1459)
                    b"315" | // RPL_ENDOFWHO (RFC1459)
                    b"318" | // RPL_ENDOFWHOIS (RFC1459)
                    b"319" | // RPL_WHOISCHANNELS (RFC1459)
                    b"320" | // RPL_WHOISSPECIAL (unreal) (conflicts: RPL_WHOIS_HIDDEN (anothernet) RPL_WHOISVIRT (austhex))
                    b"324" | // RPL_CHANNELMODEIS (RFC1459)
                    b"325" | // RPL_UNIQOPIS (RFC2812) (conflicts: RPL_CHANNELPASSIS RPL_WHOISWEBIRC (nefarious) depreciated: RPL_CHANNELMLOCKIS/RPL_CHANNELMLOCK (sorircd))
                    b"329" | // RPL_CREATIONTIME (bahamut)/RPL_CHANNELCREATED (inspircd)
                    b"331" | // RPL_NOTOPIC (RFC1459)/RPL_NOTOPICSET (inspircd)
                    b"332" | // RPL_TOPIC (RFC1459)/RPL_TOPICSET (inspircd)
                    b"333" | // RPL_TOPICWHOTIME (ircu)/RPL_TOPICTIME (inspircd)
                    b"335" | // RPL_WHOISBOT (unreal) (conflicts: RPL_WHOISTEXT (hybrid) RPL_WHOISACCOUNTONLY (nefarious))
                    b"338" | // RPL_WHOISACTUALLY (ircu) (conflict: RPL_CHANPASSOK)
                    b"341" | // RPL_INVITING (RFC1459)
                    b"342" | // RPL_SUMMONING (RFC1459) depreciated
                    b"346" | // RPL_INVITELIST (RFC2812 not 336)/RPL_INVEXLIST (hybrid)
                    b"347" | // RPL_ENDOFINVITELIST (RFC2812 not 337)/RPL_ENDOFINVEXLIST (hybrid)
                    b"348" | // RPL_EXCEPTLIST (RFC2812)/RPL_EXLIST (unreal)/RPL_EXEMPTLIST (bahamut)
                    b"349" | // RPL_ENDOFEXCEPTLIST (RFC2812)/RPL_ENDOFEXLIST (unreal)/RPL_ENDOFEXEMPTLIST (bahamut)
                    b"365" | // RPL_ENDOFLINKS (RFC1459)
                    b"366" | // RPL_ENDOFNAMES (RFC1459)
                    b"367" | // RPL_BANLIST (RFC1459)
                    b"368" | // RPL_ENDOFBANLIST (RFC1459)
                    b"369" | // RPL_ENDOFWHOWAS (RFC1459)
                    b"378" | // RPL_BANEXPIRED (aircd) (conflicts: RPL_WHOISHOST (unreal) depreciated: RPL_MOTD (austhex))
                    b"379" | // RPL_KICKLINKED (aircd) (conflicts: RPL_WHOISMODES (unreal) depreciated: RPL_WHOWASIP (inspircd))
                    b"382" | // RPL_REHASHING (RFC1459)
                    b"391" | // RPL_TIME (RFC1459)
                    b"396" | // RPL_HOSTHIDDEN (unreal)/RPL_VISIBLEHOST (hybrid)/RPL_YOURDISPLAYEDHOST (inspircd)
                    b"400" | // ERR_UNKNOWNERROR (ergo) (conflict & depreciated: ERR_FIRSTERROR (ircu))
                    b"401" | // ERR_NOSUCHNICK (RFC1459)
                    b"402" | // ERR_NOSUCHSERVER (RFC1459)
                    b"403" | // ERR_NOSUCHCHANNEL (RFC1459)
                    b"404" | // ERR_CANNOTSENDTOCHAN (RFC1459)
                    b"405" | // ERR_TOOMANYCHANNELS (RFC1459)
                    b"407" | // ERR_TOOMANYTARGETS (RFC1459)
                    b"408" | // ERR_NOSUCHSERVICE (RFC2812) (conflicts: ERR_NOCOLORSONCHAN (bahamut) ERR_NOCTRLSONCHAN (hybrid) ERR_SEARCHNOMATCH (snircd))
                    b"413" | // ERR_NOTPLEVEL (RFC1459)
                    b"414" | // ERR_WILDTOPLEVEL (RFC1459)
                    b"415" | // ERR_BADMASK (RFC2812) (conflict: ERR_MSGNEEDREGGEDNICK (solanum)/ERR_CANTSENDREGONLY (oftc-hybrid))
                    b"416" | // ERR_TOOMANYMATCHES (IRCnet)/ERR_QUERYTOOLONG (ircu)
                    b"421" | // ERR_UNKNOWNCOMMAND (RFC1459)
                    b"423" | // ERR_NOADMININFO (RFC1459)
                    b"432" | // ERR_ERRONEUSNICKNAME (RFC1459)
                    b"433" | // ERR_NICKNAMEINUSE (RFC1459)
                    b"437" | // ERR_UNAVAILRESOURCE (RFC2812) (conflict: ERR_BANNICKCHANGE (ircu))
                    b"442" | // ERR_NOTONCHANNEL (RFC1459)
                    b"444" | // ERR_NOLOGIN (RFC1459)
                    b"457" | // ERR_ACCEPTEXIST
                    b"458" | // ERR_ACCEPTNOT
                    b"461" | // ERR_NEEDMOREPARAMS (RFC1459)
                    b"467" | // ERR_KEYSET (RFC1459)
                    b"471" | // ERR_CHANNELISFULL (RFC1459)
                    b"472" | // ERR_UNKNOWNMODE (RFC1459)
                    b"473" | // ERR_INVITEONLYCHAN (RFC1459)
                    b"474" | // ERR_BANNEDFROMCHAN (RFC1459)
                    b"475" | // ERR_BADCHANNELKEY (RFC1459)
                    b"476" | // ERR_BADCHANMASK (RFC2812) (conflict: ERR_OPERONLYCHAN (plexus))
                    b"477" | // ERR_NOCHANMODES (RFC2812)/ERR_MODELESS (conflict: ERR_NEEDREGGEDNICK (bahamut)/ERR_REGONLYCHAN (oftc-hybrid))
                    b"478" | // ERR_BANLISTFULL (RFC2812)
                    b"482" | // ERR_CHANOPRIVSNEEDED (RFC1459)
                    b"517" | // ERR_DISABLED (ircu)
                    b"531" | // ERR_CANTSENDTOUSER (inspIRCd)/ERR_HOSTUNAVAIL (snircd)
                    b"650" | // RPL_SYNTAX (inspIRCd)
                    b"651" | // RPL_CHANNELMSG (inspIRCd)
                    b"652" | // RPL_WHOWASIP (inspIRCd)
                    b"659" | // RPL_SPAMCMDFWD (unreal)
                    b"671" | // RPL_WHOISSECURE (unreal)/RPL_WOISSSL (nefarious)
                    b"704" | // RPL_HELPSTART (ratbox)
                    b"705" | // RPL_HELPTXT (ratbox)
                    b"706" | // RPL_ENDOFHELP (ratbox)
                    b"707" | // ERR_TARGCHANGE (ratbox)
                    b"710" | // RPL_KNOCK (ratbox)
                    b"711" | // RPL_KNOCKDLVR (ratbox)
                    b"712" | // ERR_TOOMANYKNOCK (ratbox)
                    b"713" | // ERR_CHANOPEN (ratbox)
                    b"714" | // ERR_KNOCKONCHAN (ratbox)
                    b"718" | // RPL_UMODEGMSG (ratbox)
                    b"723" | // ERR_NOPRIVS (ratbox)
                    b"726" | // RPL_NOTESTLINE (ratbox)
                    b"761" | // RPL_KEYVALUE (IRCv3)
                    b"766" | // ERR_NOMATCHINGKEY (IRCv3)
                    b"768" | // ERR_KEYNOTSET (IRCv3)
                    b"769" | // ERR_KEYNOPERMISSION (IRCv3)
                    b"801" | // RPL_STATSCOUNTRY (inspIRCd)
                    b"901" | // RPL_LOGGEDOUT (IRCv3)
                    b"908" | // RPL_SASLMECHS (IRCv3)
                    b"910" | // RPL_ACCESSLIST (inspIRCd)
                    b"911" | // RPL_ENDOFACCESSLIST (inspIRCd)
                    b"926" | // ERR_BADCHANNEL (inspIRCd)
                    b"937" | // ERR_ALREADYCHANFILTERED (inspIRCd) depreciated
                    b"938" | // ERR_NOSUCHCHANFILTER (inspIRCd) depreciated
                    b"939" | // ERR_CHANFILTERFULL (inspIRCd) depreciated
                    b"940" | // RPL_ENDOFSPAMFILTER (inspIRCd)
                    b"942" | // ERR_INVALIDWATCHNICK (inspIRCd)
                    b"945" | // RPL_NICKLOCKOFF (inspIRCd)
                    b"946" | // ERR_NICKNOTLOCKED (inspIRCd)
                    b"947" | // RPL_NICKLOCKON (inspIRCd)
                    b"950" | // RPL_UNSILENCED (inspIRCd)
                    b"951" | // RPL_SILENCED (inspIRCd)
                    b"952" | // ERR_SILENCE (inspIRCd)
                    b"953" | // RPL_ENDOFEXEMPTIONLIST (inspIRCd)
                    b"960" | // RPL_ENDOFPROPLIST (inspIRCd)
                    b"972" | // ERR_CANNOTDOCOMMAND (unreal) (conflict: ERR_CANTUNLOADMODULE (inspIRCd))
                    b"973" | // RPL_UNLOADEDMODULE (inspIRCd)
                    b"974" | // RPL_CANNOTCHANGECHANMODE (unreal) (conflict: ERR_CANTLOADMODULE (inspIRCd))
                    b"988" | // RPL_SERVLOCKON (inspIRCd)
                    b"989" | // RPL_SERVLOCKOFF (inspIRCd)
                    b"991" | // RPL_DCCALLOWLIST (inspIRCd)
                    b"993" | // RPL_DCCALLOWTIMED (inspIRCd)
                    b"994" | // RPL_DCCALLOWPERMANENT (inspIRCd)
                    b"995" | // RPL_DCCALLOWREMOVED (inspIRCd)
                    b"996" | // ERR_DCCALLOWINVALID (inspIRCd)
                    b"997"   // RPL_DCCALLOWEXPIRED (inspIRCd)
                    => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));},
                    b"010" | // RPL_BOUNCE/RPL_REDIR (depreciated & conflict: RPL_STATMEM (ircu))
                    b"235" | // RPL_SERVLISTEND (RFC2812)
                    b"262" | // RPL_TRACEEND/RPL_ENDOFTRACE (RFC2812) (conflict: RPL_TRACEPING)
                    b"312" | // RPL_WHOISSERVER (RFC1459)
                    b"322" | // RPL_LIST (RFC1459)
                    b"330" | // RPL_WHOISACCOUNT (ircu)/RPL_WHOISLOGGEDIN (conflict: RPL_WHOWAS_TIME)
                    b"350" | // RPL_WHOISGATEWAY (inspircd)
                    b"351" | // RPL_VERSION (RFC1459)
                    b"353" | // RPL_NAMREPLY (RFC1459)
                    b"364" | // RPL_LINKS (RFC1459)
                    b"441" | // ERR_USERNOTINCHANNEL (RFC1459)
                    b"443" | // ERR_USERONCHANNEL (RFC1459)
                    b"569" | // RPL_WHOISASN (inspIRCd)
                    b"729" | // RPL_ENDOFQUIETLIST (charybdis)
                    b"734" | // ERR_MONLISTFULL (ratbox)
                    b"742" | // ERR_MLOCKRESTRICTED (charybdis)
                    b"743" | // ERR_INVALIDBAN (charybdis)
                    b"760" | // RPL_WHOISKEYVALUE (IRCv3)
                    b"803" | // RPL_OTHERUMODEIS (inspIRCd)
                    b"804" | // RPL_OTHERSNOMASKIS (inspIRCd)
                    b"900" | // RPL_LOGGEDIN (IRCv3)
                    b"936"   // ERR_WORDFILTERED (inspIRCd) depreciated
                    => if params_amount < 4 {return Err(CommandError::MinimumArgsRequired(4, cmd));},
                    b"004" | // RPL_MYINFO/RPL_SERVERVERSION
                    b"206" | // RPL_TRACESERVER (RFC1459)
                    b"207" | // RPL_TRACESERVICE (RFC2812) (conflict: RPL_TRACECAPTURED (oftc-hybrid))
                    b"244" | // RPL_STATSHLINE (RFC1459)
                    b"317" | // RPL_WHOISIDLE (RFC1459)
                    b"598" | // RPL_GONEAWAY (unreal)
                    b"599" | // RPL_NOTAWAY (unreal)
                    b"600" | // RPL_LOGON (unreal)
                    b"601" | // RPL_LOGOFF (unreal)
                    b"602" | // RPL_WATCHOFF (unreal)
                    b"604" | // RPL_NOWON (unreal)
                    b"605" | // RPL_NOWOFF (unreal)
                    b"609" | // RPL_NOWISAWAY (unreal)
                    b"696" | // ERR_INVALIDMODEPARAM (inspIRCd)
                    b"697" | // ERR_LISTMODEALREADYSET (inspIRCd)
                    b"698" | // ERR_LISTMODENOTSET (inspIRCd)
                    b"724" | // RPL_TESTMASK (ratbox)
                    b"725" | // RPL_TESTLINE (ratbox)
                    b"941" | // RPL_SPAMFILTER (inspIRCd)
                    b"954"   // RPL_EXEMPTIONLIST (inspIRCd)
                    => if params_amount < 5 {return Err(CommandError::MinimumArgsRequired(5, cmd));},
                    b"218" | // RPL_STATSYLINE (RFC1459)
                    b"241" | // RPL_STATSLLINE (RFC1459)
                    b"243" | // RPL_STATSOLINE (RFC1459)
                    b"311" | // RPL_WHOISUSER (RFC1459)
                    b"314"   // RPL_WHOWASUSER (RFC1459)
                    => if params_amount < 6 {return Err(CommandError::MinimumArgsRequired(6, cmd));},
                    b"213" | // RPL_STATSCLINE (RFC1459)
                    b"214" | // RPL_STATSNLINE (RFC1459)/RPL_STATSOLDNLINE (ircu, unreal)
                    b"215" | // RPL_STATSILINE (RFC1459)
                    b"216" | // RPL_STATSKLINE (RFC1459)
                    b"234" | // RPL_SERVLIST (RFC2812)
                    b"709" | // RPL_ETRACE (ratbox)
                    b"751"   // RPL_SCANUMODES (ratbox)
                    => if params_amount < 7 {return Err(CommandError::MinimumArgsRequired(7, cmd));},
                    b"211" | // RPL_STATSLINKINFO (RFC1459)
                    b"352" | // RPL_WHOREPLY (RFC1459)
                    b"708"   // RPL_ETRACEFULL (ratbox)
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
                b"SERVLIST0000" => return Ok(Self::Named("SERVLIST")),
                b"USERS0000000" => return Ok(Self::Named("USERS")),
                b"MAP000000000" => return Ok(Self::Named("MAP")),
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
                b"ISON00000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("ISON"));},
                b"KNOCK0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("KNOCK"));},
                b"SUMMON000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("SUMMON"));},
                b"USERIP000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("USERIP"));},
                b"WATCH0000000" => if params_amount < 1 {return Err(CommandError::MinimumArgsRequired(1, cmd));}
                                   else {return Ok(Self::Named("WATCH"));},
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
                b"ENCAP0000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("ENCAP"));},
                b"SQUERY000000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("SQUERY"));},
                b"METADATA0000" => if params_amount < 2 {return Err(CommandError::MinimumArgsRequired(2, cmd));}
                                   else {return Ok(Self::Named("METADATA"));},
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
                b"SERVER000000" => if params_amount < 3 {return Err(CommandError::MinimumArgsRequired(3, cmd));}
                                   else {return Ok(Self::Named("SERVER"));},
                b"USER00000000" => if params_amount < 4 {return Err(CommandError::MinimumArgsRequired(4, cmd));}
                                   else {return Ok(Self::Named("USER"));},
                b"WEBIRC000000" => if params_amount < 4 {return Err(CommandError::MinimumArgsRequired(4, cmd));}
                                   else {return Ok(Self::Named("WEBIRC"));},
                b"SERVICE00000" => if params_amount < 6 {return Err(CommandError::MinimumArgsRequired(6, cmd));}
                                   else {return Ok(Self::Named("SERVICE"));},
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
    use crate::is_identical;
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
        assert!(Command::parse(b"SERVLIST", 0).is_ok());
        assert!(Command::parse(b"USERS", 0).is_ok());
        assert!(Command::parse(b"MAP", 0).is_ok());
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
        assert!(Command::parse(b"ISON", 1).is_ok());
        assert!(Command::parse(b"ISON", 0).is_err());
        assert!(Command::parse(b"KNOCK", 1).is_ok());
        assert!(Command::parse(b"KNOCK", 0).is_err());
        assert!(Command::parse(b"SUMMON", 1).is_ok());
        assert!(Command::parse(b"SUMMON", 0).is_err());
        assert!(Command::parse(b"USERIP", 1).is_ok());
        assert!(Command::parse(b"USERIP", 0).is_err());
        assert!(Command::parse(b"WATCH", 1).is_ok());
        assert!(Command::parse(b"WATCH", 0).is_err());
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
        assert!(Command::parse(b"ENCAP", 2).is_ok());
        assert!(Command::parse(b"ENCAP", 0).is_err());
        assert!(Command::parse(b"SQUERY", 2).is_ok());
        assert!(Command::parse(b"SQUERY", 0).is_err());
        assert!(Command::parse(b"METADATA", 2).is_ok());
        assert!(Command::parse(b"METADATA", 0).is_err());
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
        assert!(Command::parse(b"SERVER", 3).is_ok());
        assert!(Command::parse(b"SERVER", 0).is_err());
        assert!(Command::parse(b"USER", 4).is_ok());
        assert!(Command::parse(b"USER", 0).is_err());
        assert!(Command::parse(b"WEBIRC", 4).is_ok());
        assert!(Command::parse(b"WEBIRC", 0).is_err());
        assert!(Command::parse(b"SERVICE", 6).is_ok());
        assert!(Command::parse(b"SERVICE", 0).is_err());
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
