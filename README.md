# const_irc_message_parser
A 0 dependency, no_std, const-only parser for the IRC message protocol.

## Motivation
I wanted to see how much of an IRC message parser can be written in a const context.
Every public and private function is const.
I was even able to make all the tests const functions even though it ends up being more verbose.

## Documentation
Documentation can be found here: https://docs.rs/const_irc_message_parser

## Acknowledgements
- IRC Message specifications: https://modern.ircdocs.horse
- IRC Message Tags specifications: https://ircv3.net/specs/extensions/message-tags.html
- IRC Formatting specifications: https://modern.ircdocs.horse/formatting
