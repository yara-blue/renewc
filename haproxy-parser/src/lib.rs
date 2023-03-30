use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum Error {}

pub struct Config {
    global: (),
    defaults: (),
    frontends: Vec<()>,
    backends: Vec<()>,
}

#[derive(Debug)]
enum ConfigEntry<'input> {
    BlankLine,
    Comment(&'input str),
    Global {
        comment: Option<&'input str>,
        lines: Vec<Line<'input>>,
    },
    Default {
        comment: Option<&'input str>,
        proxy: Option<&'input str>,
        lines: Vec<Line<'input>>,
    },
    Frontend {
        comment: Option<&'input str>,
        proxy: &'input str,
        lines: Vec<Line<'input>>,
    },
    Backend {
        comment: Option<&'input str>,
        proxy: &'input str,
        lines: Vec<Line<'input>>,
    },
    UserList {
        comment: Option<&'input str>,
        proxy: &'input str,
        lines: Vec<Line<'input>>,
    },
    Listen {
        comment: Option<&'input str>,
        proxy: &'input str,
        lines: Vec<Line<'input>>,
    },
}

#[derive(Debug)]
pub enum Host<'input> {
    Ipv4(Ipv4Addr),
    Dns(&'input str),
    Wildcard,
}

#[derive(Debug)]
pub struct Address<'input> {
    host: Host<'input>,
    port: Option<u16>,
}

#[derive(Debug)]
pub enum BackendModifier {
    If,
    Unless,
}

#[derive(Debug)]
pub enum Password<'input> {
    Secure(&'input str),
    Insecure(&'input str),
}

#[derive(Debug)]
pub enum Line<'input> {
    Server {
        name: &'input str,
        addr: Address<'input>,
        other: Option<&'input str>,
        comment: Option<&'input str>,
    },
    Option {
        keyword: &'input str,
        value: Option<&'input str>,
        comment: Option<&'input str>,
    },
    Bind {
        addr: Address<'input>,
        value: Option<&'input str>,
        comment: Option<&'input str>,
    },
    Acl {
        name: &'input str,
        rule: Option<&'input str>,
        comment: Option<&'input str>,
    },
    Backend {
        name: &'input str,
        modifier: Option<BackendModifier>,
        condition: Option<&'input str>,
        comment: Option<&'input str>,
    },
    Group {
        name: &'input str,
        user: Option<&'input str>,
        comment: Option<&'input str>,
    },
    User {
        name: &'input str,
        password: Password<'input>,
        groups: Vec<&'input str>,
        comment: Option<&'input str>, 
    },
    Config {
        key: &'input str,
        value: Option<&'input str>,
        comment: Option<&'input str>, 
    },
    Comment(&'input str),
    Blank,
}

pub fn parse(input: impl AsRef<str>) -> Result<Config, Error> {
    let entries = parser::configuration(input.as_ref()).unwrap();
    dbg!(entries);
    Ok(Config {
        global: (),
        defaults: (),
        frontends: Vec::new(),
        backends: Vec::new(),
    })
}

peg::parser! {
    grammar parser() for str {
        pub(super) rule configuration() -> Vec<ConfigEntry<'input>>
            = (config_comment() / config_blank() / global_section() / defaults_section() / userlist_section() / listen_section() / frontend_section() / backend_section())*

        pub(super) rule global_section() -> ConfigEntry<'input>
            = comment:global_header() lines:config_block() {
                ConfigEntry::Global{ comment, lines }
            }

        rule defaults_section() -> ConfigEntry<'input>
            = h:defaults_header() lines:config_block() {
                ConfigEntry::Default{ comment: h.1, proxy: h.0, lines }
            }

        rule userlist_section() -> ConfigEntry<'input>
            = h:userlist_header() lines:config_block() {
                ConfigEntry::UserList{ comment: h.1, proxy: h.0 , lines}
            }

        rule listen_section() -> ConfigEntry<'input>
            = h:listen_header() lines:config_block() {
                ConfigEntry::Listen{ comment: h.1, proxy: h.0 , lines}
            }

        rule frontend_section() -> ConfigEntry<'input>
            = h:frontend_header() lines:config_block() {
                ConfigEntry::Frontend{ comment: h.1, proxy: h.0, lines }
            }

        rule backend_section() -> ConfigEntry<'input>
            = h:backend_header() lines:config_block() {
                ConfigEntry::Backend{ comment: h.1, proxy: h.0 , lines}
            }

        rule global_header() -> Option<&'input str>
            = whitespace() "global" whitespace() c:comment_text()? line_break() { c }

        rule userlist_header() -> (&'input str, Option<&'input str>)
            = whitespace() "userlist" whitespace() p:proxy_name() c:comment_text()? line_break() {(p,c)}

        rule defaults_header() -> (Option<&'input str>, Option<&'input str>)
            = whitespace() "defaults" whitespace() p:proxy_name()? whitespace() c:comment_text()? line_break() {(p,c)}

        rule listen_header() -> (&'input str, Option<&'input str>)
            = whitespace() "listen" whitespace() p:proxy_name() whitespace() service_address()? value()? c:comment_text()? line_break() {(p,c)}

        rule frontend_header() -> (&'input str, Option<&'input str>)
            = whitespace() "frontend" whitespace() p:proxy_name() whitespace() service_address()? value()? c:comment_text()? line_break() {(p,c)}

        rule backend_header() -> (&'input str, Option<&'input str>)
            = whitespace() "backend" whitespace() p:proxy_name() whitespace() value()? c:comment_text()? line_break() {(p,c)}

        rule config_block() -> Vec<Line<'input>>
            = e:(server_line() / option_line() / bind_line() / acl_line() / backend_line() / group_line() / user_line() / config_line() / comment_line() / blank_line())* { e }

        rule server_line() -> Line<'input>
            = whitespace() "server" whitespace() name:server_name() whitespace() addr:service_address() other:value()? comment:comment_text()? line_break() {
                Line::Server { name, addr, other, comment }
            }

        rule option_line() -> Line<'input>
            = whitespace() "option" whitespace() keyword:keyword() whitespace() value:value()? comment:comment_text()? line_break() {
                Line::Option { keyword, value, comment }
            }

        rule bind_line() -> Line<'input>
            = whitespace() "bind" whitespaceplus() addr:service_address() whitespace() value:value()? comment:comment_text()? line_break() {
                Line::Bind { addr, value, comment }
            }

        rule acl_line() -> Line<'input>
        = whitespace() "acl" whitespace() name:acl_name() whitespace() r:value()? comment:comment_text()? line_break() {
            Line::Acl { name, rule: r, comment }
        }

        rule modifier() -> BackendModifier
        = "if" { BackendModifier::If } / "unless" { BackendModifier::Unless }

        rule backend_line() -> Line<'input>
            = whitespace() ("use_backend" / "default_backend") whitespace() name:backend_name() whitespace() modifier:modifier()? whitespace() condition:backend_condition()? comment:comment_text()? line_break() {
                Line::Backend {name, modifier, condition, comment }
            }

        rule group_line() -> Line<'input>
            = whitespace() "group" whitespace() name:group_name() whitespace() ("users" whitespace())? user:value()? comment:comment_text()? line_break() {
                Line::Group { name, user, comment }
            }

        rule password_type() -> bool
            = "password" { true } / "insecure-password" { false }

        rule groups() -> Vec<&'input str>
            = "groups" groups:$(whitespace() value())+ { 
                let mut groups = groups;
                for group in &mut groups {
                    *group = group.trim();
                }
                groups
            }

        rule user_line() -> Line<'input>
            = whitespace() "user" whitespace() name:user_name() whitespace() secure:password_type() whitespace() password:password() whitespace() groups:groups()? comment:comment_text()? line_break() {
                let password = if secure {
                    Password::Secure(password)
                } else {
                    Password::Insecure(password)
                };
                let groups = groups.unwrap_or_else(Vec::new);
                Line::User { name, password, groups, comment}
            }

        pub(super) rule config_line() -> Line<'input>
            = whitespace() !("defaults" / "global" / "userlist" / "listen" / "frontend" / "backend") key:keyword() whitespace() value:value()? comment:comment_text()? line_break() { 
                Line::Config { key, value, comment }
            }

        rule config_comment() -> ConfigEntry<'input>
            = whitespace() t:comment_text() line_break() { ConfigEntry::Comment(t) }

        rule comment_line() -> Line<'input>
            = whitespace() t:comment_text() line_break() { Line::Comment(t) }

        rule blank_line() -> Line<'input>
            = whitespace() line_break() { Line::Blank }

        rule config_blank() -> ConfigEntry<'input>
            = whitespace() line_break() { ConfigEntry::BlankLine }

        rule comment_text() -> &'input str
            = "#" s:$(char()*) &line_break() { s }

        rule line_break()
            = quiet!{['\n']}

        rule keyword() -> &'input str
            = $((("errorfile" / "timeout") whitespace())? ['a'..='z' | '0'..='9' | '-' | '_' | '.']+)

        rule alphanumeric_plus() -> &'input str
            = $(['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | ':']+)

        rule server_name() -> &'input str
            = alphanumeric_plus()

        rule acl_name() -> &'input str
            = alphanumeric_plus()

        rule backend_name() -> &'input str
            = alphanumeric_plus()

        rule group_name() -> &'input str
            = alphanumeric_plus()

        rule user_name() -> &'input str
            = alphanumeric_plus()

        rule not_comment_or_end() -> &'input str
            = $([^ '#' | '\n']+)

        rule password() -> &'input str
            = not_comment_or_end()

        rule backend_condition() -> &'input str
            = not_comment_or_end()

        rule service_address() -> Address<'input>
            = host:host() [':']? port:port()? {
                Address {host, port}
            }

        rule host() -> Host<'input>
            = ipv4_host() / dns_host() / wildcard_host()

        rule port() -> u16
            = p:$(['0'..='9']+) { p.parse().expect("port must fit in a u16") }

        rule digits_u8() -> u8
            = d:$(['0'..='9']*<1,3>) {
                d.parse().expect("digits must represent unsigned 8 bit integer")
            }

        rule ipv4_host() -> Host<'input>
            = a:digits_u8() "." b:digits_u8() "." c:digits_u8() "." d:digits_u8() {
                Host::Ipv4(Ipv4Addr::new(a,b,c,d))
            }

        rule dns_host() -> Host<'input>
            = s:$(['a'..='z' | 'A'..='Z' | '-' | '.' | '0'..='9']+) { Host::Dns(s) }

        rule wildcard_host() -> Host<'input>
            = "*" { Host::Wildcard }

        rule proxy_name() -> &'input str
            = alphanumeric_plus()

        rule value() -> &'input str
            = not_comment_or_end()

        rule char()
            = quiet!{!['\n'] "."}

        pub(super) rule whitespace()
            = quiet!{[' ' | '\t']*}

        rule whitespaceplus()
            = quiet!{[' ' | '\t']+}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global() {
        parser::configuration(include_str!("global_section.txt")).unwrap();
    }

    #[test]
    fn config_line() {
        parser::config_line(include_str!("config_line.txt")).unwrap();
    }

    #[test]
    fn whitespace() {
        let four_spaces = "    ";
        parser::whitespace(four_spaces).unwrap();
    }
}
