#[derive(Debug)]
pub enum Error {}

pub struct Config {
    global: (),
    defaults: (),
    frontends: Vec<()>,
    backends: Vec<()>,
}

enum ConfigEntry {
    Comment,
    Global,
    Default,
    Frontend,
    Backend,
}

pub fn parse(input: impl AsRef<str>) -> Result<Config, Error> {
    // let entries = parser::config(input.as_ref()).unwrap();
    Ok(Config {
        global: (),
        defaults: (),
        frontends: Vec::new(),
        backends: Vec::new(),
    })
}

peg::parser! {
    grammar parser() for str {
        pub rule configuration() -> ()
            = (comment_line() / blank_line() / global_section() / defaults_section() / userlist_section() / listen_section() / frontend_section() / backend_section())* {}
        pub rule global_section() -> ()
            = global_header() config_block() {}

        rule defaults_section() -> ()
            = defaults_header() config_block() {}

        rule userlist_section() -> ()
            = userlist_header() config_block() {}

        rule listen_section() -> ()
            = listen_header() config_block() {}

        rule frontend_section() -> ()
            = frontend_header() config_block() {}

        rule backend_section() -> ()
            = backend_header() config_block() {}

        rule global_header() -> ()
            = whitespace() "global" whitespace() comment_text()? line_break() {}

        rule userlist_header() -> ()
            = whitespace() "userlist" whitespace() proxy_name() comment_text()? line_break() {}

        rule defaults_header() -> ()
            = whitespace() "defaults" whitespace() proxy_name()? whitespace() comment_text()? line_break() {}

        rule listen_header() -> ()
            = whitespace() "listen" whitespace() proxy_name() whitespace() service_address()? value()? comment_text()? line_break() {}

        rule frontend_header() -> ()
            = whitespace() "frontend" whitespace() proxy_name() whitespace() service_address()? value()? comment_text()? line_break() {}

        rule backend_header() -> ()
            = whitespace() "backend" whitespace() proxy_name() whitespace() value()? comment_text()? line_break() {}

        rule config_block() -> ()
            = (server_line() / option_line() / bind_line() / acl_line() / backend_line() / group_line() / user_line() / config_line() / comment_line() / blank_line())* {}

        rule server_line() -> ()
            = whitespace() "server" whitespace() server_name() whitespace() service_address() value()? comment_text()? line_break() {}

        rule option_line() -> ()
            = whitespace() "option" whitespace() keyword() whitespace() value()? comment_text()? line_break() {}

        rule bind_line() -> ()
            = whitespace() "bind" whitespaceplus() service_address() whitespace() value()? comment_text()? line_break() {}

        rule acl_line() -> ()
        = whitespace() "acl" whitespace() acl_name() whitespace() value()? comment_text()? line_break() {}

        rule backend_line() -> ()
            = whitespace() ("use_backend" / "default_backend") whitespace() backend_name() whitespace() ("if" / "unless")? whitespace() backend_condition()? comment_text()? line_break() {}

        rule group_line() -> ()
            = whitespace() "group" whitespace() group_name() whitespace() ("users" whitespace())? value()? comment_text()? line_break() {}

        rule user_line() -> ()
            = whitespace() "user" whitespace() user_name() whitespace() ("password" / "insecure-password") whitespace() password() whitespace() ("groups" whitespace())? value()? comment_text()? line_break() {}

        pub(super) rule config_line() -> ()
            = whitespace() !("defaults" / "global" / "userlist" / "listen" / "frontend" / "backend") keyword() whitespace() value()? comment_text()? line_break() {}

        rule comment_line() -> ()
            = whitespace() comment_text() line_break() {}

        rule blank_line() -> ()
            = whitespace() line_break() {}

        rule comment_text() -> ()
            = "#" char()* &line_break() {}

        rule line_break() -> ()
            = ['\n'] {}

        rule keyword() -> ()
            = (("errorfile" / "timeout") whitespace())? ['a'..='z' | '0'..='9' | '-' | '_' | '.']+ {}

        rule alphanumeric_plus() -> ()
            = ['a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | ':']+ {}

        rule server_name() -> ()
            = alphanumeric_plus() {}

        rule acl_name() -> ()
            = alphanumeric_plus() {}

        rule backend_name() -> ()
            = alphanumeric_plus() {}

        rule group_name() -> ()
            = alphanumeric_plus() {}

        rule user_name() -> ()
            = alphanumeric_plus() {}

        rule not_comment_or_end() -> () 
            = [^ '#' | '\n']+ {}

        rule password() -> ()
            = not_comment_or_end() {}

        rule backend_condition() -> ()
            = not_comment_or_end() {}

        rule service_address() -> ()
            = host() [':']? port() {}

        rule host() -> ()
            = ipv4_host() / dns_host() / wildcard_host() {}

        rule port() -> ()
            = ['0'..='9']* {}

        rule digits() -> ()
            = ['0'..='9']+ {}

        rule ipv4_host() -> ()
            = digits() "." digits() "." digits() "." digits() {}

        rule dns_host() -> ()
            = ['a'..='z' | 'A'..='Z' | '-' | '.' | '0'..='9']+ {}

        rule wildcard_host() -> ()
            = "*" {}

        rule proxy_name() -> ()
            = alphanumeric_plus() {}

        rule value() -> ()
            = not_comment_or_end() {}

        rule char() -> ()
            = !['\n'] "." {}

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
