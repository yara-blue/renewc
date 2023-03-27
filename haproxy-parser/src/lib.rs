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
    let entries = parser::config(input.as_ref()).unwrap();
    Ok(Config {
        global: (),
        defaults: (),
        frontends: Vec::new(),
        backends: Vec::new(),
    })
}

peg::parser! {
    grammar parser() for str {
        rule linefeed()
        = "\n" {}

        rule section_end()
        = linefeed() linefeed()

        rule comment() -> ConfigEntry
        = "#" [_]+ linefeed() { ConfigEntry::Comment }

        pub(super) rule global() -> ConfigEntry
        = "global" [_]+ section_end() { ConfigEntry::Global }

        pub(super) rule defaults() -> ConfigEntry
        = "defaults" [_]+ section_end() { ConfigEntry::Global }

        pub(super) rule frontends() -> ConfigEntry
        = "frontends" [_]+ section_end() { ConfigEntry::Global }

        pub(super) rule backends() -> ConfigEntry
        = "backends" [_]+ section_end() { ConfigEntry::Global }

        pub(super) rule config() -> Vec<ConfigEntry>
            = entries:(comment() / global:global() / defaults:defaults() / frontends:frontends() / backends:backends())* {
                entries
            }

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global() {
        let test = "\
global
	maxconn 200";
        parser::global(test);
    }
}
